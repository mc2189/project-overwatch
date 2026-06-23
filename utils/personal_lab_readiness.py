"""Central Personal Lab readiness evaluation — shared by UI and executor."""

from __future__ import annotations

from typing import Any

from database.personal_lab import (
    DEFAULT_LAB_SCOPE_NOTES,
    add_personal_lab_scope_item,
    list_personal_lab_scope,
)
from utils.engagement_guardrails import SCOPE_LEVEL_ALLOWS, resolve_scope_match
from utils.module_testing_levels import testing_level_label
from utils.security import is_private_or_local_ip
from utils.settings_manager import personal_lab_enabled
from utils.target_detection import get_target_type, normalize_target_value

PRIVATE_HOST_SUFFIXES = (".local", ".lan", ".home", ".internal", ".localhost")


def classify_personal_lab_target(target: str) -> dict[str, Any]:
    """Classify target for Personal Lab hints and warnings."""
    cleaned = target.strip()
    target_type = get_target_type(cleaned)
    is_private_ip = target_type == "ipv4" and is_private_or_local_ip(cleaned)
    host = cleaned.lower()
    if target_type == "url":
        from urllib.parse import urlparse

        parsed = urlparse(cleaned if "://" in cleaned else f"https://{cleaned}")
        host = (parsed.hostname or cleaned).lower()
        if parsed.hostname and is_private_or_local_ip(parsed.hostname):
            is_private_ip = True

    is_local_hostname = host in {"localhost", "127.0.0.1"} or any(
        host.endswith(suffix) for suffix in PRIVATE_HOST_SUFFIXES
    )
    is_private = is_private_ip or is_local_hostname
    is_public = not is_private and target_type in {"domain", "url", "ipv4"}

    hint = None
    warning = None
    if is_private:
        hint = "Private/local target: suitable for home lab or internal testing if you control the network."
    elif is_public:
        warning = "Public target: confirm you own this target or have permission to test it."

    return {
        "target_type": target_type,
        "is_private": is_private,
        "is_public": is_public,
        "hint": hint,
        "warning": warning,
    }


def _scope_match(target: str, case_id: int, conn: Any) -> dict[str, Any] | None:
    items = list_personal_lab_scope(case_id, conn=conn)
    return resolve_scope_match(target, items)


def can_auto_scope_testing_level(testing_level: str) -> bool:
    """Auto-scope is only offered for safe active check levels."""
    allowed = SCOPE_LEVEL_ALLOWS.get("safe_active", ())
    return testing_level in allowed


def ensure_personal_lab_scope_for_confirmation(
    case_id: int,
    target: str,
    *,
    personal_lab_confirmed: bool,
    testing_level: str,
    conn: Any,
) -> tuple[bool, dict[str, Any] | None]:
    """
    Create Personal Lab scope when confirmed and missing.

    Returns (created, scope_item).
    """
    if not personal_lab_confirmed or not personal_lab_enabled():
        return False, None
    if not can_auto_scope_testing_level(testing_level):
        return False, None

    existing = _scope_match(target, case_id, conn)
    if existing is not None:
        return False, existing

    item = add_personal_lab_scope_item(
        case_id,
        target.strip(),
        notes=DEFAULT_LAB_SCOPE_NOTES,
        conn=conn,
    )
    return True, item


def evaluate_personal_lab_readiness(
    target: str,
    *,
    case_id: int | None,
    personal_lab_confirmed: bool,
    testing_level: str,
    conn: Any | None = None,
    apply_auto_scope: bool = False,
) -> dict[str, Any]:
    """
    Evaluate Personal Lab readiness for one active module.

    When apply_auto_scope is True (executor path), scope is created if needed before returning.
  """
    classification = classify_personal_lab_target(target)
    enabled = personal_lab_enabled()
    confirmed = personal_lab_confirmed
    auto_scope_created = False
    in_scope = False
    scope_item = None
    permitted = "safe_active"
    scope_status = "unknown"

    if case_id is not None and conn is not None:
        scope_item = _scope_match(target, case_id, conn)
        if scope_item is not None:
            in_scope = (scope_item.get("scope_status") or "in_scope") == "in_scope"
            scope_status = scope_item.get("scope_status") or "in_scope"
            permitted = scope_item.get("permitted_testing_level") or "safe_active"

    will_auto_scope = (
        enabled
        and confirmed
        and not in_scope
        and can_auto_scope_testing_level(testing_level)
        and case_id is not None
        and conn is not None
    )

    if apply_auto_scope and will_auto_scope:
        auto_scope_created, scope_item = ensure_personal_lab_scope_for_confirmation(
            case_id,
            target,
            personal_lab_confirmed=confirmed,
            testing_level=testing_level,
            conn=conn,
        )
        if scope_item is not None:
            in_scope = True
            scope_status = scope_item.get("scope_status") or "in_scope"
            permitted = scope_item.get("permitted_testing_level") or "safe_active"
            will_auto_scope = False

    allowed_levels = SCOPE_LEVEL_ALLOWS.get(permitted, SCOPE_LEVEL_ALLOWS["safe_active"])
    if in_scope:
        level_ok = testing_level in allowed_levels
    elif will_auto_scope or (confirmed and can_auto_scope_testing_level(testing_level)):
        level_ok = can_auto_scope_testing_level(testing_level)
    else:
        level_ok = False

    blocked_reason: str | None = None
    if not enabled:
        blocked_reason = "Personal Lab Mode is disabled in settings."
    elif not confirmed:
        blocked_reason = "Personal Lab confirmation is required before running active modules."
    elif not in_scope and not will_auto_scope:
        if not can_auto_scope_testing_level(testing_level):
            blocked_reason = (
                f"Target is not in Personal Lab scope and auto-scope is not available for "
                f"{testing_level_label(testing_level)} modules."
            )
        else:
            blocked_reason = "Tick Personal Lab confirmation to authorise and add this target to lab scope."
    elif in_scope and not level_ok:
        blocked_reason = (
            f"Module testing level ({testing_level_label(testing_level)}) exceeds Personal Lab scope."
        )

    if not confirmed:
        result = "needs_confirmation"
        scope_label = "required after confirmation"
    elif blocked_reason:
        result = "blocked"
        scope_label = "blocked"
    elif in_scope:
        result = "ready"
        scope_label = "ready"
    elif will_auto_scope:
        result = "ready"
        scope_label = "will be added on run"
    else:
        result = "needs_confirmation"
        scope_label = "required after confirmation"

    return {
        "enabled": enabled,
        "confirmed": confirmed,
        "in_scope": in_scope,
        "will_auto_scope_on_run": will_auto_scope,
        "auto_scope_created": auto_scope_created,
        "scope_status": scope_status,
        "scope_label": scope_label,
        "testing_level_permitted": permitted,
        "testing_level_ok": level_ok,
        "allowed": blocked_reason is None,
        "blocked_reason": blocked_reason,
        "result": result,
        "classification": classification,
        "is_private_target": classification["is_private"],
        "is_public_target": classification["is_public"],
        "target_hint": classification.get("hint"),
        "target_warning": classification.get("warning"),
        "needs_lab_scope_add": not in_scope and not will_auto_scope,
        "can_auto_scope": will_auto_scope or (confirmed and not in_scope and can_auto_scope_testing_level(testing_level)),
    }

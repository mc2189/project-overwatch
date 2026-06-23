"""Engagement scope and rules-of-engagement execution guardrails."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlparse

from database.engagements import (
    get_engagement_for_case,
    get_roe,
    list_scope_items,
)
from utils.module_testing_levels import (
    get_module_testing_level,
    is_active_testing_level,
    is_intrusive_testing_level,
    testing_level_label,
)
from utils.target_detection import get_target_type, normalize_target_value

SCOPE_LEVEL_ALLOWS: dict[str, set[str]] = {
    "passive_only": {"passive_lookup"},
    "safe_active": {"passive_lookup", "safe_active_check"},
    "intrusive_active": {"passive_lookup", "safe_active_check", "intrusive_active_check"},
    "manual_only": {"passive_lookup"},
}


def _normalise_scope_value(asset_type: str, value: str) -> str:
    cleaned = value.strip().lower()
    if asset_type == "url":
        parsed = urlparse(cleaned if "://" in cleaned else f"https://{cleaned}")
        return (parsed.hostname or cleaned).rstrip(".")
    if asset_type in {"domain", "hostname", "email-domain"}:
        return cleaned.split("@")[-1].rstrip(".")
    return cleaned


def _target_matches_scope_item(target: str, target_type: str, item: dict[str, Any]) -> bool:
    asset_type = item.get("asset_type") or "other"
    asset_value = _normalise_scope_value(asset_type, item.get("asset_value") or "")
    if not asset_value:
        return False

    normalised_target = target.strip().lower()
    if target_type == "url":
        host = _normalise_scope_value("url", normalised_target)
        if asset_type in {"url"}:
            return normalised_target.rstrip("/") == asset_value.rstrip("/")
        if asset_type in {"domain", "hostname", "email-domain"}:
            return host == asset_value or host.endswith(f".{asset_value}")
    if target_type == "domain":
        host = normalize_target_value(normalised_target, "domain")
        if asset_type in {"domain", "hostname", "email-domain"}:
            return host == asset_value or host.endswith(f".{asset_value}")
    if target_type == "ipv4":
        if asset_type == "ipv4":
            return normalised_target == asset_value
        if asset_type == "cidr":
            try:
                network = ipaddress.ip_network(asset_value, strict=False)
                return ipaddress.ip_address(normalised_target) in network
            except ValueError:
                return False
    if asset_type == "other" and asset_value in normalised_target:
        return True
    return False


def resolve_scope_match(target: str, scope_items: list[dict[str, Any]]) -> dict[str, Any] | None:
    target_type = get_target_type(target)
    matches = [item for item in scope_items if _target_matches_scope_item(target, target_type, item)]
    if not matches:
        return None
    priority = {"in_scope": 0, "restricted": 1, "pending_approval": 2, "out_of_scope": 3}
    matches.sort(key=lambda item: priority.get(item.get("scope_status") or "", 9))
    return matches[0]


def assess_target_scope(
    target: str,
    *,
    case_id: int | None,
    conn: Any | None = None,
) -> dict[str, Any]:
    """Return scope assessment for a target within the case engagement."""
    result: dict[str, Any] = {
        "engagement": None,
        "scope_item": None,
        "scope_status": "unknown",
        "permitted_testing_level": None,
        "emergency_stop_active": False,
        "warnings": [],
    }
    if case_id is None:
        result["warnings"].append("No case selected — engagement scope cannot be evaluated.")
        return result

    engagement = get_engagement_for_case(case_id, conn=conn)
    if engagement is None:
        result["warnings"].append("No client engagement linked to this case.")
        return result

    result["engagement"] = engagement
    result["emergency_stop_active"] = bool(engagement.get("emergency_stop_active"))
    if engagement.get("status") not in {"active", "paused"}:
        result["warnings"].append(
            f"Engagement status is {engagement.get('status')} — active testing may be restricted."
        )

    scope_items = list_scope_items(int(engagement["id"]), conn=conn)
    match = resolve_scope_match(target, scope_items)
    if match is None:
        result["scope_status"] = "unknown"
        result["warnings"].append("Target is not listed in engagement scope (unknown/unapproved).")
        return result

    result["scope_item"] = match
    result["scope_status"] = match.get("scope_status") or "unknown"
    result["permitted_testing_level"] = match.get("permitted_testing_level")
    if match.get("scope_status") == "out_of_scope":
        result["warnings"].append("Target matches an out-of-scope asset entry.")
    elif match.get("scope_status") == "restricted":
        result["warnings"].append("Target matches a restricted scope entry — review ROE before active testing.")
    elif match.get("scope_status") == "pending_approval":
        result["warnings"].append("Target matches a scope entry pending approval.")
    return result


def check_engagement_execution(
    module_id: str,
    target: str,
    *,
    case_id: int | None,
    authorisation_confirmed: bool,
    standalone_authorised_testing: bool = False,
    options: dict[str, Any] | None = None,
    conn: Any | None = None,
) -> dict[str, Any]:
    """
    Evaluate engagement/scope/ROE guardrails before module execution.

    Passive modules generally continue; active/intrusive modules require engagement,
    scope alignment, ROE permissions, and existing authorisation confirmation.
    """
    options = options or {}
    testing_level = get_module_testing_level(module_id, options)
    assessment = assess_target_scope(target, case_id=case_id, conn=conn)
    engagement = assessment.get("engagement")
    scope_status = assessment.get("scope_status") or "unknown"
    scope_item = assessment.get("scope_item")
    warnings = list(assessment.get("warnings") or [])
    blocked_reason: str | None = None

    if testing_level == "prohibited":
        blocked_reason = "This module class is prohibited by platform policy."

    active_level = is_active_testing_level(testing_level)
    intrusive_level = is_intrusive_testing_level(testing_level)
    high_risk = testing_level == "high_risk_manual_only"

    if not blocked_reason and active_level:
        if engagement is None and not standalone_authorised_testing:
            blocked_reason = (
                "Active testing requires a linked active engagement or explicit standalone "
                "authorised testing confirmation."
            )
        elif engagement is not None:
            if engagement.get("emergency_stop_active"):
                blocked_reason = "Emergency stop is active for this engagement — active/intrusive modules are blocked."
            elif engagement.get("status") not in {"active"}:
                blocked_reason = (
                    f"Engagement status is {engagement.get('status')} — set to active before active testing."
                )

    roe = get_roe(int(engagement["id"]), conn=conn) if engagement else {}

    if not blocked_reason and active_level and scope_status == "out_of_scope":
        blocked_reason = "Target is out of scope for this engagement."

    if not blocked_reason and active_level and scope_status in {"unknown", "pending_approval"}:
        if engagement is not None and not standalone_authorised_testing:
            blocked_reason = (
                "Target is not approved in engagement scope — add an in-scope asset or use standalone "
                "authorised testing with explicit confirmation."
            )

    if not blocked_reason and scope_item and scope_status in {"in_scope", "restricted"}:
        permitted = scope_item.get("permitted_testing_level") or "passive_only"
        allowed_levels = SCOPE_LEVEL_ALLOWS.get(permitted, SCOPE_LEVEL_ALLOWS["passive_only"])
        if testing_level not in allowed_levels:
            blocked_reason = (
                f"Module testing level ({testing_level_label(testing_level)}) exceeds permitted scope level "
                f"({permitted.replace('_', ' ')}) for this asset."
            )

    if not blocked_reason and engagement and roe:
        if active_level and not roe.get("active_scanning_allowed"):
            blocked_reason = "Rules of engagement do not permit active scanning for this engagement."
        if intrusive_level and not roe.get("intrusive_testing_allowed"):
            blocked_reason = "Rules of engagement do not permit intrusive testing for this engagement."
        if high_risk:
            blocked_reason = "High-risk manual-only modules are not enabled in this release."

    if not blocked_reason and (active_level or intrusive_level) and not authorisation_confirmed:
        blocked_reason = "Authorisation confirmation is required before running this module."

    return {
        "allowed": blocked_reason is None,
        "blocked_reason": blocked_reason,
        "testing_level": testing_level,
        "testing_level_label": testing_level_label(testing_level),
        "scope_status": scope_status,
        "permitted_testing_level": assessment.get("permitted_testing_level"),
        "engagement": engagement,
        "scope_item": scope_item,
        "emergency_stop_active": bool(assessment.get("emergency_stop_active")),
        "warnings": warnings,
        "standalone_authorised_testing": standalone_authorised_testing,
    }


def enrich_operation_plan(
    plan: dict[str, Any],
    *,
    target: str,
    case_id: int,
    selected_module_ids: list[str],
    standalone_authorised_testing: bool,
    nmap_options: dict[str, Any] | None = None,
    conn: Any | None = None,
) -> dict[str, Any]:
    """Attach engagement/scope context to a run operation plan."""
    assessment = assess_target_scope(target, case_id=case_id, conn=conn)
    engagement = assessment.get("engagement")
    module_checks: list[dict[str, Any]] = []
    blocked_modules: list[str] = []
    for module_id in selected_module_ids:
        options = {"nmap_options": nmap_options} if module_id == "infra_nmap" else {}
        check = check_engagement_execution(
            module_id,
            target,
            case_id=case_id,
            authorisation_confirmed=plan.get("authorisation_confirmed", False),
            standalone_authorised_testing=standalone_authorised_testing,
            options=options,
            conn=conn,
        )
        module_checks.append({"module_id": module_id, **check})
        if not check["allowed"]:
            from modules.module_registry import get_module

            module = get_module(module_id)
            label = module.display_name if module else module_id
            blocked_modules.append(f"{label}: {check['blocked_reason']}")

    enriched = dict(plan)
    enriched["engagement"] = engagement
    enriched["engagement_name"] = (engagement or {}).get("name")
    enriched["engagement_status"] = (engagement or {}).get("status")
    enriched["emergency_stop_active"] = bool(assessment.get("emergency_stop_active"))
    enriched["scope_status"] = assessment.get("scope_status")
    enriched["permitted_testing_level"] = assessment.get("permitted_testing_level")
    enriched["scope_warnings"] = assessment.get("warnings") or []
    enriched["module_engagement_checks"] = module_checks
    enriched["engagement_blocked_modules"] = blocked_modules
    if blocked_modules:
        enriched["ready_to_run"] = False
    return enriched

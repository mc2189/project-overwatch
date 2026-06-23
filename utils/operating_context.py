"""Operating context modes and unified active-module preflight guardrails."""

from __future__ import annotations

from typing import Any

from database.personal_lab import list_personal_lab_scope
from utils.engagement_guardrails import (
    SCOPE_LEVEL_ALLOWS,
    assess_target_scope,
    check_engagement_execution,
    resolve_scope_match,
)
from utils.module_testing_levels import (
    get_module_testing_level,
    is_active_testing_level,
    testing_level_label,
)
from utils.personal_lab_readiness import evaluate_personal_lab_readiness
from utils.target_detection import get_target_type, target_type_label

PASSIVE_RESEARCH = "passive_research"
PERSONAL_LAB = "personal_lab"
CLIENT_ENGAGEMENT = "client_engagement"

OPERATING_CONTEXT_ORDER: tuple[str, ...] = (
    PASSIVE_RESEARCH,
    PERSONAL_LAB,
    CLIENT_ENGAGEMENT,
)

OPERATING_CONTEXT_LABELS: dict[str, str] = {
    PASSIVE_RESEARCH: "Passive Research",
    PERSONAL_LAB: "Personal Lab",
    CLIENT_ENGAGEMENT: "Client Engagement",
}

OPERATING_CONTEXT_DESCRIPTIONS: dict[str, str] = {
    PASSIVE_RESEARCH: (
        "Passive OSINT and enrichment modules with minimal friction. "
        "Active modules require Personal Lab or Client Engagement context."
    ),
    PERSONAL_LAB: (
        "Self-owned systems, home network, lab devices and learning. "
        "Safe active checks after clear confirmation — not a client engagement."
    ),
    CLIENT_ENGAGEMENT: (
        "Formal client work with full engagement, scope, ROE and emergency stop controls."
    ),
}

PERSONAL_LAB_CONFIRMATION_TEXT = (
    "I confirm this target is my own system, lab environment, home network, test asset, "
    "or otherwise authorised for testing."
)
PERSONAL_LAB_CONFIRMATION_VERSION = "1.0"

PERSONAL_LAB_PROFILE: dict[str, Any] = {
    "name": "Personal Lab",
    "status": "active",
    "safe_active_allowed": True,
    "emergency_stop_default": False,
    "is_client_engagement": False,
}


def operating_context_label(context: str) -> str:
    return OPERATING_CONTEXT_LABELS.get(context, context.replace("_", " ").title())


def list_operating_contexts() -> list[tuple[str, str]]:
    return [(key, OPERATING_CONTEXT_LABELS[key]) for key in OPERATING_CONTEXT_ORDER]


def assess_personal_lab_scope(
    target: str,
    *,
    case_id: int | None,
    conn: Any | None = None,
) -> dict[str, Any]:
    """Return personal lab scope assessment for a target."""
    result: dict[str, Any] = {
        "scope_item": None,
        "scope_status": "unknown",
        "permitted_testing_level": None,
        "warnings": [],
    }
    if case_id is None or conn is None:
        result["warnings"].append("No case selected — personal lab scope cannot be evaluated.")
        return result

    items = list_personal_lab_scope(case_id, conn=conn)
    match = resolve_scope_match(target, items)
    if match is None:
        result["warnings"].append("Target is not in Personal Lab scope.")
        return result

    result["scope_item"] = match
    result["scope_status"] = match.get("scope_status") or "in_scope"
    result["permitted_testing_level"] = match.get("permitted_testing_level") or "safe_active"
    return result


def _preflight_item(
    key: str,
    label: str,
    *,
    ok: bool,
    fix: str | None = None,
    value: str | None = None,
) -> dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "status": "ok" if ok else "fail",
        "fix": fix,
        "value": value,
    }


def _aggregate_preflight(
    *,
    allowed: bool,
    operating_context: str,
    target: str,
    module_id: str,
    testing_level: str,
    items: list[dict[str, Any]],
    blocked_reason: str | None = None,
    warnings: list[str] | None = None,
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    failed = [item for item in items if item.get("status") == "fail"]
    fix_actions = [item["fix"] for item in failed if item.get("fix")]
    if allowed:
        result_state = "ready"
    elif failed:
        result_state = "needs_action" if any(item.get("fix") for item in failed) else "blocked"
    else:
        result_state = "blocked"

    payload: dict[str, Any] = {
        "allowed": allowed,
        "result": result_state,
        "operating_context": operating_context,
        "operating_context_label": operating_context_label(operating_context),
        "target": target,
        "target_type": get_target_type(target),
        "target_type_label": target_type_label(get_target_type(target)),
        "module_id": module_id,
        "testing_level_required": testing_level,
        "testing_level_required_label": testing_level_label(testing_level),
        "items": items,
        "blocked_reason": blocked_reason,
        "fix_actions": fix_actions,
        "warnings": warnings or [],
    }
    if extra:
        payload.update(extra)
    return payload


def check_module_execution_guardrails(
    module_id: str,
    target: str,
    *,
    case_id: int | None,
    authorisation_confirmed: bool,
    operating_context: str = PASSIVE_RESEARCH,
    personal_lab_confirmed: bool = False,
    apply_auto_scope: bool = False,
    options: dict[str, Any] | None = None,
    conn: Any | None = None,
) -> dict[str, Any]:
    """Evaluate guardrails for a module run under the selected operating context."""
    options = options or {}
    testing_level = get_module_testing_level(module_id, options)
    active_level = is_active_testing_level(testing_level)

    if testing_level == "prohibited":
        return _aggregate_preflight(
            allowed=False,
            operating_context=operating_context,
            target=target,
            module_id=module_id,
            testing_level=testing_level,
            items=[
                _preflight_item(
                    "policy",
                    "Module policy",
                    ok=False,
                    fix="This module class is prohibited by platform policy.",
                )
            ],
            blocked_reason="This module class is prohibited by platform policy.",
        )

    if not active_level:
        return _aggregate_preflight(
            allowed=True,
            operating_context=operating_context,
            target=target,
            module_id=module_id,
            testing_level=testing_level,
            items=[
                _preflight_item("module_mode", "Module mode", ok=True, value="passive"),
                _preflight_item(
                    "operating_context",
                    "Operating context",
                    ok=True,
                    value=operating_context_label(operating_context),
                ),
            ],
            extra={"scope_status": "not_required", "testing_level_permitted": "passive_lookup"},
        )

    if operating_context == PASSIVE_RESEARCH:
        return _aggregate_preflight(
            allowed=False,
            operating_context=operating_context,
            target=target,
            module_id=module_id,
            testing_level=testing_level,
            items=[
                _preflight_item(
                    "operating_context",
                    "Operating context",
                    ok=False,
                    value=operating_context_label(operating_context),
                    fix="Select Personal Lab for self-owned testing or Client Engagement for formal work.",
                ),
                _preflight_item(
                    "active_mode",
                    "Active module in Passive Research",
                    ok=False,
                    fix="Switch operating context to run active modules.",
                ),
            ],
            blocked_reason=(
                "Active modules cannot run in Passive Research mode. "
                "Select Personal Lab or Client Engagement."
            ),
        )

    if operating_context == PERSONAL_LAB:
        return _check_personal_lab_guardrails(
            module_id,
            target,
            case_id=case_id,
            authorisation_confirmed=authorisation_confirmed,
            personal_lab_confirmed=personal_lab_confirmed,
            apply_auto_scope=apply_auto_scope,
            options=options,
            conn=conn,
            testing_level=testing_level,
        )

    return _check_client_engagement_guardrails(
        module_id,
        target,
        case_id=case_id,
        authorisation_confirmed=authorisation_confirmed,
        options=options,
        conn=conn,
        testing_level=testing_level,
    )


def _check_personal_lab_guardrails(
    module_id: str,
    target: str,
    *,
    case_id: int | None,
    authorisation_confirmed: bool,
    personal_lab_confirmed: bool,
    apply_auto_scope: bool,
    options: dict[str, Any],
    conn: Any | None,
    testing_level: str,
) -> dict[str, Any]:
    confirmed = personal_lab_confirmed or authorisation_confirmed
    readiness = evaluate_personal_lab_readiness(
        target,
        case_id=case_id,
        personal_lab_confirmed=confirmed,
        testing_level=testing_level,
        conn=conn,
        apply_auto_scope=apply_auto_scope,
    )
    classification = readiness.get("classification") or {}

    items: list[dict[str, Any]] = [
        _preflight_item(
            "operating_context",
            "Operating context",
            ok=True,
            value=f"{PERSONAL_LAB_PROFILE['name']}",
        ),
        _preflight_item(
            "personal_lab_enabled",
            "Personal Lab Mode enabled",
            ok=readiness.get("enabled", False),
            fix="Enable Personal Lab Mode in Settings or set PROJECT_OVERWATCH_PERSONAL_LAB_ENABLED=true.",
        ),
        _preflight_item(
            "lab_confirmation",
            "Lab confirmation",
            ok=readiness.get("confirmed", False),
            value="confirmed" if readiness.get("confirmed") else "required",
            fix="Tick Personal Lab confirmation to continue.",
        ),
        _preflight_item(
            "lab_scope",
            "Lab scope",
            ok=readiness.get("in_scope") or readiness.get("will_auto_scope_on_run", False),
            value=readiness.get("scope_label", "unknown"),
            fix="Tick Personal Lab confirmation to continue." if not confirmed else None,
        ),
        _preflight_item(
            "testing_level",
            "Testing level",
            ok=readiness.get("testing_level_ok", False),
            value="safe active permitted",
            fix="Personal Lab scope must permit safe active checks.",
        ),
        _preflight_item(
            "emergency_stop",
            "Emergency stop",
            ok=True,
            value="not applicable",
        ),
    ]

    blocked_reason = readiness.get("blocked_reason")
    if readiness.get("result") == "needs_confirmation" and not blocked_reason:
        blocked_reason = "Personal Lab confirmation is required before running active modules."

    result_state = readiness.get("result", "blocked")
    if result_state == "needs_confirmation":
        result_state = "needs_action"

    payload = _aggregate_preflight(
        allowed=readiness.get("allowed", False),
        operating_context=PERSONAL_LAB,
        target=target,
        module_id=module_id,
        testing_level=testing_level,
        items=items,
        blocked_reason=blocked_reason,
        extra={
            "scope_status": readiness.get("scope_status"),
            "testing_level_permitted": readiness.get("testing_level_permitted"),
            "personal_lab_confirmed": confirmed,
            "authorisation_confirmed": confirmed,
            "emergency_stop_active": False,
            "is_private_target": readiness.get("is_private_target", False),
            "is_public_target": readiness.get("is_public_target", False),
            "target_hint": readiness.get("target_hint"),
            "target_warning": readiness.get("target_warning"),
            "will_auto_scope_on_run": readiness.get("will_auto_scope_on_run", False),
            "auto_scope_created": readiness.get("auto_scope_created", False),
            "needs_lab_scope_add": readiness.get("needs_lab_scope_add", False),
            "can_auto_scope": readiness.get("can_auto_scope", False),
            "lab_readiness": readiness,
        },
    )
    payload["result"] = result_state if not readiness.get("allowed") else "ready"
    return payload


def _check_client_engagement_guardrails(
    module_id: str,
    target: str,
    *,
    case_id: int | None,
    authorisation_confirmed: bool,
    options: dict[str, Any],
    conn: Any | None,
    testing_level: str,
) -> dict[str, Any]:
    engagement_check = check_engagement_execution(
        module_id,
        target,
        case_id=case_id,
        authorisation_confirmed=authorisation_confirmed,
        standalone_authorised_testing=False,
        options=options,
        conn=conn,
    )
    assessment = assess_target_scope(target, case_id=case_id, conn=conn)
    engagement = engagement_check.get("engagement") or assessment.get("engagement")

    items: list[dict[str, Any]] = [
        _preflight_item(
            "operating_context",
            "Operating context",
            ok=True,
            value=operating_context_label(CLIENT_ENGAGEMENT),
        ),
        _preflight_item(
            "engagement_linked",
            "Client engagement linked",
            ok=engagement is not None,
            fix="Link a client engagement to this case on the Client Engagements page.",
        ),
    ]

    if engagement:
        status = engagement.get("status")
        items.append(
            _preflight_item(
                "engagement_status",
                "Engagement status",
                ok=status == "active",
                value=str(status),
                fix="Activate engagement — set status to active before client active testing.",
            )
        )
        items.append(
            _preflight_item(
                "emergency_stop",
                "Emergency stop",
                ok=not engagement.get("emergency_stop_active"),
                value="active" if engagement.get("emergency_stop_active") else "off",
                fix="Turn emergency stop off on the Client Engagements page.",
            )
        )

    scope_status = engagement_check.get("scope_status") or "unknown"
    items.append(
        _preflight_item(
            "scope_status",
            "Target scope status",
            ok=scope_status in {"in_scope", "restricted"},
            value=scope_status.replace("_", " "),
            fix="Add target to engagement scope as in_scope or adjust scope entry.",
        )
    )

    permitted = engagement_check.get("permitted_testing_level") or assessment.get("permitted_testing_level")
    items.append(
        _preflight_item(
            "testing_level",
            "Testing level permitted",
            ok=engagement_check.get("allowed") or scope_status not in {"out_of_scope", "unknown"},
            value=(permitted or "—").replace("_", " "),
            fix="Set scope permitted testing level to safe active or higher.",
        )
    )

    items.append(
        _preflight_item(
            "authorisation",
            "Authorisation checkbox",
            ok=authorisation_confirmed,
            fix="Tick the authorisation confirmation checkbox.",
        )
    )

    return _aggregate_preflight(
        allowed=engagement_check.get("allowed", False),
        operating_context=CLIENT_ENGAGEMENT,
        target=target,
        module_id=module_id,
        testing_level=testing_level,
        items=items,
        blocked_reason=engagement_check.get("blocked_reason"),
        warnings=engagement_check.get("warnings"),
        extra={
            "scope_status": scope_status,
            "testing_level_permitted": permitted,
            "authorisation_confirmed": authorisation_confirmed,
            "emergency_stop_active": engagement_check.get("emergency_stop_active", False),
            "engagement": engagement,
        },
    )


def enrich_operation_plan_with_preflight(
    plan: dict[str, Any],
    *,
    target: str,
    case_id: int,
    selected_module_ids: list[str],
    operating_context: str,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
    nmap_options: dict[str, Any] | None = None,
    conn: Any | None = None,
) -> dict[str, Any]:
    """Attach per-module preflight results to an operation plan."""
    module_preflights: list[dict[str, Any]] = []
    blocked_modules: list[str] = []
    for module_id in selected_module_ids:
        options = {"nmap_options": nmap_options} if module_id == "infra_nmap" else {}
        preflight = check_module_execution_guardrails(
            module_id,
            target,
            case_id=case_id,
            authorisation_confirmed=authorisation_confirmed,
            operating_context=operating_context,
            personal_lab_confirmed=personal_lab_confirmed,
            options=options,
            conn=conn,
        )
        from modules.module_registry import get_module

        module = get_module(module_id)
        label = module.display_name if module else module_id
        module_preflights.append({"module_id": module_id, "display_name": label, **preflight})
        if not preflight.get("allowed"):
            reason = preflight.get("blocked_reason") or "Preflight blocked this module."
            blocked_modules.append(f"{label}: {reason}")

    enriched = dict(plan)
    enriched["operating_context"] = operating_context
    enriched["operating_context_label"] = operating_context_label(operating_context)
    enriched["module_preflights"] = module_preflights
    enriched["engagement_blocked_modules"] = blocked_modules
    if blocked_modules:
        enriched["ready_to_run"] = False
    elif plan.get("incompatible_modules"):
        enriched["ready_to_run"] = False
    elif not plan.get("target") or not plan.get("selected_modules"):
        enriched["ready_to_run"] = False
    else:
        enriched["ready_to_run"] = True
    return enriched

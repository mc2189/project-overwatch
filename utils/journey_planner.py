"""Assessment journey planner — recommended, optional, and blocked checks."""

from __future__ import annotations

from typing import Any

from modules.module_registry import get_module
from ui.constants import IMPLEMENTED_MODULE_IDS, MODULE_CARD_TITLES
from ui.module_runtime import module_disable_reason, module_enabled_for_ui, module_runtime_ready
from utils.assessment_goals import get_modules_for_goal
from utils.module_compatibility import get_compatible_modules, get_incompatible_reason
from utils.module_testing_levels import get_module_testing_level, is_active_testing_level
from utils.operating_context import check_module_execution_guardrails
from utils.target_detection import get_target_type


def _module_label(module_id: str) -> str:
    module = get_module(module_id)
    if module:
        return MODULE_CARD_TITLES.get(module_id, module.display_name)
    return module_id


def _journey_row(
    module_id: str,
    *,
    category: str,
    reason: str | None = None,
    preflight: dict[str, Any] | None = None,
) -> dict[str, Any]:
    module = get_module(module_id)
    row: dict[str, Any] = {
        "module_id": module_id,
        "display_name": _module_label(module_id),
        "category": category,
        "mode": module.mode if module else "unknown",
        "requires_authorisation": bool(module and module.requires_authorisation),
        "reason": reason,
    }
    if preflight:
        row["preflight"] = preflight
        row["preflight_result"] = preflight.get("result")
        row["blocked_reason"] = preflight.get("blocked_reason")
    return row


def build_assessment_journey(
    *,
    case_id: int,
    target: str,
    goal_id: str,
    selected_module_ids: list[str] | None = None,
    operating_context: str,
    personal_lab_confirmed: bool = False,
    authorisation_confirmed: bool = False,
    quick_check_include_port_scan: bool = False,
    conn: Any | None = None,
) -> dict[str, Any]:
    """Classify modules into journey categories for the workspace."""
    cleaned = target.strip()
    target_type = get_target_type(cleaned) if cleaned else "unknown"
    compatible_modules = get_compatible_modules(cleaned) if cleaned else []
    compatible_ids = {module.module_id for module in compatible_modules}

    if selected_module_ids is not None:
        recommended_ids = [module_id for module_id in selected_module_ids if module_id in compatible_ids]
    else:
        recommended_ids = [
            module_id
            for module_id in get_modules_for_goal(
                goal_id,
                target_type,
                target=cleaned,
                quick_check_include_port_scan=quick_check_include_port_scan,
            )
            if module_id in compatible_ids
        ]

    recommended_set = set(recommended_ids)
    optional_ids = [
        module.module_id
        for module in compatible_modules
        if module.module_id not in recommended_set
    ]

    recommended: list[dict[str, Any]] = []
    optional: list[dict[str, Any]] = []
    active_needs_confirmation: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    not_relevant: list[dict[str, Any]] = []

    def _classify(module_id: str, category: str) -> None:
        module = get_module(module_id)
        if module is None:
            return
        if not module_enabled_for_ui(module, cleaned):
            reason = module_disable_reason(module, cleaned) or "Not available for this target."
            not_relevant.append(_journey_row(module_id, category="not_relevant", reason=reason))
            return

        options: dict[str, Any] = {}
        if module_id == "infra_nmap":
            options = {"nmap_options": {}}
        preflight = None
        if is_active_testing_level(get_module_testing_level(module_id, options)):
            preflight = check_module_execution_guardrails(
                module_id,
                cleaned,
                case_id=case_id,
                authorisation_confirmed=authorisation_confirmed,
                operating_context=operating_context,
                personal_lab_confirmed=personal_lab_confirmed,
                options=options,
                conn=conn,
            )

        row = _journey_row(module_id, category=category, preflight=preflight)
        if preflight and not preflight.get("allowed"):
            if preflight.get("result") == "needs_action":
                active_needs_confirmation.append(row)
            else:
                blocked.append(row)
        elif preflight and module.requires_authorisation and not (
            personal_lab_confirmed or authorisation_confirmed
        ):
            row["reason"] = "Authorisation confirmation required."
            active_needs_confirmation.append(row)
        elif category == "recommended":
            recommended.append(row)
        else:
            optional.append(row)

    for module_id in recommended_ids:
        _classify(module_id, "recommended")

    for module_id in optional_ids:
        _classify(module_id, "optional")

    for module_id in IMPLEMENTED_MODULE_IDS:
        if module_id in compatible_ids:
            continue
        module = get_module(module_id)
        if module is None:
            continue
        reason = get_incompatible_reason(module, target_type)
        if reason:
            not_relevant.append(
                _journey_row(module_id, category="not_relevant", reason=reason)
            )

    return {
        "goal_id": goal_id,
        "target": cleaned,
        "target_type": target_type,
        "recommended": recommended,
        "optional": optional,
        "active_needs_confirmation": active_needs_confirmation,
        "blocked": blocked,
        "not_relevant": not_relevant,
        "recommended_module_ids": recommended_ids,
        "selected_module_ids": recommended_ids if selected_module_ids is None else list(selected_module_ids),
    }

"""Module execution dispatcher for Project Overwatch."""

from __future__ import annotations

import sqlite3
from typing import Any

from database.db_setup import create_operation_log
from modules.module_registry import get_module, is_executable
from modules.executors.registry import register_all_executors
from modules.executors.results import make_result
from utils.module_compatibility import get_incompatible_reason, module_accepts_target
from utils.target_detection import get_target_type

register_all_executors()


def is_runtime_ready(module_id: str) -> bool:
    """Return True when a module's backend is loaded and ready to run."""
    from modules.executor_dispatch import is_dispatch_ready

    return is_dispatch_ready(module_id)


def get_runtime_error(module_id: str) -> str | None:
    """Return a load-time error message for a module, if any."""
    from modules.executor_dispatch import get_dispatch_error

    return get_dispatch_error(module_id)


def execute_module(
    module_id: str,
    target: str,
    options: dict[str, Any] | None = None,
    db_context: sqlite3.Connection | None = None,
    authorisation_confirmed: bool = False,
    case_id: int | None = None,
    entity_id: int | None = None,
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> dict[str, Any]:
    """
    Execute a registered module and return a structured result dictionary.

    Execution is blocked when the module is missing, not implemented, not active,
    not executable, or requires authorisation that has not been confirmed.
    """
    options = options or {}

    module = get_module(module_id)
    if module is None:
        return make_result(
            module_id,
            success=False,
            status="blocked",
            summary="Module is not registered.",
            errors=["unknown_module_id"],
        )

    if not module.implemented:
        return make_result(
            module_id,
            success=False,
            status="blocked",
            summary=f"{module.display_name} is not implemented.",
            errors=["implemented=False"],
        )

    if module.status != "active":
        return make_result(
            module_id,
            success=False,
            status="blocked",
            summary=f"{module.display_name} is not active.",
            errors=[f"status={module.status}"],
        )

    if not is_executable(module):
        return make_result(
            module_id,
            success=False,
            status="blocked",
            summary=f"{module.display_name} is not executable.",
            errors=["not_executable"],
        )

    from utils.security import is_safe_target_string

    if not is_safe_target_string(target):
        reason = "Target contains unsafe characters for module execution."
        result = make_result(
            module_id,
            success=False,
            status="blocked",
            summary=reason,
            errors=["unsafe_target"],
        )
        if db_context is not None and case_id is not None:
            create_operation_log(
                case_id,
                module_id,
                target,
                "blocked",
                authorisation_confirmed=authorisation_confirmed,
                summary=reason,
                run_mode_id=run_mode_id,
                run_mode_label=run_mode_label,
                conn=db_context,
            )
        return result

    target_type = get_target_type(target)
    if not module_accepts_target(module, target_type):
        reason = get_incompatible_reason(module, target_type)
        result = make_result(
            module_id,
            success=False,
            status="blocked",
            summary=reason,
            errors=["target_incompatible"],
        )
        if db_context is not None and case_id is not None:
            create_operation_log(
                case_id,
                module_id,
                target,
                "blocked",
                authorisation_confirmed=authorisation_confirmed,
                summary=reason,
                run_mode_id=run_mode_id,
                run_mode_label=run_mode_label,
                conn=db_context,
            )
        return result

    from utils.operating_context import (
        PERSONAL_LAB,
        PERSONAL_LAB_CONFIRMATION_TEXT,
        PERSONAL_LAB_CONFIRMATION_VERSION,
        PASSIVE_RESEARCH,
        check_module_execution_guardrails,
    )

    operating_context = str(options.get("operating_context") or PASSIVE_RESEARCH)
    personal_lab_confirmed = bool(options.get("personal_lab_confirmed"))
    if "operating_context" not in options and authorisation_confirmed:
        operating_context = PERSONAL_LAB
        personal_lab_confirmed = True
    elif options.get("standalone_authorised_testing"):
        operating_context = PERSONAL_LAB
        personal_lab_confirmed = personal_lab_confirmed or authorisation_confirmed
    guardrail = check_module_execution_guardrails(
        module_id,
        target,
        case_id=case_id,
        authorisation_confirmed=authorisation_confirmed,
        operating_context=operating_context,
        personal_lab_confirmed=personal_lab_confirmed,
        apply_auto_scope=(
            operating_context == PERSONAL_LAB and personal_lab_confirmed
        ),
        options=options,
        conn=db_context,
    )
    if not guardrail["allowed"]:
        reason = guardrail.get("blocked_reason") or "Execution guardrail blocked this module run."
        result = make_result(
            module_id,
            success=False,
            status="blocked",
            summary=reason,
            errors=[reason],
            warnings=guardrail.get("warnings") or [],
        )
        if db_context is not None and case_id is not None:
            create_operation_log(
                case_id,
                module_id,
                target,
                "blocked",
                authorisation_confirmed=authorisation_confirmed,
                summary=reason,
                run_mode_id=run_mode_id,
                run_mode_label=run_mode_label,
                conn=db_context,
            )
        return result

    if (
        operating_context == PERSONAL_LAB
        and personal_lab_confirmed
        and db_context is not None
        and case_id is not None
    ):
        from database.personal_lab import log_lab_testing_confirmation

        log_lab_testing_confirmation(
            case_id=case_id,
            target=target,
            module_id=module_id,
            operating_context=operating_context,
            confirmation_text=PERSONAL_LAB_CONFIRMATION_TEXT,
            confirmation_version=PERSONAL_LAB_CONFIRMATION_VERSION,
            auto_scope_created=bool(guardrail.get("auto_scope_created")),
            conn=db_context,
        )

    effective_auth = authorisation_confirmed or (
        operating_context == PERSONAL_LAB and personal_lab_confirmed
    )
    if module.requires_authorisation and not effective_auth:
        return make_result(
            module_id,
            success=False,
            status="blocked",
            summary="Authorisation confirmation is required before running this module.",
            errors=["authorisation_required"],
        )

    from utils.settings_manager import check_module_preflight

    preflight = check_module_preflight(module)
    if not preflight["ok"]:
        return make_result(
            module_id,
            success=False,
            status="blocked",
            summary=preflight["summary"],
            errors=preflight["errors"],
        )

    from modules.executor_dispatch import run_dispatch

    def _unavailable(module_id: str, *, summary: str, error_message: str) -> dict[str, Any]:
        return make_result(
            module_id,
            success=False,
            status="error",
            summary=summary,
            errors=[error_message],
        )

    dispatched = run_dispatch(
        module_id,
        target,
        options,
        db_context,
        authorisation_confirmed,
        case_id,
        entity_id,
        run_mode_id,
        run_mode_label,
        make_unavailable_result=_unavailable,
    )
    if dispatched is not None:
        return dispatched

    return make_result(
        module_id,
        success=False,
        status="blocked",
        summary=f"{module.display_name} is registered but not wired in the executor yet.",
        errors=["not_wired"],
    )

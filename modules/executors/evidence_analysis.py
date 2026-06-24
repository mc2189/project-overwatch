"""Evidence analysis module execution handlers."""

from __future__ import annotations

import sqlite3
from typing import Any

from database.db_setup import create_operation_log
from modules.executors import loaders
from modules.executors.persistence import _persist_file_metadata_records
from modules.executors.results import make_result
from modules.module_registry import get_module
from utils.findings_registry import interpret_module_findings
from utils.module_compatibility import get_incompatible_reason, module_accepts_target
from utils.result_status import STATUS_BLOCKED, STATUS_ERROR
from utils.target_detection import get_target_type


def _execute_file_metadata_review(
    module_id: str,
    target: str,
    options: dict[str, Any],
    db_context: sqlite3.Connection | None,
    authorisation_confirmed: bool,
    case_id: int | None,
    entity_id: int | None,
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> dict[str, Any]:
    handler, load_error = loaders.loaded_handler(
        loaders._load_file_metadata_handler, "_file_metadata_handler", "_file_metadata_load_error"
    )
    if handler is None:
        error_message = load_error or "Document and Image Metadata Review module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="Document and Image Metadata Review module is not available.",
            errors=[error_message],
        )

    target_type = options.get("target_type") or get_target_type(target)
    module = get_module(module_id)
    if module and not module_accepts_target(module, target_type):
        reason = get_incompatible_reason(module, target_type)
        return make_result(
            module_id,
            success=False,
            status=STATUS_BLOCKED,
            summary=reason or "Target type is not supported for file metadata review.",
            errors=[reason or "incompatible_target"],
        )

    run_options = dict(options or {})
    run_options.setdefault("target_type", target_type)
    if case_id is not None:
        run_options.setdefault("case_id", case_id)

    review_data = handler(target, options=run_options)
    status = review_data.get("status") or STATUS_ERROR
    parsed_data = review_data.get("data") or review_data.get("parsed_data") or {}
    interpreter_findings = review_data.get("interpreter_findings")
    if interpreter_findings is None:
        interpreter_findings = interpret_module_findings(module_id, parsed_data, run_options)
    warnings = list(review_data.get("warnings") or [])
    errors = list(review_data.get("errors") or [])

    if not review_data.get("success"):
        summary = review_data.get("summary") or (errors[0] if errors else "File metadata review failed.")
        result = make_result(
            module_id,
            success=False,
            status=status,
            summary=summary,
            raw_output=review_data.get("raw_output", ""),
            errors=errors,
            parsed_data=parsed_data,
            warnings=warnings,
            interpreter_findings=interpreter_findings,
        )
        if db_context is not None and case_id is not None:
            create_operation_log(
                case_id,
                module_id,
                target,
                result["status"],
                authorisation_confirmed=authorisation_confirmed,
                summary=summary,
                run_mode_id=run_mode_id,
                run_mode_label=run_mode_label,
                conn=db_context,
            )
        return result

    summary = review_data.get("summary") or "File metadata review completed."
    result = make_result(
        module_id,
        success=True,
        status=status,
        summary=summary,
        raw_output=review_data.get("raw_output", ""),
        warnings=warnings,
        parsed_data=parsed_data,
        interpreter_findings=interpreter_findings,
    )

    if db_context is not None and case_id is not None and entity_id is not None:
        _persist_file_metadata_records(
            db_context,
            case_id=case_id,
            entity_id=entity_id,
            module_id=module_id,
            target=target,
            result=result,
            authorisation_confirmed=authorisation_confirmed,
            run_mode_id=run_mode_id,
            run_mode_label=run_mode_label,
        )

    return result

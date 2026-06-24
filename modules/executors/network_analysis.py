"""Network analysis module execution handlers."""

from __future__ import annotations

import sqlite3
from typing import Any

from database.db_setup import create_operation_log
from utils.findings_registry import interpret_module_findings
from utils.result_status import STATUS_BLOCKED, STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_ERROR, STATUS_PARTIAL

from modules.executors import loaders
from modules.executors.loaders import (
    _live_capture_handler,
    _live_capture_load_error,
    _load_live_capture_handler,
    _load_pcap_review_handler,
    _pcap_review_handler,
    _pcap_review_load_error,
)
from modules.executors.persistence import _persist_live_capture_records, _persist_pcap_records
from modules.executors.results import make_result

def _execute_pcap_review(
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
    pcap_review_handler, pcap_review_load_error = loaders.loaded_handler(
        loaders._load_pcap_review_handler, "_pcap_review_handler", "_pcap_review_load_error"
    )
    if pcap_review_handler is None:
        error_message = pcap_review_load_error or "PCAP Evidence Review module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="PCAP Evidence Review module is not available.",
            errors=[error_message],
        )

    target_type = get_target_type(target)
    module = get_module(module_id)
    if module and not module_accepts_target(module, target_type):
        reason = get_incompatible_reason(module, target_type)
        return make_result(
            module_id,
            success=False,
            status=STATUS_BLOCKED,
            summary=reason or "Target type is not supported for PCAP review.",
            errors=[reason or "incompatible_target"],
        )

    run_options = dict(options or {})
    run_options.setdefault("pcap_filename", target)
    run_options.setdefault("target_type", target_type)
    if case_id is not None:
        run_options.setdefault("case_id", case_id)

    review_data = pcap_review_handler(target, options=run_options)
    status = review_data.get("status") or STATUS_ERROR
    parsed_data = review_data.get("parsed_data") or {}
    filename = parsed_data.get("filename") or target
    interpreter_findings = review_data.get("interpreter_findings")
    if interpreter_findings is None:
        interpreter_findings = interpret_module_findings(module_id, parsed_data)
    warnings = list(review_data.get("warnings") or [])
    errors = list(review_data.get("errors") or [])

    if not review_data.get("success"):
        summary = review_data.get("summary") or (errors[0] if errors else "PCAP review failed.")
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
                filename,
                result["status"],
                authorisation_confirmed=authorisation_confirmed,
                summary=summary,
                run_mode_id=run_mode_id,
                run_mode_label=run_mode_label,
                conn=db_context,
            )
        return result

    summary = review_data.get("summary") or f"PCAP evidence review completed for {filename}."
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
        _persist_pcap_records(
            db_context,
            case_id=case_id,
            entity_id=entity_id,
            module_id=module_id,
            target=filename,
            result=result,
            authorisation_confirmed=authorisation_confirmed,
            run_mode_id=run_mode_id,
            run_mode_label=run_mode_label,
        )

    return result


def _execute_live_capture(
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
    live_capture_handler, live_capture_load_error = loaders.loaded_handler(
        loaders._load_live_capture_handler, "_live_capture_handler", "_live_capture_load_error"
    )
    if live_capture_handler is None:
        error_message = live_capture_load_error or "Personal Lab Packet Capture module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="Personal Lab Packet Capture module is not available.",
            errors=[error_message],
        )

    run_options = dict(options or {})
    if case_id is not None:
        run_options.setdefault("case_id", case_id)

    capture_data = live_capture_handler(target, options=run_options)
    status = capture_data.get("status") or STATUS_ERROR
    parsed_data = capture_data.get("parsed_data") or {}
    interpreter_findings = capture_data.get("interpreter_findings")
    if interpreter_findings is None:
        interpreter_findings = interpret_module_findings(module_id, parsed_data)
    warnings = list(capture_data.get("warnings") or [])
    errors = list(capture_data.get("errors") or [])

    if not capture_data.get("success"):
        summary = capture_data.get("summary") or (errors[0] if errors else "Live capture failed.")
        result = make_result(
            module_id,
            success=False,
            status=status,
            summary=summary,
            raw_output=capture_data.get("raw_output", ""),
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

    summary = capture_data.get("summary") or "Personal Lab packet capture completed."
    result = make_result(
        module_id,
        success=True,
        status=status,
        summary=summary,
        raw_output=capture_data.get("raw_output", ""),
        warnings=warnings,
        parsed_data=parsed_data,
        interpreter_findings=interpreter_findings,
    )

    if db_context is not None and case_id is not None and entity_id is not None:
        _persist_live_capture_records(
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

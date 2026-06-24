"""Threat intelligence module execution handlers."""

from __future__ import annotations

import sqlite3
from typing import Any

from database.db_setup import create_operation_log
from utils.findings_registry import interpret_module_findings
from utils.result_status import STATUS_BLOCKED, STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_ERROR

from modules.executors.loaders import (
    _abuseipdb_handler,
    _abuseipdb_load_error,
    _greynoise_handler,
    _greynoise_load_error,
    _load_abuseipdb_handler,
    _load_greynoise_handler,
    _load_shodan_handler,
    _load_urlhaus_handler,
    _load_virustotal_handler,
    _shodan_handler,
    _shodan_load_error,
    _urlhaus_handler,
    _urlhaus_load_error,
    _virustotal_handler,
    _virustotal_load_error,
)
from modules.executors.persistence import (
    _persist_abuseipdb_records,
    _persist_greynoise_records,
    _persist_shodan_records,
    _persist_urlhaus_records,
    _persist_virustotal_records,
)
from modules.executors.results import make_result

def _execute_virustotal(
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
    _load_virustotal_handler()
    if _virustotal_handler is None:
        error_message = _virustotal_load_error or "VirusTotal module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="VirusTotal module is not available.",
            errors=[error_message],
        )

    from utils.settings_manager import get_env

    api_key = get_env("VIRUSTOTAL_API_KEY") or ""
    target_type = get_target_type(target)
    intel_data = _virustotal_handler(
        target,
        api_key=api_key,
        target_type=target_type,
        options=options,
    )
    status = intel_data.get("status") or STATUS_ERROR
    parsed_data = intel_data.get("parsed_data") or {}
    lookup_target = parsed_data.get("target") or target
    interpreter_findings = interpret_module_findings(module_id, parsed_data)
    warnings = list(intel_data.get("warnings") or [])
    errors = list(intel_data.get("errors") or [])

    if not intel_data.get("success"):
        summary = errors[0] if errors else "VirusTotal lookup failed."
        result = make_result(
            module_id,
            success=False,
            status=status,
            summary=summary,
            raw_output=intel_data.get("raw_output", ""),
            errors=errors,
            parsed_data=parsed_data,
            warnings=warnings,
            evidence=intel_data.get("evidence", []),
            interpreter_findings=interpreter_findings,
        )
        if db_context is not None and case_id is not None:
            create_operation_log(
                case_id,
                module_id,
                lookup_target,
                result["status"],
                authorisation_confirmed=authorisation_confirmed,
                summary=summary,
                run_mode_id=run_mode_id,
                run_mode_label=run_mode_label,
                conn=db_context,
            )
        return result

    if parsed_data.get("private_local_ip"):
        summary = "Private/local IP address — public reputation lookup is not applicable."
    else:
        summary = f"VirusTotal reputation lookup completed for {lookup_target}."
    status = intel_data.get("status") or STATUS_COMPLETED
    result = make_result(
        module_id,
        success=True,
        status=status,
        summary=summary,
        raw_output=intel_data.get("raw_output", ""),
        findings=intel_data.get("findings", []),
        warnings=warnings,
        parsed_data=parsed_data,
        interpreter_findings=interpreter_findings,
        evidence=intel_data.get("evidence", []),
    )

    if db_context is not None and case_id is not None:
        entity_type = ENTITY_TYPE_BY_TARGET.get(parsed_data.get("target_type") or target_type, "unknown")
        target_entity = create_or_get_entity(
            case_id,
            entity_type,
            lookup_target,
            label=lookup_target,
            source=module_id,
            conn=db_context,
        )
        _persist_virustotal_records(
            db_context,
            case_id=case_id,
            entity_id=target_entity["id"],
            module_id=module_id,
            target=lookup_target,
            result=result,
            authorisation_confirmed=authorisation_confirmed,
            run_mode_id=run_mode_id,
            run_mode_label=run_mode_label,
        )

    return result


def _execute_abuseipdb(
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
    _load_abuseipdb_handler()
    if _abuseipdb_handler is None:
        error_message = _abuseipdb_load_error or "AbuseIPDB module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="AbuseIPDB module is not available.",
            errors=[error_message],
        )

    from utils.settings_manager import get_env

    api_key = get_env("ABUSEIPDB_API_KEY") or ""
    target_type = get_target_type(target)
    intel_data = _abuseipdb_handler(
        target,
        api_key=api_key,
        target_type=target_type,
        options=options,
    )
    status = intel_data.get("status") or STATUS_ERROR
    parsed_data = intel_data.get("parsed_data") or {}
    lookup_target = parsed_data.get("ip_address") or parsed_data.get("target") or target
    interpreter_findings = interpret_module_findings(module_id, parsed_data)
    warnings = list(intel_data.get("warnings") or [])
    errors = list(intel_data.get("errors") or [])

    if not intel_data.get("success"):
        summary = errors[0] if errors else "AbuseIPDB lookup failed."
        result = make_result(
            module_id,
            success=False,
            status=status,
            summary=summary,
            raw_output=intel_data.get("raw_output", ""),
            errors=errors,
            parsed_data=parsed_data,
            warnings=warnings,
            evidence=intel_data.get("evidence", []),
            interpreter_findings=interpreter_findings,
        )
        if db_context is not None and case_id is not None:
            create_operation_log(
                case_id,
                module_id,
                lookup_target,
                result["status"],
                authorisation_confirmed=authorisation_confirmed,
                summary=summary,
                run_mode_id=run_mode_id,
                run_mode_label=run_mode_label,
                conn=db_context,
            )
        return result

    if parsed_data.get("private_local_ip"):
        summary = "Private/local IP address — public AbuseIPDB reputation lookup is not applicable."
    else:
        summary = f"AbuseIPDB reputation lookup completed for {lookup_target}."
    status = intel_data.get("status") or STATUS_COMPLETED
    result = make_result(
        module_id,
        success=True,
        status=status,
        summary=summary,
        raw_output=intel_data.get("raw_output", ""),
        findings=intel_data.get("findings", []),
        warnings=warnings,
        parsed_data=parsed_data,
        interpreter_findings=interpreter_findings,
        evidence=intel_data.get("evidence", []),
    )

    if db_context is not None and case_id is not None:
        target_entity = create_or_get_entity(
            case_id,
            "ipv4",
            lookup_target,
            label=lookup_target,
            source=module_id,
            conn=db_context,
        )
        _persist_abuseipdb_records(
            db_context,
            case_id=case_id,
            entity_id=target_entity["id"],
            module_id=module_id,
            target=lookup_target,
            result=result,
            authorisation_confirmed=authorisation_confirmed,
            run_mode_id=run_mode_id,
            run_mode_label=run_mode_label,
        )

    return result


def _execute_greynoise(
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
    _load_greynoise_handler()
    if _greynoise_handler is None:
        error_message = _greynoise_load_error or "GreyNoise module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="GreyNoise module is not available.",
            errors=[error_message],
        )

    from utils.settings_manager import get_env

    api_key = get_env("GREYNOISE_API_KEY")
    target_type = get_target_type(target)
    intel_data = _greynoise_handler(
        target,
        api_key=api_key,
        target_type=target_type,
        options=options,
    )
    status = intel_data.get("status") or STATUS_ERROR
    parsed_data = intel_data.get("parsed_data") or {}
    lookup_target = parsed_data.get("ip_address") or parsed_data.get("target") or target
    interpreter_findings = interpret_module_findings(module_id, parsed_data)
    warnings = list(intel_data.get("warnings") or [])
    errors = list(intel_data.get("errors") or [])

    if not intel_data.get("success"):
        summary = errors[0] if errors else "GreyNoise lookup failed."
        result = make_result(
            module_id,
            success=False,
            status=status,
            summary=summary,
            raw_output=intel_data.get("raw_output", ""),
            errors=errors,
            parsed_data=parsed_data,
            warnings=warnings,
            evidence=intel_data.get("evidence", []),
            interpreter_findings=interpreter_findings,
        )
        if db_context is not None and case_id is not None:
            create_operation_log(
                case_id,
                module_id,
                lookup_target,
                result["status"],
                authorisation_confirmed=authorisation_confirmed,
                summary=summary,
                run_mode_id=run_mode_id,
                run_mode_label=run_mode_label,
                conn=db_context,
            )
        return result

    if parsed_data.get("private_local_ip"):
        summary = "Private/local IP address — public GreyNoise internet-noise lookup is not applicable."
    else:
        summary = f"GreyNoise internet-noise lookup completed for {lookup_target}."
    status = intel_data.get("status") or STATUS_COMPLETED
    result = make_result(
        module_id,
        success=True,
        status=status,
        summary=summary,
        raw_output=intel_data.get("raw_output", ""),
        findings=intel_data.get("findings", []),
        warnings=warnings,
        parsed_data=parsed_data,
        interpreter_findings=interpreter_findings,
        evidence=intel_data.get("evidence", []),
    )

    if db_context is not None and case_id is not None:
        target_entity = create_or_get_entity(
            case_id,
            "ipv4",
            lookup_target,
            label=lookup_target,
            source=module_id,
            conn=db_context,
        )
        _persist_greynoise_records(
            db_context,
            case_id=case_id,
            entity_id=target_entity["id"],
            module_id=module_id,
            target=lookup_target,
            result=result,
            authorisation_confirmed=authorisation_confirmed,
            run_mode_id=run_mode_id,
            run_mode_label=run_mode_label,
        )

    return result


def _execute_shodan(
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
    _load_shodan_handler()
    if _shodan_handler is None:
        error_message = _shodan_load_error or "Shodan module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="Shodan module is not available.",
            errors=[error_message],
        )

    from utils.settings_manager import get_env

    api_key = get_env("SHODAN_API_KEY") or ""
    target_type = get_target_type(target)
    intel_data = _shodan_handler(
        target,
        api_key=api_key,
        target_type=target_type,
        options=options,
    )
    status = intel_data.get("status") or STATUS_ERROR
    parsed_data = intel_data.get("parsed_data") or {}
    lookup_target = parsed_data.get("ip_address") or parsed_data.get("target") or target
    interpreter_findings = interpret_module_findings(module_id, parsed_data)
    warnings = list(intel_data.get("warnings") or [])
    errors = list(intel_data.get("errors") or [])

    if not intel_data.get("success"):
        summary = errors[0] if errors else "Shodan lookup failed."
        result = make_result(
            module_id,
            success=False,
            status=status,
            summary=summary,
            raw_output=intel_data.get("raw_output", ""),
            errors=errors,
            parsed_data=parsed_data,
            warnings=warnings,
            evidence=intel_data.get("evidence", []),
            interpreter_findings=interpreter_findings,
        )
        if db_context is not None and case_id is not None:
            create_operation_log(
                case_id,
                module_id,
                lookup_target,
                result["status"],
                authorisation_confirmed=authorisation_confirmed,
                summary=summary,
                run_mode_id=run_mode_id,
                run_mode_label=run_mode_label,
                conn=db_context,
            )
        return result

    if parsed_data.get("private_local_ip"):
        summary = "Private/local IP address — public Shodan internet-exposure lookup is not applicable."
    else:
        summary = f"Shodan internet-exposure lookup completed for {lookup_target}."
    status = intel_data.get("status") or STATUS_COMPLETED
    result = make_result(
        module_id,
        success=True,
        status=status,
        summary=summary,
        raw_output=intel_data.get("raw_output", ""),
        findings=intel_data.get("findings", []),
        warnings=warnings,
        parsed_data=parsed_data,
        interpreter_findings=interpreter_findings,
        evidence=intel_data.get("evidence", []),
    )

    if db_context is not None and case_id is not None:
        target_entity = create_or_get_entity(
            case_id,
            "ipv4",
            lookup_target,
            label=lookup_target,
            source=module_id,
            conn=db_context,
        )
        _persist_shodan_records(
            db_context,
            case_id=case_id,
            entity_id=target_entity["id"],
            module_id=module_id,
            target=lookup_target,
            result=result,
            authorisation_confirmed=authorisation_confirmed,
            run_mode_id=run_mode_id,
            run_mode_label=run_mode_label,
        )

    return result


def _execute_urlhaus(
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
    _load_urlhaus_handler()
    if _urlhaus_handler is None:
        error_message = _urlhaus_load_error or "URLhaus module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="URLhaus module is not available.",
            errors=[error_message],
        )

    from utils.settings_manager import get_urlhaus_auth_key

    auth_key = get_urlhaus_auth_key()
    target_type = get_target_type(target)
    intel_data = _urlhaus_handler(
        target,
        auth_key=auth_key,
        target_type=target_type,
        options=options,
    )
    status = intel_data.get("status") or STATUS_ERROR
    parsed_data = intel_data.get("parsed_data") or {}
    lookup_target = parsed_data.get("lookup_value") or parsed_data.get("target") or target
    interpreter_findings = interpret_module_findings(module_id, parsed_data)
    warnings = list(intel_data.get("warnings") or [])
    errors = list(intel_data.get("errors") or [])

    if not intel_data.get("success"):
        summary = errors[0] if errors else "URLhaus lookup failed."
        result = make_result(
            module_id,
            success=False,
            status=status,
            summary=summary,
            raw_output=intel_data.get("raw_output", ""),
            errors=errors,
            parsed_data=parsed_data,
            warnings=warnings,
            evidence=intel_data.get("evidence", []),
            interpreter_findings=interpreter_findings,
        )
        if db_context is not None and case_id is not None:
            create_operation_log(
                case_id,
                module_id,
                lookup_target,
                result["status"],
                authorisation_confirmed=authorisation_confirmed,
                summary=summary,
                run_mode_id=run_mode_id,
                run_mode_label=run_mode_label,
                conn=db_context,
            )
        return result

    if parsed_data.get("private_local_ip"):
        summary = "Private/local IP address — public URLhaus malware URL lookup is not applicable."
    else:
        summary = f"URLhaus malware URL lookup completed for {lookup_target}."
    status = intel_data.get("status") or STATUS_COMPLETED
    result = make_result(
        module_id,
        success=True,
        status=status,
        summary=summary,
        raw_output=intel_data.get("raw_output", ""),
        findings=intel_data.get("findings", []),
        warnings=warnings,
        parsed_data=parsed_data,
        interpreter_findings=interpreter_findings,
        evidence=intel_data.get("evidence", []),
    )

    if db_context is not None and case_id is not None:
        entity_type = ENTITY_TYPE_BY_TARGET.get(parsed_data.get("target_type") or target_type, "unknown")
        if entity_type == "domain" and target_type == "url":
            entity_type = "url"
        target_entity = create_or_get_entity(
            case_id,
            entity_type,
            lookup_target,
            label=lookup_target,
            source=module_id,
            conn=db_context,
        )
        _persist_urlhaus_records(
            db_context,
            case_id=case_id,
            entity_id=target_entity["id"],
            module_id=module_id,
            target=lookup_target,
            result=result,
            authorisation_confirmed=authorisation_confirmed,
            run_mode_id=run_mode_id,
            run_mode_label=run_mode_label,
        )

    return result


"""Infrastructure module execution handlers."""

from __future__ import annotations

import shutil
import sqlite3
from typing import Any

from database.db_setup import create_operation_log
from utils.findings_registry import interpret_module_findings
from utils.nmap_options import SCRIPT_VULN, build_nmap_flags, normalize_options
from utils.nmap_profiles import enrich_parsed_scan_metadata, profile_display_name, resolve_profile_id
from utils.nmap_xml_parser import parse_nmap_results
from utils.result_status import (
    STATUS_BLOCKED,
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_WARNINGS,
    STATUS_ERROR,
)

from modules.executors import loaders
from modules.executors.loaders import (
    _cert_subdomain_handler,
    _cert_subdomain_load_error,
    _domain_intel_handler,
    _domain_intel_load_error,
    _email_security_handler,
    _email_security_load_error,
    _http_security_handler,
    _http_security_load_error,
    _load_cert_subdomain_handler,
    _load_domain_intel_handler,
    _load_email_security_handler,
    _load_http_security_handler,
    _load_nmap_handlers,
    _load_tls_review_handler,
    _load_website_metadata_handler,
    _load_whois_rdap_handler,
    _nmap_handlers,
    _nmap_load_error,
    _tls_review_handler,
    _tls_review_load_error,
    _website_metadata_handler,
    _website_metadata_load_error,
    _whois_rdap_handler,
    _whois_rdap_load_error,
)
from modules.executors.persistence import (
    _persist_cert_subdomain_records,
    _persist_domain_intel_records,
    _persist_email_security_records,
    _persist_http_security_records,
    _persist_remote_access_records,
    _persist_investigation_records,
    _persist_nmap_services_and_relationships,
    _persist_tls_review_records,
    _persist_website_metadata_records,
    _persist_whois_rdap_records,
    _save_recon_output,
)
from modules.executors.results import make_result

def _scan_output_text(scan_data: dict[str, Any]) -> str:
    parts = [
        scan_data.get("raw_output", ""),
        scan_data.get("stderr", ""),
        scan_data.get("stdout", ""),
    ]
    return "\n".join(part for part in parts if part)


def _scan_failed(scan_data: dict[str, Any]) -> bool:
    if not scan_data.get("success", True):
        return True
    return scan_data.get("raw_output", "").startswith("Error")


def _run_nmap_with_privilege_retry(
    run_nmap_scan: Any,
    target: str,
    nmap_options: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Run Nmap and retry without privilege-sensitive flags if Nmap reports a root error."""
    current_options = normalize_options(nmap_options)
    flags = build_nmap_flags(current_options)
    scan_data = run_nmap_scan(target, flags)

    if not _scan_failed(scan_data):
        return scan_data, current_options

    issue = detect_nmap_privilege_issue(_scan_output_text(scan_data))
    if issue == "os_detection" and "-O" in flags:
        current_options["os_detection"] = False
        current_options["os_detection_skipped"] = True
        current_options["os_detection_runtime_failed"] = True
        flags = build_nmap_flags(current_options)
        scan_data = run_nmap_scan(target, flags)
        if not _scan_failed(scan_data):
            return scan_data, current_options

    if _scan_failed(scan_data):
        issue = detect_nmap_privilege_issue(_scan_output_text(scan_data))
        current_flags = build_nmap_flags(current_options)
        if issue == "traceroute" and "--traceroute" in current_flags:
            current_options["traceroute"] = False
            current_options["traceroute_skipped"] = True
            current_options["traceroute_runtime_failed"] = True
            scan_data = run_nmap_scan(target, build_nmap_flags(current_options))

    return scan_data, current_options


def _build_nmap_summary(target: str, nmap_options: dict[str, Any], parsed_data: dict[str, Any] | None = None) -> str:
    profile_id = resolve_profile_id(nmap_options.get("profile_id") or nmap_options.get("profile"))
    profile_name = profile_display_name(profile_id)
    open_count = len((parsed_data or {}).get("parsed_ports") or [])
    summary = f"Nmap {profile_name} completed for {target}."
    if open_count:
        summary += f" {open_count} open port(s) observed."
    notes: list[str] = []
    if nmap_options.get("os_detection_runtime_failed"):
        notes.append("OS detection failed at runtime and was not included in the final result")
    elif nmap_options.get("os_detection_skipped"):
        notes.append("OS detection was skipped")
    if nmap_options.get("traceroute_runtime_failed"):
        notes.append("traceroute failed at runtime and was not included in the final result")
    elif nmap_options.get("traceroute_skipped"):
        notes.append("traceroute was skipped")
    if notes:
        summary += " " + "; ".join(notes) + "."
    return summary


def _execute_nmap(
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
    loaders._load_nmap_handlers()
    if loaders._nmap_handlers is None:
        error_message = loaders._nmap_load_error or "Nmap module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="Nmap module is not available.",
            errors=[error_message],
        )

    run_nmap_scan, _parse_nmap_problems = loaders._nmap_handlers
    nmap_options = normalize_options(options.get("nmap_options", {}))
    port_errors = list(nmap_options.get("custom_port_errors") or [])
    if port_errors:
        return make_result(
            module_id,
            success=False,
            status="blocked",
            summary="Custom port list is invalid.",
            errors=port_errors,
            selected_options=nmap_options,
        )

    if nmap_options.get("script_category") == SCRIPT_VULN and not authorisation_confirmed:
        return make_result(
            module_id,
            success=False,
            status="blocked",
            summary="Nmap vuln scripts require authorisation confirmation.",
            errors=["authorisation_required_for_vuln_scripts"],
            selected_options=nmap_options,
        )

    scan_data, nmap_options = _run_nmap_with_privilege_retry(run_nmap_scan, target, nmap_options)
    raw_output = scan_data.get("raw_output", "")
    findings = scan_data.get("findings", [])
    xml_output = scan_data.get("xml_output", "")
    is_error = _scan_failed(scan_data)
    flags = build_nmap_flags(nmap_options)

    parsed_data = parse_nmap_results(raw_output, xml_output)
    parsed_data = enrich_parsed_scan_metadata(
        parsed_data,
        target=target,
        nmap_options=nmap_options,
        flags=flags,
    )
    if xml_output:
        parsed_data["xml_output"] = xml_output
    interpreter_findings = interpret_module_findings(
        module_id,
        parsed_data,
        nmap_options,
    )

    if is_error:
        result = make_result(
            module_id,
            success=False,
            status="error",
            summary=f"Nmap scan failed for {target}.",
            raw_output=raw_output,
            findings=findings,
            errors=[raw_output],
            parsed_data=parsed_data,
            interpreter_findings=interpreter_findings,
            selected_options=nmap_options,
        )
    else:
        nmap_warnings: list[str] = []
        if nmap_options.get("os_detection_runtime_failed"):
            nmap_warnings.append("OS detection failed at runtime and was not included in the final result.")
        elif nmap_options.get("os_detection_skipped"):
            nmap_warnings.append("OS detection was skipped because elevated privileges were not available.")
        if nmap_options.get("traceroute_runtime_failed"):
            nmap_warnings.append("Traceroute failed at runtime and was not included in the final result.")
        elif nmap_options.get("traceroute_skipped"):
            nmap_warnings.append("Traceroute was skipped because elevated privileges were not available.")
        nmap_status = STATUS_COMPLETED_WITH_WARNINGS if nmap_warnings else STATUS_COMPLETED
        result = make_result(
            module_id,
            success=True,
            status=nmap_status,
            summary=_build_nmap_summary(target, nmap_options, parsed_data),
            raw_output=raw_output,
            findings=findings,
            warnings=nmap_warnings,
            parsed_data=parsed_data,
            interpreter_findings=interpreter_findings,
            selected_options=nmap_options,
        )

    if db_context is not None:
        if not is_error:
            _save_recon_output(db_context, target, raw_output)
        if case_id is not None:
            _persist_investigation_records(
                db_context,
                case_id=case_id,
                entity_id=entity_id,
                module_id=module_id,
                target=target,
                result=result,
                authorisation_confirmed=authorisation_confirmed,
                options=options,
                run_mode_id=run_mode_id,
                run_mode_label=run_mode_label,
            )

    return result


def _domain_intel_connectivity_note(parsed_data: dict[str, Any]) -> str | None:
    """Return a user-friendly note when collection looks blocked by network issues."""
    dns = parsed_data.get("dns", {})
    has_dns = any(dns.get(record_type) for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME"))
    http = parsed_data.get("http", {})
    http_ok = http.get("https", {}).get("reachable") or http.get("http", {}).get("reachable")
    errors: list[str] = []
    for key in ("http", "https"):
        err = (http.get(key) or {}).get("error") or ""
        if err:
            errors.append(err.lower())
    wayback_error = (parsed_data.get("wayback") or {}).get("error") or ""
    if wayback_error:
        errors.append(wayback_error.lower())
    network_keywords = ("timeout", "timed out", "connection", "network", "unreachable", "failed to establish")
    if not has_dns and not http_ok:
        return "Limited or no DNS/HTTP response — check your network connection and try again."
    if any(any(word in err for word in network_keywords) for err in errors):
        return "Some lookups failed — results may be incomplete. Check your network connection."
    return None


def _execute_domain_intel(
    module_id: str,
    target: str,
    db_context: sqlite3.Connection | None,
    authorisation_confirmed: bool,
    case_id: int | None,
    entity_id: int | None,
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> dict[str, Any]:
    domain_intel_handler, domain_intel_load_error = loaders.loaded_handler(
        loaders._load_domain_intel_handler, "_domain_intel_handler", "_domain_intel_load_error"
    )
    if domain_intel_handler is None:
        error_message = domain_intel_load_error or "Domain Intelligence module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="Domain Intelligence module is not available.",
            errors=[error_message],
        )

    intel_data = domain_intel_handler(target)
    if not intel_data.get("success"):
        errors = intel_data.get("errors") or ["Domain intelligence collection failed."]
        return make_result(
            module_id,
            success=False,
            status="error",
            summary=errors[0],
            raw_output=intel_data.get("raw_output", ""),
            errors=errors,
            parsed_data=intel_data.get("parsed_data"),
        )

    parsed_data = intel_data.get("parsed_data") or {}
    domain = parsed_data.get("domain") or target
    interpreter_findings = interpret_module_findings(module_id, parsed_data)
    summary = f"Domain intelligence collected for {domain}."
    connectivity_note = _domain_intel_connectivity_note(parsed_data)
    if connectivity_note:
        summary += f" {connectivity_note}"
    warnings = list(intel_data.get("warnings") or [])
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
    )

    if db_context is not None and case_id is not None:
        domain_entity = create_or_get_entity(
            case_id,
            "domain",
            domain,
            label=domain,
            source=module_id,
            conn=db_context,
        )
        _persist_domain_intel_records(
            db_context,
            case_id=case_id,
            domain_entity_id=domain_entity["id"],
            module_id=module_id,
            target=domain,
            result=result,
            authorisation_confirmed=authorisation_confirmed,
            run_mode_id=run_mode_id,
            run_mode_label=run_mode_label,
        )

    return result


def _execute_cert_subdomain(
    module_id: str,
    target: str,
    db_context: sqlite3.Connection | None,
    authorisation_confirmed: bool,
    case_id: int | None,
    entity_id: int | None,
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> dict[str, Any]:
    cert_subdomain_handler, cert_subdomain_load_error = loaders.loaded_handler(
        loaders._load_cert_subdomain_handler, "_cert_subdomain_handler", "_cert_subdomain_load_error"
    )
    if cert_subdomain_handler is None:
        error_message = cert_subdomain_load_error or "Certificate & Subdomain Intelligence module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="Certificate & Subdomain Intelligence module is not available.",
            errors=[error_message],
        )

    intel_data = cert_subdomain_handler(target)
    if not intel_data.get("success"):
        errors = intel_data.get("errors") or ["Certificate and subdomain intelligence collection failed."]
        return make_result(
            module_id,
            success=False,
            status="error",
            summary=errors[0],
            raw_output=intel_data.get("raw_output", ""),
            errors=errors,
            parsed_data=intel_data.get("data"),
        )

    parsed_data = intel_data.get("data") or {}
    domain = parsed_data.get("domain") or target
    interpreter_findings = interpret_module_findings(module_id, parsed_data)
    result = make_result(
        module_id,
        success=True,
        status=intel_data.get("status", "completed"),
        summary=intel_data.get("summary", f"Certificate intelligence collected for {domain}."),
        raw_output=intel_data.get("raw_output", ""),
        findings=intel_data.get("findings", []),
        warnings=intel_data.get("warnings", []),
        parsed_data=parsed_data,
        interpreter_findings=interpreter_findings,
    )

    if db_context is not None and case_id is not None:
        domain_entity = create_or_get_entity(
            case_id,
            "domain",
            domain,
            label=domain,
            source=module_id,
            conn=db_context,
        )
        _persist_cert_subdomain_records(
            db_context,
            case_id=case_id,
            domain_entity_id=domain_entity["id"],
            module_id=module_id,
            target=domain,
            result=result,
            authorisation_confirmed=authorisation_confirmed,
            run_mode_id=run_mode_id,
            run_mode_label=run_mode_label,
        )

    return result


def _execute_website_metadata(
    module_id: str,
    target: str,
    db_context: sqlite3.Connection | None,
    authorisation_confirmed: bool,
    case_id: int | None,
    entity_id: int | None,
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> dict[str, Any]:
    website_metadata_handler, website_metadata_load_error = loaders.loaded_handler(
        loaders._load_website_metadata_handler, "_website_metadata_handler", "_website_metadata_load_error"
    )
    if website_metadata_handler is None:
        error_message = website_metadata_load_error or "Website Metadata Review module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="Website Metadata Review module is not available.",
            errors=[error_message],
        )

    intel_data = website_metadata_handler(target)
    if not intel_data.get("success"):
        errors = intel_data.get("errors") or ["Website metadata review failed."]
        return make_result(
            module_id,
            success=False,
            status="error",
            summary=errors[0],
            raw_output=intel_data.get("raw_output", ""),
            errors=errors,
            parsed_data=intel_data.get("data"),
        )

    parsed_data = intel_data.get("data") or {}
    domain = parsed_data.get("domain") or target
    interpreter_findings = interpret_module_findings(module_id, parsed_data)
    result = make_result(
        module_id,
        success=True,
        status=intel_data.get("status", "completed"),
        summary=intel_data.get("summary", f"Website metadata reviewed for {domain}."),
        raw_output=intel_data.get("raw_output", ""),
        findings=intel_data.get("findings", []),
        warnings=intel_data.get("warnings", []),
        parsed_data=parsed_data,
        interpreter_findings=interpreter_findings,
    )

    if db_context is not None and case_id is not None:
        domain_entity = create_or_get_entity(
            case_id,
            "domain",
            domain,
            label=domain,
            source=module_id,
            conn=db_context,
        )
        _persist_website_metadata_records(
            db_context,
            case_id=case_id,
            domain_entity_id=domain_entity["id"],
            module_id=module_id,
            target=domain,
            result=result,
            authorisation_confirmed=authorisation_confirmed,
            run_mode_id=run_mode_id,
            run_mode_label=run_mode_label,
        )

    return result


def _execute_email_security(
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
    email_security_handler, email_security_load_error = loaders.loaded_handler(
        loaders._load_email_security_handler, "_email_security_handler", "_email_security_load_error"
    )
    if email_security_handler is None:
        error_message = email_security_load_error or "Domain Email Security Posture module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="Domain Email Security Posture module is not available.",
            errors=[error_message],
        )

    intel_data = email_security_handler(target, options=options)
    if not intel_data.get("success"):
        errors = intel_data.get("errors") or ["Domain email security review failed."]
        return make_result(
            module_id,
            success=False,
            status=intel_data.get("status", "error"),
            summary=errors[0],
            raw_output=intel_data.get("raw_output", ""),
            errors=errors,
            parsed_data=intel_data.get("data"),
            warnings=intel_data.get("warnings", []),
        )

    parsed_data = intel_data.get("data") or {}
    domain = parsed_data.get("domain") or target
    interpreter_findings = interpret_module_findings(module_id, parsed_data)
    result = make_result(
        module_id,
        success=True,
        status=intel_data.get("status", "completed"),
        summary=intel_data.get("summary", f"Email security posture reviewed for {domain}."),
        raw_output=intel_data.get("raw_output", ""),
        findings=intel_data.get("findings", []),
        warnings=intel_data.get("warnings", []),
        parsed_data=parsed_data,
        interpreter_findings=interpreter_findings,
    )

    if db_context is not None and case_id is not None:
        domain_entity = create_or_get_entity(
            case_id,
            "domain",
            domain,
            label=domain,
            source=module_id,
            conn=db_context,
        )
        _persist_email_security_records(
            db_context,
            case_id=case_id,
            domain_entity_id=domain_entity["id"],
            module_id=module_id,
            target=domain,
            result=result,
            authorisation_confirmed=authorisation_confirmed,
            run_mode_id=run_mode_id,
            run_mode_label=run_mode_label,
        )

    return result


def _execute_tls_review(
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
    tls_review_handler, tls_review_load_error = loaders.loaded_handler(
        loaders._load_tls_review_handler, "_tls_review_handler", "_tls_review_load_error"
    )
    if tls_review_handler is None:
        error_message = tls_review_load_error or "SSL / TLS Configuration Review module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="SSL / TLS Configuration Review module is not available.",
            errors=[error_message],
        )

    tls_data = tls_review_handler(target, options=options)
    status = tls_data.get("status", "error")
    if status == "blocked":
        errors = tls_data.get("errors") or [tls_data.get("summary") or "TLS review blocked."]
        return make_result(
            module_id,
            success=False,
            status="blocked",
            summary=errors[0],
            raw_output=tls_data.get("raw_output", ""),
            errors=errors,
            parsed_data=tls_data.get("data"),
            warnings=tls_data.get("warnings", []),
        )

    if not tls_data.get("success"):
        errors = tls_data.get("errors") or tls_data.get("warnings") or ["TLS review failed."]
        return make_result(
            module_id,
            success=False,
            status=status,
            summary=errors[0] if errors else "TLS review failed.",
            raw_output=tls_data.get("raw_output", ""),
            errors=errors if isinstance(errors, list) else [str(errors)],
            parsed_data=tls_data.get("data"),
            warnings=tls_data.get("warnings", []),
        )

    parsed_data = tls_data.get("data") or {}
    host = parsed_data.get("host") or target
    interpreter_findings = interpret_module_findings(module_id, parsed_data, options)
    result = make_result(
        module_id,
        success=True,
        status=tls_data.get("status", "completed"),
        summary=tls_data.get("summary", f"TLS review completed for {host}."),
        raw_output=tls_data.get("raw_output", ""),
        findings=tls_data.get("findings", []),
        warnings=tls_data.get("warnings", []),
        parsed_data=parsed_data,
        interpreter_findings=interpreter_findings,
    )

    if db_context is not None and case_id is not None:
        target_type = parsed_data.get("target_type") or get_target_type(target)
        host_entity_type = ENTITY_TYPE_BY_TARGET.get(target_type, "domain")
        if target_type in {"domain", "url"}:
            host_entity_type = "domain"
        elif target_type == "ipv4":
            host_entity_type = "ipv4"

        host_entity = create_or_get_entity(
            case_id,
            host_entity_type,
            host,
            label=host,
            source=module_id,
            conn=db_context,
        )
        _persist_tls_review_records(
            db_context,
            case_id=case_id,
            host_entity_id=host_entity["id"],
            module_id=module_id,
            target=target,
            result=result,
            authorisation_confirmed=authorisation_confirmed,
            run_mode_id=run_mode_id,
            run_mode_label=run_mode_label,
        )

    return result


def _execute_http_security(
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
    http_security_handler, http_security_load_error = loaders.loaded_handler(
        loaders._load_http_security_handler, "_http_security_handler", "_http_security_load_error"
    )
    if http_security_handler is None:
        error_message = http_security_load_error or "HTTP Security Header Review module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="HTTP Security Header Review module is not available.",
            errors=[error_message],
        )

    http_data = http_security_handler(target, options=options)
    status = http_data.get("status", "error")
    if status == "blocked":
        errors = http_data.get("errors") or [http_data.get("summary") or "HTTP security review blocked."]
        return make_result(
            module_id,
            success=False,
            status="blocked",
            summary=errors[0],
            raw_output=http_data.get("raw_output", ""),
            errors=errors,
            parsed_data=http_data.get("data"),
            warnings=http_data.get("warnings", []),
        )

    if not http_data.get("success"):
        errors = http_data.get("errors") or http_data.get("warnings") or ["HTTP security review failed."]
        return make_result(
            module_id,
            success=False,
            status=status,
            summary=errors[0] if errors else "HTTP security review failed.",
            raw_output=http_data.get("raw_output", ""),
            errors=errors if isinstance(errors, list) else [str(errors)],
            parsed_data=http_data.get("data"),
            warnings=http_data.get("warnings", []),
        )

    parsed_data = http_data.get("data") or {}
    host = parsed_data.get("host") or target
    interpreter_findings = interpret_module_findings(module_id, parsed_data, options)
    result = make_result(
        module_id,
        success=True,
        status=http_data.get("status", "completed"),
        summary=http_data.get("summary", f"HTTP security review completed for {host}."),
        raw_output=http_data.get("raw_output", ""),
        findings=http_data.get("findings", []),
        warnings=http_data.get("warnings", []),
        parsed_data=parsed_data,
        interpreter_findings=interpreter_findings,
    )

    if db_context is not None and case_id is not None:
        target_type = parsed_data.get("target_type") or get_target_type(target)
        host_entity_type = ENTITY_TYPE_BY_TARGET.get(target_type, "domain")
        if target_type in {"domain", "url"}:
            host_entity_type = "domain"
        elif target_type == "ipv4":
            host_entity_type = "ipv4"

        host_entity = create_or_get_entity(
            case_id,
            host_entity_type,
            host,
            label=host,
            source=module_id,
            conn=db_context,
        )
        _persist_http_security_records(
            db_context,
            case_id=case_id,
            host_entity_id=host_entity["id"],
            module_id=module_id,
            target=target,
            result=result,
            authorisation_confirmed=authorisation_confirmed,
            run_mode_id=run_mode_id,
            run_mode_label=run_mode_label,
        )

    return result


def _execute_remote_access_review(
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
    remote_access_handler, remote_access_load_error = loaders.loaded_handler(
        loaders._load_remote_access_handler, "_remote_access_handler", "_remote_access_load_error"
    )
    if remote_access_handler is None:
        error_message = remote_access_load_error or "Remote Access Exposure Review module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="Remote Access Exposure Review module is not available.",
            errors=[error_message],
        )

    review_options = dict(options)
    if review_options.get("parsed_data") and not review_options.get("parsed_ports"):
        parsed = review_options.get("parsed_data") or {}
        if isinstance(parsed, dict) and parsed.get("parsed_ports"):
            review_options["parsed_ports"] = parsed.get("parsed_ports")

    if db_context is not None and case_id is not None and not review_options.get("discovered_services"):
        from utils.service_discovery import load_discovered_services

        review_options["discovered_services"] = load_discovered_services(
            case_id,
            target,
            conn=db_context,
            latest_results=review_options.get("latest_results"),
        )

    review_data = remote_access_handler(target, options=review_options)
    status = review_data.get("status", "error")
    if not review_data.get("success"):
        errors = review_data.get("errors") or [review_data.get("summary") or "Remote access review failed."]
        return make_result(
            module_id,
            success=False,
            status=status,
            summary=errors[0],
            raw_output=review_data.get("raw_output", ""),
            errors=errors if isinstance(errors, list) else [str(errors)],
            parsed_data=review_data.get("data"),
            warnings=review_data.get("warnings", []),
        )

    parsed_data = review_data.get("data") or {}
    host = parsed_data.get("host") or target
    interpreter_findings = interpret_module_findings(module_id, parsed_data, review_options)
    result = make_result(
        module_id,
        success=True,
        status=review_data.get("status", "completed"),
        summary=review_data.get("summary", f"Remote access review completed for {host}."),
        raw_output=review_data.get("raw_output", ""),
        findings=review_data.get("findings", []),
        warnings=review_data.get("warnings", []),
        parsed_data=parsed_data,
        interpreter_findings=interpreter_findings,
    )

    if db_context is not None and case_id is not None:
        from database.db_setup import create_or_get_entity
        from utils.target_detection import ENTITY_TYPE_BY_TARGET, get_target_type

        target_type = parsed_data.get("target_type") or get_target_type(target)
        host_entity_type = ENTITY_TYPE_BY_TARGET.get(target_type, "domain")
        if target_type in {"domain", "url"}:
            host_entity_type = "domain"
        elif target_type == "ipv4":
            host_entity_type = "ipv4"

        host_entity_id = entity_id
        if host_entity_id is None:
            host_entity = create_or_get_entity(
                case_id,
                host_entity_type,
                host,
                label=host,
                source=module_id,
                conn=db_context,
            )
            host_entity_id = host_entity["id"]

        _persist_remote_access_records(
            db_context,
            case_id=case_id,
            host_entity_id=host_entity_id,
            module_id=module_id,
            target=target,
            result=result,
            authorisation_confirmed=authorisation_confirmed,
            run_mode_id=run_mode_id,
            run_mode_label=run_mode_label,
        )

    return result


def _execute_whois_rdap(
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
    whois_rdap_handler, whois_rdap_load_error = loaders.loaded_handler(
        loaders._load_whois_rdap_handler, "_whois_rdap_handler", "_whois_rdap_load_error"
    )
    if whois_rdap_handler is None:
        error_message = whois_rdap_load_error or "WHOIS/RDAP Intelligence module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="WHOIS/RDAP Intelligence module is not available.",
            errors=[error_message],
        )

    intel_data = whois_rdap_handler(
        target,
        options={**options, "case_id": case_id},
    )
    parsed_data = intel_data.get("parsed_data") or intel_data.get("data") or {}

    if not intel_data.get("success") and intel_data.get("errors"):
        errors = intel_data.get("errors") or ["WHOIS/RDAP lookup failed."]
        return make_result(
            module_id,
            success=False,
            status=intel_data.get("status", "error"),
            summary=errors[0],
            raw_output=intel_data.get("raw_output", ""),
            errors=errors,
            parsed_data=parsed_data,
            warnings=intel_data.get("warnings", []),
            evidence=intel_data.get("evidence", []),
        )

    interpreter_findings = interpret_module_findings(module_id, parsed_data)
    result = make_result(
        module_id,
        success=True,
        status=intel_data.get("status", STATUS_COMPLETED),
        summary=intel_data.get("summary", f"WHOIS/RDAP lookup completed for {target}."),
        raw_output=intel_data.get("raw_output", ""),
        findings=intel_data.get("findings", []),
        warnings=intel_data.get("warnings", []),
        parsed_data=parsed_data,
        interpreter_findings=interpreter_findings,
        evidence=intel_data.get("evidence", []),
    )

    if db_context is not None and case_id is not None:
        target_type = parsed_data.get("target_type") or get_target_type(target)
        query_value = parsed_data.get("query_value") or parsed_data.get("domain_or_ip") or target
        if target_type in {"domain", "url"}:
            entity_type = "domain"
            entity_value = parsed_data.get("domain_or_ip") or query_value
        else:
            entity_type = "ip_address"
            entity_value = query_value

        source_entity = create_or_get_entity(
            case_id,
            entity_type,
            entity_value,
            label=entity_value,
            source=module_id,
            conn=db_context,
        )
        _persist_whois_rdap_records(
            db_context,
            case_id=case_id,
            source_entity_id=source_entity["id"],
            module_id=module_id,
            target=entity_value,
            result=result,
            authorisation_confirmed=authorisation_confirmed,
            run_mode_id=run_mode_id,
            run_mode_label=run_mode_label,
        )

    return result


"""Module execution dispatcher for Project Overwatch."""

from __future__ import annotations

import importlib.util
import json
import shutil
import sqlite3
from pathlib import Path
from typing import Any

from database.db_setup import (
    create_observation,
    create_operation_log,
    create_or_get_entity,
    create_relationship,
)
from modules.module_registry import get_module, is_executable
from utils.findings_registry import interpret_module_findings
from utils.findings_sync import sync_module_findings
from utils.module_compatibility import get_incompatible_reason, module_accepts_target
from utils.target_detection import ENTITY_TYPE_BY_TARGET, get_target_type
from utils.nmap_options import SCRIPT_VULN, build_nmap_flags, normalize_options
from utils.nmap_parser import build_service_entity_label, build_service_entity_value
from utils.nmap_xml_parser import parse_nmap_results
from utils.result_status import (
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_WARNINGS,
    should_persist_observation,
)
from utils.evidence_model import observation_evidence_for_module
from utils.evidence_capture import capture_module_evidence, link_observation_evidence_to_findings
from utils.module_sdk import build_module_result, normalise_result, validate_module_result

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NMAP_MODULE_PATH = PROJECT_ROOT / "modules" / "2_infrastructure" / "infra_nmap.py"
DOMAIN_INTEL_MODULE_PATH = PROJECT_ROOT / "modules" / "2_infrastructure" / "infra_domain_intel.py"
CERT_SUBDOMAIN_MODULE_PATH = PROJECT_ROOT / "modules" / "2_infrastructure" / "infra_cert_subdomain.py"
WEBSITE_METADATA_MODULE_PATH = PROJECT_ROOT / "modules" / "2_infrastructure" / "infra_website_metadata.py"
VIRUSTOTAL_MODULE_PATH = PROJECT_ROOT / "modules" / "4_threat_intel" / "intel_virustotal.py"

_nmap_handlers: tuple[Any, Any] | None = None
_nmap_load_error: str | None = None
_nmap_load_attempted = False
_domain_intel_handler: Any | None = None
_domain_intel_load_error: str | None = None
_domain_intel_load_attempted = False
_cert_subdomain_handler: Any | None = None
_cert_subdomain_load_error: str | None = None
_cert_subdomain_load_attempted = False
_website_metadata_handler: Any | None = None
_website_metadata_load_error: str | None = None
_website_metadata_load_attempted = False
_virustotal_handler: Any | None = None
_virustotal_load_error: str | None = None
_virustotal_load_attempted = False


def _observation_evidence_kwargs(module_id: str, result: dict[str, Any]) -> dict[str, Any]:
    """Build observation evidence fields from module defaults and run result."""
    meta = observation_evidence_for_module(module_id, result)
    return {
        key: meta[key]
        for key in (
            "evidence_type",
            "source_name",
            "source_url",
            "reliability",
            "collection_method",
            "collected_at",
            "module_version",
        )
        if meta.get(key) is not None
    }


def _prepare_module_result(result: dict[str, Any]) -> dict[str, Any]:
    """Normalise and attach non-fatal validation notes to a module result."""
    normalized = normalise_result(result)
    validation = validate_module_result(normalized)
    if validation["errors"]:
        for message in validation["errors"]:
            note = f"Result validation error: {message}"
            if note not in normalized["warnings"]:
                normalized["warnings"].append(note)
    for message in validation["warnings"]:
        note = f"Result validation: {message}"
        if note not in normalized["warnings"]:
            normalized["warnings"].append(note)
    return normalized


def make_result(
    module_id: str,
    *,
    success: bool,
    status: str,
    summary: str,
    raw_output: str = "",
    findings: list[str] | None = None,
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
    parsed_data: dict[str, Any] | None = None,
    interpreter_findings: list[dict[str, Any]] | None = None,
    selected_options: dict[str, Any] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a standard execution result payload."""
    result = build_module_result(
        module_id,
        status,
        summary,
        success=success,
        data=data or parsed_data,
        findings=findings,
        warnings=warnings,
        errors=errors,
        raw_output=raw_output,
        evidence=evidence,
    )
    if interpreter_findings is not None:
        result["interpreter_findings"] = interpreter_findings
    if selected_options is not None:
        result["selected_options"] = selected_options
    if parsed_data is not None:
        result["parsed_data"] = parsed_data
        if not result.get("data"):
            result["data"] = parsed_data
    return _prepare_module_result(result)


def _load_nmap_handlers() -> None:
    global _nmap_handlers, _nmap_load_error, _nmap_load_attempted

    if _nmap_load_attempted:
        return

    _nmap_load_attempted = True

    if not NMAP_MODULE_PATH.is_file():
        _nmap_load_error = f"Module file not found: {NMAP_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("infra_nmap", NMAP_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {NMAP_MODULE_PATH}")
        infra_nmap = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(infra_nmap)
        _nmap_handlers = (infra_nmap.run_nmap_scan, infra_nmap.parse_nmap_problems)
    except Exception as exc:
        _nmap_load_error = str(exc)


def _load_domain_intel_handler() -> None:
    global _domain_intel_handler, _domain_intel_load_error, _domain_intel_load_attempted

    if _domain_intel_load_attempted:
        return

    _domain_intel_load_attempted = True

    if not DOMAIN_INTEL_MODULE_PATH.is_file():
        _domain_intel_load_error = f"Module file not found: {DOMAIN_INTEL_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("infra_domain_intel", DOMAIN_INTEL_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {DOMAIN_INTEL_MODULE_PATH}")
        infra_domain_intel = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(infra_domain_intel)
        _domain_intel_handler = infra_domain_intel.run_domain_intel
    except Exception as exc:
        _domain_intel_load_error = str(exc)


def _load_cert_subdomain_handler() -> None:
    global _cert_subdomain_handler, _cert_subdomain_load_error, _cert_subdomain_load_attempted

    if _cert_subdomain_load_attempted:
        return

    _cert_subdomain_load_attempted = True

    if not CERT_SUBDOMAIN_MODULE_PATH.is_file():
        _cert_subdomain_load_error = f"Module file not found: {CERT_SUBDOMAIN_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("infra_cert_subdomain", CERT_SUBDOMAIN_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {CERT_SUBDOMAIN_MODULE_PATH}")
        infra_cert_subdomain = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(infra_cert_subdomain)
        _cert_subdomain_handler = infra_cert_subdomain.run_cert_subdomain_intel
    except Exception as exc:
        _cert_subdomain_load_error = str(exc)


def _load_website_metadata_handler() -> None:
    global _website_metadata_handler, _website_metadata_load_error, _website_metadata_load_attempted

    if _website_metadata_load_attempted:
        return

    _website_metadata_load_attempted = True

    if not WEBSITE_METADATA_MODULE_PATH.is_file():
        _website_metadata_load_error = f"Module file not found: {WEBSITE_METADATA_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("infra_website_metadata", WEBSITE_METADATA_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {WEBSITE_METADATA_MODULE_PATH}")
        infra_website_metadata = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(infra_website_metadata)
        _website_metadata_handler = infra_website_metadata.run_website_metadata_review
    except Exception as exc:
        _website_metadata_load_error = str(exc)


def _load_virustotal_handler() -> None:
    global _virustotal_handler, _virustotal_load_error, _virustotal_load_attempted

    if _virustotal_load_attempted:
        return

    _virustotal_load_attempted = True

    if not VIRUSTOTAL_MODULE_PATH.is_file():
        _virustotal_load_error = f"Module file not found: {VIRUSTOTAL_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("intel_virustotal", VIRUSTOTAL_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {VIRUSTOTAL_MODULE_PATH}")
        intel_virustotal = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(intel_virustotal)
        _virustotal_handler = intel_virustotal.run_virustotal_lookup
    except Exception as exc:
        _virustotal_load_error = str(exc)


def _nmap_binary_available() -> bool:
    return shutil.which("nmap") is not None


def is_runtime_ready(module_id: str) -> bool:
    """Return True when a module's backend is loaded and ready to run."""
    if module_id == "infra_nmap":
        _load_nmap_handlers()
        return _nmap_handlers is not None and _nmap_binary_available()
    if module_id == "infra_domain_intel":
        _load_domain_intel_handler()
        return _domain_intel_handler is not None
    if module_id == "infra_cert_subdomain":
        _load_cert_subdomain_handler()
        return _cert_subdomain_handler is not None
    if module_id == "infra_website_metadata":
        _load_website_metadata_handler()
        return _website_metadata_handler is not None
    if module_id == "intel_virustotal":
        _load_virustotal_handler()
        return _virustotal_handler is not None
    return False


def get_runtime_error(module_id: str) -> str | None:
    """Return a load-time error message for a module, if any."""
    if module_id == "infra_nmap":
        _load_nmap_handlers()
        if not _nmap_binary_available():
            return (
                "Nmap is not installed or not on your PATH. "
                "Install from https://nmap.org/download.html and restart the app."
            )
        return _nmap_load_error
    if module_id == "infra_domain_intel":
        _load_domain_intel_handler()
        return _domain_intel_load_error
    if module_id == "infra_cert_subdomain":
        _load_cert_subdomain_handler()
        return _cert_subdomain_load_error
    if module_id == "infra_website_metadata":
        _load_website_metadata_handler()
        return _website_metadata_load_error
    if module_id == "intel_virustotal":
        _load_virustotal_handler()
        return _virustotal_load_error
    return None


def _save_recon_output(conn: sqlite3.Connection, target: str, raw_output: str) -> None:
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM targets WHERE domain_or_ip = ?", (target,))
    target_row = cursor.fetchone()
    if target_row:
        cursor.execute(
            "INSERT INTO recon_data (target_id, open_ports) VALUES (?, ?)",
            (target_row[0], raw_output),
        )
        conn.commit()


def _persist_nmap_services_and_relationships(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    source_entity_id: int,
    target: str,
    parsed_ports: list[dict[str, Any]],
    module_id: str,
) -> None:
    """Create service entities and exposes_service relationships from parsed ports."""
    for port_info in parsed_ports:
        service_entity = create_or_get_entity(
            case_id,
            "service",
            build_service_entity_value(target, port_info),
            label=build_service_entity_label(port_info),
            source=module_id,
            confidence=80,
            conn=conn,
        )
        create_relationship(
            case_id,
            source_entity_id,
            "exposes_service",
            service_entity["id"],
            source_module=module_id,
            confidence=80,
            conn=conn,
        )


def _persist_module_findings(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int | None,
    observation_id: int | None,
    module_id: str,
    interpreter_findings: list[dict[str, Any]],
) -> None:
    """Sync structured interpreter findings (close superseded, upsert current)."""
    stored = sync_module_findings(
        conn,
        case_id=case_id,
        entity_id=entity_id,
        observation_id=observation_id,
        module_id=module_id,
        interpreter_findings=interpreter_findings,
    )
    if observation_id and stored:
        link_observation_evidence_to_findings(conn, observation_id, stored)


def _persist_observation_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> None:
    capture_module_evidence(
        conn,
        case_id=case_id,
        entity_id=entity_id,
        observation_id=observation_id,
        module_id=module_id,
        result=result,
    )


def _persist_investigation_records(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int | None,
    module_id: str,
    target: str,
    result: dict[str, Any],
    authorisation_confirmed: bool,
    options: dict[str, Any],
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> None:
    """Save operation and observation records for a completed module run."""
    result = _prepare_module_result(result)
    create_operation_log(
        case_id,
        module_id,
        target,
        result["status"],
        authorisation_confirmed=authorisation_confirmed,
        summary=result["summary"],
        run_mode_id=run_mode_id,
        run_mode_label=run_mode_label,
        conn=conn,
    )

    if entity_id is None or not should_persist_observation(result["status"]):
        return

    parsed_data = result.get("parsed_data") or {}
    parsed_ports = parsed_data.get("parsed_ports", [])

    if parsed_ports:
        _persist_nmap_services_and_relationships(
            conn,
            case_id=case_id,
            source_entity_id=entity_id,
            target=target,
            parsed_ports=parsed_ports,
            module_id=module_id,
        )

    selected_options = result.get("selected_options") or options.get("nmap_options", {})
    observation = create_observation(
        case_id,
        entity_id,
        module_id,
        "network_scan",
        "Nmap scan result",
        summary=result["summary"],
        data_json=json.dumps(
            {
                "module_id": module_id,
                "success": result["success"],
                "status": result["status"],
                "findings_count": len(result["findings"]),
                "findings": result["findings"],
                "nmap_profile": selected_options.get("profile"),
                "selected_options": selected_options,
                "parsed_ports": parsed_data.get("parsed_ports", []),
                "parsed_services": parsed_data.get("parsed_services", []),
                "os_matches": parsed_data.get("os_matches", []),
                "script_results": parsed_data.get("script_results", []),
                "interpreter_findings": result.get("interpreter_findings", []),
                "warnings": result.get("warnings", []),
                "parse_source": parsed_data.get("parse_source"),
            }
        ),
        raw_output=result["raw_output"],
        **_observation_evidence_kwargs(module_id, result),
        conn=conn,
    )

    _persist_observation_evidence(
        conn,
        case_id=case_id,
        entity_id=entity_id,
        observation_id=observation["id"],
        module_id=module_id,
        result=result,
    )

    interpreter_findings = result.get("interpreter_findings") or []
    if interpreter_findings:
        _persist_module_findings(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation["id"],
            module_id=module_id,
            interpreter_findings=interpreter_findings,
        )


def _persist_domain_intel_records(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    domain_entity_id: int,
    module_id: str,
    target: str,
    result: dict[str, Any],
    authorisation_confirmed: bool,
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> None:
    """Save domain intelligence operations, observations, entities, and relationships."""
    result = _prepare_module_result(result)
    create_operation_log(
        case_id,
        module_id,
        target,
        result["status"],
        authorisation_confirmed=authorisation_confirmed,
        summary=result["summary"],
        run_mode_id=run_mode_id,
        run_mode_label=run_mode_label,
        conn=conn,
    )

    if not should_persist_observation(result["status"]):
        return

    parsed_data = result.get("parsed_data") or {}
    dns_records = parsed_data.get("dns", {})

    for ip_address in dns_records.get("A", []) + dns_records.get("AAAA", []):
        ip_entity = create_or_get_entity(
            case_id,
            "ip_address",
            ip_address,
            label=ip_address,
            source=module_id,
            confidence=85,
            conn=conn,
        )
        create_relationship(
            case_id,
            domain_entity_id,
            "resolves_to",
            ip_entity["id"],
            source_module=module_id,
            confidence=85,
            conn=conn,
        )

    for mail_host in dns_records.get("MX", []):
        mail_entity = create_or_get_entity(
            case_id,
            "domain",
            mail_host,
            label=mail_host,
            source=module_id,
            confidence=80,
            conn=conn,
        )
        create_relationship(
            case_id,
            domain_entity_id,
            "uses_mail_server",
            mail_entity["id"],
            source_module=module_id,
            confidence=80,
            conn=conn,
        )

    for nameserver in dns_records.get("NS", []):
        ns_entity = create_or_get_entity(
            case_id,
            "domain",
            nameserver,
            label=nameserver,
            source=module_id,
            confidence=80,
            conn=conn,
        )
        create_relationship(
            case_id,
            domain_entity_id,
            "uses_nameserver",
            ns_entity["id"],
            source_module=module_id,
            confidence=80,
            conn=conn,
        )

    observation = create_observation(
        case_id,
        domain_entity_id,
        module_id,
        "domain_intelligence",
        "Domain intelligence result",
        summary=result["summary"],
        data_json=json.dumps(
            {
                "module_id": module_id,
                "success": result["success"],
                "status": result["status"],
                "findings": result.get("findings", []),
                "interpreter_findings": result.get("interpreter_findings", []),
                "warnings": result.get("warnings", []),
                "domain": parsed_data.get("domain"),
                "input": parsed_data.get("input"),
                "dns": parsed_data.get("dns", {}),
                "http": parsed_data.get("http", {}),
                "security_headers": parsed_data.get("security_headers", {}),
                "tls": parsed_data.get("tls", {}),
                "wayback": parsed_data.get("wayback", {}),
            }
        ),
        raw_output=result["raw_output"],
        **_observation_evidence_kwargs(module_id, result),
        conn=conn,
    )

    _persist_observation_evidence(
        conn,
        case_id=case_id,
        entity_id=domain_entity_id,
        observation_id=observation["id"],
        module_id=module_id,
        result=result,
    )

    interpreter_findings = result.get("interpreter_findings") or []
    if interpreter_findings:
        _persist_module_findings(
            conn,
            case_id=case_id,
            entity_id=domain_entity_id,
            observation_id=observation["id"],
            module_id=module_id,
            interpreter_findings=interpreter_findings,
        )


def _persist_cert_subdomain_records(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    domain_entity_id: int,
    module_id: str,
    target: str,
    result: dict[str, Any],
    authorisation_confirmed: bool,
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> None:
    """Save certificate/subdomain operations, observations, entities, and relationships."""
    result = _prepare_module_result(result)
    create_operation_log(
        case_id,
        module_id,
        target,
        result["status"],
        authorisation_confirmed=authorisation_confirmed,
        summary=result["summary"],
        run_mode_id=run_mode_id,
        run_mode_label=run_mode_label,
        conn=conn,
    )

    if not should_persist_observation(result["status"]):
        return

    parsed_data = result.get("parsed_data") or {}
    domain = parsed_data.get("domain") or target

    for subdomain in parsed_data.get("subdomains", []):
        if subdomain == domain:
            continue
        subdomain_entity = create_or_get_entity(
            case_id,
            "domain",
            subdomain,
            label=subdomain,
            source=module_id,
            confidence=75,
            conn=conn,
        )
        create_relationship(
            case_id,
            domain_entity_id,
            "has_subdomain",
            subdomain_entity["id"],
            source_module=module_id,
            confidence=75,
            conn=conn,
        )

    observation = create_observation(
        case_id,
        domain_entity_id,
        module_id,
        "certificate_subdomain_intelligence",
        "Certificate and subdomain intelligence result",
        summary=result["summary"],
        data_json=json.dumps(
            {
                "module_id": module_id,
                "success": result["success"],
                "status": result["status"],
                "findings": result.get("findings", []),
                "interpreter_findings": result.get("interpreter_findings", []),
                "warnings": result.get("warnings", []),
                "original_target": parsed_data.get("original_target"),
                "domain": domain,
                "subdomains": parsed_data.get("subdomains", []),
                "certificates": parsed_data.get("certificates", []),
                "source": parsed_data.get("source"),
                "warning": parsed_data.get("warning"),
                "wildcard_observed": parsed_data.get("wildcard_observed"),
                "truncated": parsed_data.get("truncated"),
            }
        ),
        raw_output=result["raw_output"],
        **_observation_evidence_kwargs(module_id, result),
        conn=conn,
    )

    _persist_observation_evidence(
        conn,
        case_id=case_id,
        entity_id=domain_entity_id,
        observation_id=observation["id"],
        module_id=module_id,
        result=result,
    )

    interpreter_findings = result.get("interpreter_findings") or []
    if interpreter_findings:
        _persist_module_findings(
            conn,
            case_id=case_id,
            entity_id=domain_entity_id,
            observation_id=observation["id"],
            module_id=module_id,
            interpreter_findings=interpreter_findings,
        )


def _persist_website_metadata_records(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    domain_entity_id: int,
    module_id: str,
    target: str,
    result: dict[str, Any],
    authorisation_confirmed: bool,
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> None:
    """Save website metadata operations, observations, entities, and relationships."""
    result = _prepare_module_result(result)
    create_operation_log(
        case_id,
        module_id,
        target,
        result["status"],
        authorisation_confirmed=authorisation_confirmed,
        summary=result["summary"],
        run_mode_id=run_mode_id,
        run_mode_label=run_mode_label,
        conn=conn,
    )

    if not should_persist_observation(result["status"]):
        return

    parsed_data = result.get("parsed_data") or {}
    domain = parsed_data.get("domain") or target
    homepage = parsed_data.get("homepage") or {}

    canonical_url = homepage.get("canonical_url")
    if canonical_url:
        canonical_entity = create_or_get_entity(
            case_id,
            "url",
            canonical_url,
            label=canonical_url,
            source=module_id,
            confidence=80,
            conn=conn,
        )
        create_relationship(
            case_id,
            domain_entity_id,
            "has_canonical_url",
            canonical_entity["id"],
            source_module=module_id,
            confidence=80,
            conn=conn,
        )

    for entry in (parsed_data.get("sitemap_hints") or {}).get("entries") or []:
        sitemap_url = entry.get("url")
        if not sitemap_url:
            continue
        sitemap_entity = create_or_get_entity(
            case_id,
            "url",
            sitemap_url,
            label=sitemap_url,
            source=module_id,
            confidence=70,
            conn=conn,
        )
        create_relationship(
            case_id,
            domain_entity_id,
            "references_sitemap",
            sitemap_entity["id"],
            source_module=module_id,
            confidence=70,
            conn=conn,
        )

    observation = create_observation(
        case_id,
        domain_entity_id,
        module_id,
        "website_metadata_review",
        "Website metadata review result",
        summary=result["summary"],
        data_json=json.dumps(
            {
                "module_id": module_id,
                "success": result["success"],
                "status": result["status"],
                "findings": result.get("findings", []),
                "interpreter_findings": result.get("interpreter_findings", []),
                "warnings": result.get("warnings", []),
                "original_target": parsed_data.get("original_target"),
                "domain": domain,
                "homepage": homepage,
                "robots_txt": parsed_data.get("robots_txt", {}),
                "sitemap_hints": parsed_data.get("sitemap_hints", {}),
                "warning": parsed_data.get("warning"),
            }
        ),
        raw_output=result["raw_output"],
        **_observation_evidence_kwargs(module_id, result),
        conn=conn,
    )

    _persist_observation_evidence(
        conn,
        case_id=case_id,
        entity_id=domain_entity_id,
        observation_id=observation["id"],
        module_id=module_id,
        result=result,
    )

    interpreter_findings = result.get("interpreter_findings") or []
    if interpreter_findings:
        _persist_module_findings(
            conn,
            case_id=case_id,
            entity_id=domain_entity_id,
            observation_id=observation["id"],
            module_id=module_id,
            interpreter_findings=interpreter_findings,
        )


def _persist_virustotal_records(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    module_id: str,
    target: str,
    result: dict[str, Any],
    authorisation_confirmed: bool,
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> None:
    """Save VirusTotal operations, observations, and findings."""
    result = _prepare_module_result(result)
    create_operation_log(
        case_id,
        module_id,
        target,
        result["status"],
        authorisation_confirmed=authorisation_confirmed,
        summary=result["summary"],
        run_mode_id=run_mode_id,
        run_mode_label=run_mode_label,
        conn=conn,
    )

    if not should_persist_observation(result["status"]):
        return

    parsed_data = result.get("parsed_data") or {}
    observation = create_observation(
        case_id,
        entity_id,
        module_id,
        "threat_intel_lookup",
        "VirusTotal lookup result",
        summary=result["summary"],
        data_json=json.dumps(
            {
                "module_id": module_id,
                "success": result["success"],
                "status": result["status"],
                "findings": result.get("findings", []),
                "interpreter_findings": result.get("interpreter_findings", []),
                "warnings": result.get("warnings", []),
                "target": parsed_data.get("target"),
                "target_type": parsed_data.get("target_type"),
                "last_analysis_stats": parsed_data.get("last_analysis_stats", {}),
                "reputation": parsed_data.get("reputation"),
                "api": parsed_data.get("api", {}),
            }
        ),
        raw_output=result["raw_output"],
        **_observation_evidence_kwargs(module_id, result),
        conn=conn,
    )

    _persist_observation_evidence(
        conn,
        case_id=case_id,
        entity_id=entity_id,
        observation_id=observation["id"],
        module_id=module_id,
        result=result,
    )

    interpreter_findings = result.get("interpreter_findings") or []
    if interpreter_findings:
        _persist_module_findings(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation["id"],
            module_id=module_id,
            interpreter_findings=interpreter_findings,
        )


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


def _build_nmap_summary(target: str, nmap_options: dict[str, Any]) -> str:
    summary = f"Nmap scan completed for {target}."
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
    _load_nmap_handlers()
    if _nmap_handlers is None:
        error_message = _nmap_load_error or "Nmap module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="Nmap module is not available.",
            errors=[error_message],
        )

    run_nmap_scan, _parse_nmap_problems = _nmap_handlers
    nmap_options = normalize_options(options.get("nmap_options", {}))

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

    parsed_data = parse_nmap_results(raw_output, xml_output)
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
            summary=_build_nmap_summary(target, nmap_options),
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
    _load_domain_intel_handler()
    if _domain_intel_handler is None:
        error_message = _domain_intel_load_error or "Domain Intelligence module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="Domain Intelligence module is not available.",
            errors=[error_message],
        )

    intel_data = _domain_intel_handler(target)
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
    _load_cert_subdomain_handler()
    if _cert_subdomain_handler is None:
        error_message = _cert_subdomain_load_error or "Certificate & Subdomain Intelligence module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="Certificate & Subdomain Intelligence module is not available.",
            errors=[error_message],
        )

    intel_data = _cert_subdomain_handler(target)
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
    _load_website_metadata_handler()
    if _website_metadata_handler is None:
        error_message = _website_metadata_load_error or "Website Metadata Review module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="Website Metadata Review module is not available.",
            errors=[error_message],
        )

    intel_data = _website_metadata_handler(target)
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
    if not intel_data.get("success") and intel_data.get("errors"):
        errors = intel_data.get("errors") or ["VirusTotal lookup failed."]
        return make_result(
            module_id,
            success=False,
            status="error",
            summary=errors[0],
            raw_output=intel_data.get("raw_output", ""),
            errors=errors,
            parsed_data=intel_data.get("parsed_data"),
            warnings=intel_data.get("warnings", []),
            evidence=intel_data.get("evidence", []),
        )

    parsed_data = intel_data.get("parsed_data") or {}
    lookup_target = parsed_data.get("target") or target
    interpreter_findings = interpret_module_findings(module_id, parsed_data)
    summary = f"VirusTotal lookup completed for {lookup_target}."
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

    if module.requires_authorisation and not authorisation_confirmed:
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

    if module_id == "infra_nmap":
        if not is_runtime_ready(module_id):
            error_message = get_runtime_error(module_id) or "Nmap runtime is not ready."
            return make_result(
                module_id,
                success=False,
                status="error",
                summary="Nmap module is not available.",
                errors=[error_message],
            )
        return _execute_nmap(
            module_id,
            target,
            options,
            db_context,
            authorisation_confirmed,
            case_id,
            entity_id,
            run_mode_id,
            run_mode_label,
        )

    if module_id == "infra_domain_intel":
        if not is_runtime_ready(module_id):
            error_message = get_runtime_error(module_id) or "Domain Intelligence runtime is not ready."
            return make_result(
                module_id,
                success=False,
                status="error",
                summary="Domain Intelligence module is not available.",
                errors=[error_message],
            )
        return _execute_domain_intel(
            module_id,
            target,
            db_context,
            authorisation_confirmed,
            case_id,
            entity_id,
            run_mode_id,
            run_mode_label,
        )

    if module_id == "infra_cert_subdomain":
        if not is_runtime_ready(module_id):
            error_message = get_runtime_error(module_id) or "Certificate & Subdomain Intelligence runtime is not ready."
            return make_result(
                module_id,
                success=False,
                status="error",
                summary="Certificate & Subdomain Intelligence module is not available.",
                errors=[error_message],
            )
        return _execute_cert_subdomain(
            module_id,
            target,
            db_context,
            authorisation_confirmed,
            case_id,
            entity_id,
            run_mode_id,
            run_mode_label,
        )

    if module_id == "infra_website_metadata":
        if not is_runtime_ready(module_id):
            error_message = get_runtime_error(module_id) or "Website Metadata Review runtime is not ready."
            return make_result(
                module_id,
                success=False,
                status="error",
                summary="Website Metadata Review module is not available.",
                errors=[error_message],
            )
        return _execute_website_metadata(
            module_id,
            target,
            db_context,
            authorisation_confirmed,
            case_id,
            entity_id,
            run_mode_id,
            run_mode_label,
        )

    if module_id == "intel_virustotal":
        if not is_runtime_ready(module_id):
            error_message = get_runtime_error(module_id) or "VirusTotal runtime is not ready."
            return make_result(
                module_id,
                success=False,
                status="error",
                summary="VirusTotal module is not available.",
                errors=[error_message],
            )
        return _execute_virustotal(
            module_id,
            target,
            options,
            db_context,
            authorisation_confirmed,
            case_id,
            entity_id,
            run_mode_id,
            run_mode_label,
        )

    # Additional modules: register an interpreter in utils/findings_registry.py and wire execution here.
    return make_result(
        module_id,
        success=False,
        status="blocked",
        summary=f"{module.display_name} is registered but not wired in the executor yet.",
        errors=["not_wired"],
    )

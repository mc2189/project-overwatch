"""Operation, observation, finding and evidence persistence for module runs."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from database.db_setup import (
    create_observation,
    create_operation_log,
    create_or_get_entity,
    create_relationship,
)
from utils.evidence_capture import capture_module_evidence, link_observation_evidence_to_findings
from utils.findings_sync import sync_module_findings
from utils.nmap_parser import build_service_entity_label, build_service_entity_value
from utils.result_status import should_persist_observation
from utils.target_detection import ENTITY_TYPE_BY_TARGET, get_target_type

from modules.executors.results import _observation_evidence_kwargs, _prepare_module_result

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
                "nmap_profile": selected_options.get("profile_id")
                or (parsed_data.get("scan_profile") or {}).get("profile_id")
                or selected_options.get("profile"),
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


def _persist_email_security_records(
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
    """Save email security operations, observations, entities, and relationships."""
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

    for mx_record in parsed_data.get("mx") or []:
        mail_host = mx_record.get("hostname")
        if not mail_host:
            continue
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

    observation = create_observation(
        case_id,
        domain_entity_id,
        module_id,
        "email_security_posture",
        "Domain email security posture result",
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
                "spf": parsed_data.get("spf", {}),
                "dmarc": parsed_data.get("dmarc", {}),
                "mx": parsed_data.get("mx", []),
                "caa": parsed_data.get("caa", []),
                "mta_sts": parsed_data.get("mta_sts", {}),
                "tls_rpt": parsed_data.get("tls_rpt", {}),
                "bimi": parsed_data.get("bimi", {}),
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


def _persist_tls_review_records(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    host_entity_id: int,
    module_id: str,
    target: str,
    result: dict[str, Any],
    authorisation_confirmed: bool,
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> None:
    """Save TLS review operations, observations, entities, and relationships."""
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
    host = parsed_data.get("host") or target
    port = int(parsed_data.get("port") or 443)
    conn_info = parsed_data.get("connection") or {}
    tls_info = parsed_data.get("tls") or {}
    cert = parsed_data.get("certificate") or {}

    service_value = f"{host}:{port}/tcp"
    service_label = f"{port}/tcp tls"
    if tls_info.get("version"):
        service_label = f"{port}/tcp {tls_info['version']}"

    if conn_info.get("success"):
        service_entity = create_or_get_entity(
            case_id,
            "service",
            service_value,
            label=service_label,
            source=module_id,
            confidence=85,
            conn=conn,
        )
        create_relationship(
            case_id,
            host_entity_id,
            "exposes_tls_service",
            service_entity["id"],
            source_module=module_id,
            confidence=85,
            conn=conn,
        )

        fingerprint = cert.get("fingerprint_sha256")
        cert_subject = cert.get("subject")
        if fingerprint or cert_subject:
            cert_value = fingerprint or f"{host}:{cert_subject}"
            cert_entity = create_or_get_entity(
                case_id,
                "certificate",
                cert_value,
                label=cert_subject or cert_value[:16],
                source=module_id,
                confidence=85,
                conn=conn,
            )
            create_relationship(
                case_id,
                service_entity["id"],
                "presents_certificate",
                cert_entity["id"],
                source_module=module_id,
                confidence=85,
                conn=conn,
            )
            issuer = cert.get("issuer")
            if issuer:
                issuer_entity = create_or_get_entity(
                    case_id,
                    "organisation",
                    issuer.strip().lower(),
                    label=issuer,
                    source=module_id,
                    confidence=75,
                    conn=conn,
                )
                create_relationship(
                    case_id,
                    cert_entity["id"],
                    "issued_by",
                    issuer_entity["id"],
                    source_module=module_id,
                    confidence=75,
                    conn=conn,
                )

    observation = create_observation(
        case_id,
        host_entity_id,
        module_id,
        "tls_configuration_review",
        "TLS configuration review result",
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
                "host": host,
                "port": port,
                "sni": parsed_data.get("sni"),
                "connection": conn_info,
                "tls": {
                    "version": tls_info.get("version"),
                    "cipher": tls_info.get("cipher"),
                    "protocol_probe": tls_info.get("protocol_probe"),
                },
                "certificate": {
                    key: cert.get(key)
                    for key in (
                        "subject",
                        "issuer",
                        "not_before",
                        "not_after",
                        "days_until_expiry",
                        "san_dns_names",
                        "hostname_valid",
                        "chain_valid",
                        "fingerprint_sha256",
                    )
                },
            }
        ),
        raw_output=result["raw_output"],
        **_observation_evidence_kwargs(module_id, result),
        conn=conn,
    )

    _persist_observation_evidence(
        conn,
        case_id=case_id,
        entity_id=host_entity_id,
        observation_id=observation["id"],
        module_id=module_id,
        result=result,
    )

    interpreter_findings = result.get("interpreter_findings") or []
    if interpreter_findings:
        _persist_module_findings(
            conn,
            case_id=case_id,
            entity_id=host_entity_id,
            observation_id=observation["id"],
            module_id=module_id,
            interpreter_findings=interpreter_findings,
        )


def _persist_http_security_records(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    host_entity_id: int,
    module_id: str,
    target: str,
    result: dict[str, Any],
    authorisation_confirmed: bool,
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> None:
    """Save HTTP security review operations, observations, entities, and relationships."""
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
    host = parsed_data.get("host") or target
    scheme = (parsed_data.get("scheme") or "https").lower()
    port = int(parsed_data.get("port") or (443 if scheme == "https" else 80))
    response = parsed_data.get("response") or {}

    if response.get("success"):
        service_value = f"{host}:{port}/{scheme}"
        service_label = f"{port}/{scheme} web"
        service_entity = create_or_get_entity(
            case_id,
            "service",
            service_value,
            label=service_label,
            source=module_id,
            confidence=85,
            conn=conn,
        )
        create_relationship(
            case_id,
            host_entity_id,
            "exposes_web_service",
            service_entity["id"],
            source_module=module_id,
            confidence=85,
            conn=conn,
        )

    observation = create_observation(
        case_id,
        host_entity_id,
        module_id,
        "http_security_header_review",
        "HTTP security header review result",
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
                "host": host,
                "scheme": scheme,
                "port": port,
                "requested_url": parsed_data.get("requested_url"),
                "response": {
                    "success": response.get("success"),
                    "status_code": response.get("status_code"),
                    "final_url": response.get("final_url"),
                    "redirect_chain": response.get("redirect_chain"),
                    "content_type": response.get("content_type"),
                    "content_length": response.get("content_length"),
                    "error": response.get("error"),
                },
                "headers": {
                    "server": (parsed_data.get("headers") or {}).get("server"),
                    "x_powered_by": (parsed_data.get("headers") or {}).get("x_powered_by"),
                    "cache_control": (parsed_data.get("headers") or {}).get("cache_control"),
                },
                "security_headers": parsed_data.get("security_headers"),
                "cookies": parsed_data.get("cookies"),
                "well_known": parsed_data.get("well_known"),
            }
        ),
        raw_output=result["raw_output"],
        **_observation_evidence_kwargs(module_id, result),
        conn=conn,
    )

    _persist_observation_evidence(
        conn,
        case_id=case_id,
        entity_id=host_entity_id,
        observation_id=observation["id"],
        module_id=module_id,
        result=result,
    )

    interpreter_findings = result.get("interpreter_findings") or []
    if interpreter_findings:
        _persist_module_findings(
            conn,
            case_id=case_id,
            entity_id=host_entity_id,
            observation_id=observation["id"],
            module_id=module_id,
            interpreter_findings=interpreter_findings,
        )


def _persist_remote_access_records(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    host_entity_id: int,
    module_id: str,
    target: str,
    result: dict[str, Any],
    authorisation_confirmed: bool,
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> None:
    """Save remote access review operations, observations, entities, and relationships."""
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
    host = parsed_data.get("host") or target
    remote_services = list(parsed_data.get("remote_services") or [])

    for service in remote_services:
        port = service.get("port")
        if port is None:
            continue
        service_for_entity = {
            **service,
            "service": service.get("service_name") or service.get("service"),
            "protocol": service.get("protocol") or "tcp",
        }
        service_entity = create_or_get_entity(
            case_id,
            "service",
            build_service_entity_value(host, service_for_entity),
            label=build_service_entity_label(service_for_entity),
            source=module_id,
            confidence=80,
            conn=conn,
        )
        create_relationship(
            case_id,
            host_entity_id,
            "exposes_service",
            service_entity["id"],
            source_module=module_id,
            confidence=80,
            conn=conn,
        )
        product = service.get("product")
        if product:
            product_entity = create_or_get_entity(
                case_id,
                "software",
                f"{host}:{port}:{product}",
                label=str(product)[:120],
                source=module_id,
                confidence=70,
                conn=conn,
            )
            create_relationship(
                case_id,
                service_entity["id"],
                "identifies_product",
                product_entity["id"],
                source_module=module_id,
                confidence=70,
                conn=conn,
            )

    observation = create_observation(
        case_id,
        host_entity_id,
        module_id,
        "remote_access_review",
        "Remote access exposure review result",
        summary=result["summary"],
        data_json=json.dumps(
            {
                "module_id": module_id,
                "success": result["success"],
                "status": result["status"],
                "target": parsed_data.get("target"),
                "host": host,
                "is_private_target": parsed_data.get("is_private_target"),
                "remote_services": remote_services,
                "remote_service_count": parsed_data.get("remote_service_count"),
                "data_sources": parsed_data.get("data_sources"),
                "limitations": parsed_data.get("limitations"),
                "lan_device_hint": parsed_data.get("lan_device_hint"),
                "interpreter_findings": result.get("interpreter_findings", []),
                "warnings": result.get("warnings", []),
            }
        ),
        raw_output=result["raw_output"],
        **_observation_evidence_kwargs(module_id, result),
        conn=conn,
    )

    _persist_observation_evidence(
        conn,
        case_id=case_id,
        entity_id=host_entity_id,
        observation_id=observation["id"],
        module_id=module_id,
        result=result,
    )

    interpreter_findings = result.get("interpreter_findings") or []
    if interpreter_findings:
        _persist_module_findings(
            conn,
            case_id=case_id,
            entity_id=host_entity_id,
            observation_id=observation["id"],
            module_id=module_id,
            interpreter_findings=interpreter_findings,
        )


def _persist_ssh_review_records(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    host_entity_id: int,
    module_id: str,
    target: str,
    result: dict[str, Any],
    authorisation_confirmed: bool,
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> None:
    """Save SSH review operations, observations, entities, and relationships."""
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
    host = parsed_data.get("host") or target
    port = int(parsed_data.get("port") or 22)
    connection = parsed_data.get("connection") or {}
    banner = parsed_data.get("banner") or {}

    service_for_entity = {
        "port": port,
        "protocol": "tcp",
        "service": "ssh",
        "service_name": "ssh",
        "product": banner.get("software_family") or banner.get("software"),
        "version": banner.get("version"),
    }
    service_entity = create_or_get_entity(
        case_id,
        "service",
        build_service_entity_value(host, service_for_entity),
        label=build_service_entity_label(service_for_entity),
        source=module_id,
        confidence=85 if connection.get("success") else 70,
        conn=conn,
    )
    create_relationship(
        case_id,
        host_entity_id,
        "exposes_service",
        service_entity["id"],
        source_module=module_id,
        confidence=85 if connection.get("success") else 70,
        conn=conn,
    )

    product = banner.get("software_family") or banner.get("software")
    if product:
        product_entity = create_or_get_entity(
            case_id,
            "software",
            f"{host}:{port}:{product}",
            label=str(product)[:120],
            source=module_id,
            confidence=75,
            conn=conn,
        )
        create_relationship(
            case_id,
            service_entity["id"],
            "identifies_product",
            product_entity["id"],
            source_module=module_id,
            confidence=75,
            conn=conn,
        )

    observation = create_observation(
        case_id,
        host_entity_id,
        module_id,
        "ssh_configuration_review",
        "SSH configuration review result",
        summary=result["summary"],
        data_json=json.dumps(
            {
                "module_id": module_id,
                "success": result["success"],
                "status": result["status"],
                "target": parsed_data.get("target"),
                "host": host,
                "port": port,
                "is_private_target": parsed_data.get("is_private_target"),
                "exposure_context": parsed_data.get("exposure_context"),
                "banner": banner,
                "connection": connection,
                "nmap_ssh_service": parsed_data.get("nmap_ssh_service"),
                "optional_metadata": parsed_data.get("optional_metadata"),
                "data_sources": parsed_data.get("data_sources"),
                "limitations": parsed_data.get("limitations"),
                "interpreter_findings": result.get("interpreter_findings", []),
                "warnings": result.get("warnings", []),
            }
        ),
        raw_output=result["raw_output"],
        **_observation_evidence_kwargs(module_id, result),
        conn=conn,
    )

    _persist_observation_evidence(
        conn,
        case_id=case_id,
        entity_id=host_entity_id,
        observation_id=observation["id"],
        module_id=module_id,
        result=result,
    )

    interpreter_findings = result.get("interpreter_findings") or []
    if interpreter_findings:
        _persist_module_findings(
            conn,
            case_id=case_id,
            entity_id=host_entity_id,
            observation_id=observation["id"],
            module_id=module_id,
            interpreter_findings=interpreter_findings,
        )


def _persist_web_stack_records(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    host_entity_id: int,
    module_id: str,
    target: str,
    result: dict[str, Any],
    authorisation_confirmed: bool,
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> None:
    """Save web stack identification operations, observations, entities, and relationships."""
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
    host = parsed_data.get("host") or target
    scheme = (parsed_data.get("scheme") or "https").lower()
    port = int(parsed_data.get("port") or (443 if scheme == "https" else 80))
    response = parsed_data.get("response") or {}
    indicators = list(parsed_data.get("indicators") or [])

    if response.get("success"):
        service_value = f"{host}:{port}/{scheme}"
        service_label = f"{port}/{scheme} web"
        service_entity = create_or_get_entity(
            case_id,
            "service",
            service_value,
            label=service_label,
            source=module_id,
            confidence=85,
            conn=conn,
        )
        create_relationship(
            case_id,
            host_entity_id,
            "exposes_web_service",
            service_entity["id"],
            source_module=module_id,
            confidence=85,
            conn=conn,
        )

    notable_categories = {"cms", "hosting_platform", "javascript_framework", "web_server"}
    for row in indicators:
        if row.get("confidence") == "low" and row.get("category") not in {"cms", "hosting_platform"}:
            continue
        if row.get("category") not in notable_categories and row.get("category") != "cdn_platform":
            continue
        name = row.get("name")
        if not name:
            continue
        software_entity = create_or_get_entity(
            case_id,
            "software",
            f"{host}:{name}",
            label=str(name)[:120],
            source=module_id,
            confidence=75 if row.get("confidence") == "high" else 65,
            conn=conn,
        )
        create_relationship(
            case_id,
            host_entity_id,
            "identifies_product",
            software_entity["id"],
            source_module=module_id,
            confidence=75 if row.get("confidence") == "high" else 65,
            conn=conn,
        )

    observation = create_observation(
        case_id,
        host_entity_id,
        module_id,
        "web_stack_identification",
        "Web stack identification result",
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
                "host": host,
                "scheme": scheme,
                "port": port,
                "requested_url": parsed_data.get("requested_url"),
                "response": {
                    "success": response.get("success"),
                    "status_code": response.get("status_code"),
                    "final_url": response.get("final_url"),
                    "redirect_chain": response.get("redirect_chain"),
                    "content_type": response.get("content_type"),
                    "error": response.get("error"),
                },
                "headers": parsed_data.get("headers"),
                "indicators": indicators,
                "categories": parsed_data.get("categories"),
                "script_sources": parsed_data.get("script_sources"),
                "stylesheet_links": parsed_data.get("stylesheet_links"),
                "meta_generator": parsed_data.get("meta_generator"),
            }
        ),
        raw_output=result["raw_output"],
        **_observation_evidence_kwargs(module_id, result),
        conn=conn,
    )

    _persist_observation_evidence(
        conn,
        case_id=case_id,
        entity_id=host_entity_id,
        observation_id=observation["id"],
        module_id=module_id,
        result=result,
    )

    interpreter_findings = result.get("interpreter_findings") or []
    if interpreter_findings:
        _persist_module_findings(
            conn,
            case_id=case_id,
            entity_id=host_entity_id,
            observation_id=observation["id"],
            module_id=module_id,
            interpreter_findings=interpreter_findings,
        )


def _persist_web_path_records(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    host_entity_id: int,
    module_id: str,
    target: str,
    result: dict[str, Any],
    authorisation_confirmed: bool,
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> None:
    """Save web path review operations, observations, entities, and relationships."""
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
    host = parsed_data.get("host") or target
    scheme = (parsed_data.get("scheme") or "https").lower()
    port = int(parsed_data.get("port") or (443 if scheme == "https" else 80))
    path_results = list(parsed_data.get("path_results") or [])
    service_entity_id: int | None = None

    if parsed_data.get("reachable"):
        service_value = f"{host}:{port}/{scheme}"
        service_label = f"{port}/{scheme} web"
        service_entity = create_or_get_entity(
            case_id,
            "service",
            service_value,
            label=service_label,
            source=module_id,
            confidence=85,
            conn=conn,
        )
        service_entity_id = service_entity["id"]
        create_relationship(
            case_id,
            host_entity_id,
            "exposes_web_service",
            service_entity_id,
            source_module=module_id,
            confidence=85,
            conn=conn,
        )

    for row in path_results:
        if not row.get("notable"):
            continue
        full_url = row.get("full_url")
        if not full_url:
            continue
        path_entity = create_or_get_entity(
            case_id,
            "url",
            full_url,
            label=str(row.get("path") or full_url)[:120],
            source=module_id,
            confidence=75,
            conn=conn,
        )
        if service_entity_id is not None:
            create_relationship(
                case_id,
                service_entity_id,
                "exposes_path",
                path_entity["id"],
                source_module=module_id,
                confidence=75,
                conn=conn,
            )
        else:
            create_relationship(
                case_id,
                host_entity_id,
                "exposes_path",
                path_entity["id"],
                source_module=module_id,
                confidence=75,
                conn=conn,
            )

    observation = create_observation(
        case_id,
        host_entity_id,
        module_id,
        "web_path_review",
        "Controlled web path review result",
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
                "host": host,
                "scheme": scheme,
                "port": port,
                "base_url": parsed_data.get("base_url"),
                "requested_url": parsed_data.get("requested_url"),
                "paths_checked": parsed_data.get("paths_checked"),
                "notable_count": parsed_data.get("notable_count"),
                "notable_categories": parsed_data.get("notable_categories"),
                "path_results": [
                    {
                        key: value
                        for key, value in row.items()
                        if key not in {"body_preview"}
                    }
                    for row in path_results
                ],
            }
        ),
        raw_output=result["raw_output"],
        **_observation_evidence_kwargs(module_id, result),
        conn=conn,
    )

    _persist_observation_evidence(
        conn,
        case_id=case_id,
        entity_id=host_entity_id,
        observation_id=observation["id"],
        module_id=module_id,
        result=result,
    )

    interpreter_findings = result.get("interpreter_findings") or []
    if interpreter_findings:
        _persist_module_findings(
            conn,
            case_id=case_id,
            entity_id=host_entity_id,
            observation_id=observation["id"],
            module_id=module_id,
            interpreter_findings=interpreter_findings,
        )


def _organisation_entity_value(info: dict[str, Any] | None) -> str | None:
    if not info:
        return None
    return info.get("name") or info.get("handle")


def _contact_entity_value(info: dict[str, Any] | None) -> str | None:
    if not info:
        return None
    return info.get("email") or info.get("name") or info.get("handle")


def _persist_whois_rdap_records(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    source_entity_id: int,
    module_id: str,
    target: str,
    result: dict[str, Any],
    authorisation_confirmed: bool,
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
) -> None:
    """Save WHOIS/RDAP operations, observations, entities, relationships, and findings."""
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

    parsed_data = result.get("parsed_data") or result.get("data") or {}
    rdap_summary = parsed_data.get("rdap_summary") or {}
    target_type = parsed_data.get("target_type") or get_target_type(target)

    if target_type in {"domain", "url"}:
        for nameserver in rdap_summary.get("nameservers") or []:
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
                source_entity_id,
                "uses_nameserver",
                ns_entity["id"],
                source_module=module_id,
                confidence=80,
                conn=conn,
            )

        registrar_value = _organisation_entity_value(rdap_summary.get("registrar"))
        if registrar_value:
            registrar_entity = create_or_get_entity(
                case_id,
                "organization",
                registrar_value,
                label=registrar_value,
                source=module_id,
                confidence=75,
                conn=conn,
            )
            create_relationship(
                case_id,
                source_entity_id,
                "registered_with",
                registrar_entity["id"],
                source_module=module_id,
                confidence=75,
                conn=conn,
            )

    if target_type == "ipv4":
        holder_value = _organisation_entity_value(rdap_summary.get("registrant")) or rdap_summary.get("network_name")
        if holder_value:
            holder_entity = create_or_get_entity(
                case_id,
                "organization",
                str(holder_value),
                label=str(holder_value),
                source=module_id,
                confidence=75,
                conn=conn,
            )
            create_relationship(
                case_id,
                source_entity_id,
                "allocated_to",
                holder_entity["id"],
                source_module=module_id,
                confidence=75,
                conn=conn,
            )

    abuse_value = _contact_entity_value(rdap_summary.get("abuse_contact"))
    if abuse_value:
        abuse_entity = create_or_get_entity(
            case_id,
            "contact",
            abuse_value,
            label=abuse_value,
            source=module_id,
            confidence=70,
            conn=conn,
        )
        create_relationship(
            case_id,
            source_entity_id,
            "has_abuse_contact",
            abuse_entity["id"],
            source_module=module_id,
            confidence=70,
            conn=conn,
        )

    observation = create_observation(
        case_id,
        source_entity_id,
        module_id,
        "whois_rdap_lookup",
        "WHOIS/RDAP intelligence result",
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
                "query_value": parsed_data.get("query_value"),
                "target_type": parsed_data.get("target_type"),
                "domain_or_ip": parsed_data.get("domain_or_ip"),
                "lookup_status": parsed_data.get("lookup_status"),
                "private_local_ip": parsed_data.get("private_local_ip"),
                "rdap_summary": rdap_summary,
                "source": parsed_data.get("source"),
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
        entity_id=source_entity_id,
        observation_id=observation["id"],
        module_id=module_id,
        result=result,
    )

    interpreter_findings = result.get("interpreter_findings") or []
    if interpreter_findings:
        _persist_module_findings(
            conn,
            case_id=case_id,
            entity_id=source_entity_id,
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

    _persist_virustotal_entities(
        conn,
        case_id=case_id,
        source_entity_id=entity_id,
        module_id=module_id,
        parsed_data=parsed_data,
    )


def _persist_virustotal_entities(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    source_entity_id: int,
    module_id: str,
    parsed_data: dict[str, Any],
) -> None:
    """Create organisation/ASN entities and relationships from VirusTotal metadata."""
    if parsed_data.get("private_local_ip"):
        return

    target_type = parsed_data.get("target_type")
    if target_type == "ipv4":
        org_value = parsed_data.get("as_owner") or parsed_data.get("network")
        if org_value:
            org_entity = create_or_get_entity(
                case_id,
                "organization",
                str(org_value),
                label=str(org_value),
                source=module_id,
                confidence=70,
                conn=conn,
            )
            create_relationship(
                case_id,
                source_entity_id,
                "associated_with",
                org_entity["id"],
                source_module=module_id,
                confidence=70,
                conn=conn,
            )
        asn = parsed_data.get("asn")
        if asn not in (None, ""):
            asn_label = f"AS{asn}"
            asn_entity = create_or_get_entity(
                case_id,
                "asn",
                asn_label,
                label=asn_label,
                source=module_id,
                confidence=70,
                conn=conn,
            )
            create_relationship(
                case_id,
                source_entity_id,
                "associated_with",
                asn_entity["id"],
                source_module=module_id,
                confidence=70,
                conn=conn,
            )

    if target_type in {"domain", "url"}:
        registrar = parsed_data.get("registrar")
        if registrar:
            registrar_entity = create_or_get_entity(
                case_id,
                "organization",
                str(registrar),
                label=str(registrar),
                source=module_id,
                confidence=70,
                conn=conn,
            )
            create_relationship(
                case_id,
                source_entity_id,
                "associated_with",
                registrar_entity["id"],
                source_module=module_id,
                confidence=70,
                conn=conn,
            )


def _persist_abuseipdb_records(
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
    """Save AbuseIPDB operations, observations, and findings."""
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
        "AbuseIPDB lookup result",
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
                "ip_address": parsed_data.get("ip_address"),
                "abuse_confidence_score": parsed_data.get("abuse_confidence_score"),
                "total_reports": parsed_data.get("total_reports"),
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

    _persist_abuseipdb_entities(
        conn,
        case_id=case_id,
        source_entity_id=entity_id,
        module_id=module_id,
        parsed_data=parsed_data,
    )


def _persist_abuseipdb_entities(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    source_entity_id: int,
    module_id: str,
    parsed_data: dict[str, Any],
) -> None:
    """Create organisation entity and relationship from AbuseIPDB ISP metadata."""
    if parsed_data.get("private_local_ip"):
        return

    isp = parsed_data.get("isp")
    if isp:
        org_entity = create_or_get_entity(
            case_id,
            "organization",
            str(isp),
            label=str(isp),
            source=module_id,
            confidence=70,
            conn=conn,
        )
        create_relationship(
            case_id,
            source_entity_id,
            "associated_with",
            org_entity["id"],
            source_module=module_id,
            confidence=70,
            conn=conn,
        )


def _persist_greynoise_records(
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
    """Save GreyNoise operations, observations, and findings."""
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
        "GreyNoise lookup result",
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
                "ip_address": parsed_data.get("ip_address"),
                "noise": parsed_data.get("noise"),
                "riot": parsed_data.get("riot"),
                "classification": parsed_data.get("classification"),
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

    _persist_greynoise_entities(
        conn,
        case_id=case_id,
        source_entity_id=entity_id,
        module_id=module_id,
        parsed_data=parsed_data,
    )


def _persist_greynoise_entities(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    source_entity_id: int,
    module_id: str,
    parsed_data: dict[str, Any],
) -> None:
    """Create organisation entity from GreyNoise provider/actor name when useful."""
    if parsed_data.get("private_local_ip"):
        return

    name = parsed_data.get("name")
    if not name or str(name).strip().lower() in {"", "unknown", "n/a"}:
        return

    org_entity = create_or_get_entity(
        case_id,
        "organization",
        str(name),
        label=str(name),
        source=module_id,
        confidence=70,
        conn=conn,
    )
    create_relationship(
        case_id,
        source_entity_id,
        "associated_with",
        org_entity["id"],
        source_module=module_id,
        confidence=70,
        conn=conn,
    )


def _persist_shodan_records(
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
    """Save Shodan operations, observations, and findings."""
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
        "Shodan lookup result",
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
                "ip_address": parsed_data.get("ip_address"),
                "service_count": parsed_data.get("service_count"),
                "ports": parsed_data.get("ports"),
                "organisation": parsed_data.get("organisation"),
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

    _persist_shodan_entities(
        conn,
        case_id=case_id,
        source_entity_id=entity_id,
        module_id=module_id,
        target=target,
        parsed_data=parsed_data,
    )


def _persist_shodan_entities(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    source_entity_id: int,
    module_id: str,
    target: str,
    parsed_data: dict[str, Any],
) -> None:
    """Create service, organisation, ASN, and hostname entities from Shodan metadata."""
    if parsed_data.get("private_local_ip"):
        return

    org_value = parsed_data.get("organisation") or parsed_data.get("isp")
    if org_value:
        org_entity = create_or_get_entity(
            case_id,
            "organization",
            str(org_value),
            label=str(org_value),
            source=module_id,
            confidence=70,
            conn=conn,
        )
        create_relationship(
            case_id,
            source_entity_id,
            "associated_with",
            org_entity["id"],
            source_module=module_id,
            confidence=70,
            conn=conn,
        )

    asn = parsed_data.get("asn")
    if asn not in (None, ""):
        asn_label = str(asn) if str(asn).upper().startswith("AS") else f"AS{asn}"
        asn_entity = create_or_get_entity(
            case_id,
            "asn",
            asn_label,
            label=asn_label,
            source=module_id,
            confidence=70,
            conn=conn,
        )
        create_relationship(
            case_id,
            source_entity_id,
            "associated_with",
            asn_entity["id"],
            source_module=module_id,
            confidence=70,
            conn=conn,
        )

    for hostname in (parsed_data.get("hostnames") or [])[:10]:
        hostname_text = str(hostname).strip()
        if not hostname_text:
            continue
        host_entity = create_or_get_entity(
            case_id,
            "domain",
            hostname_text,
            label=hostname_text,
            source=module_id,
            confidence=70,
            conn=conn,
        )
        create_relationship(
            case_id,
            source_entity_id,
            "has_hostname",
            host_entity["id"],
            source_module=module_id,
            confidence=70,
            conn=conn,
        )

    services = parsed_data.get("services") or []
    for service in services[:25]:
        port = service.get("port")
        if port is None:
            continue
        protocol = str(service.get("transport") or "tcp").lower()
        port_info = {
            "port": port,
            "protocol": protocol,
            "service": service.get("module") or service.get("product") or "",
            "version": service.get("version") or "",
        }
        service_entity = create_or_get_entity(
            case_id,
            "service",
            build_service_entity_value(target, port_info),
            label=build_service_entity_label(port_info),
            source=module_id,
            confidence=65,
            conn=conn,
        )
        create_relationship(
            case_id,
            source_entity_id,
            "reported_exposes_service",
            service_entity["id"],
            source_module=module_id,
            confidence=65,
            conn=conn,
        )


def _urlhaus_host_entity_type(host: str) -> str:
    return "ip_address" if get_target_type(host) == "ipv4" else "domain"


def _persist_urlhaus_records(
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
    """Save URLhaus operations, observations, and findings."""
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
        "URLhaus lookup result",
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
                "lookup_type": parsed_data.get("lookup_type"),
                "lookup_value": parsed_data.get("lookup_value"),
                "query_status": parsed_data.get("query_status"),
                "url_count": parsed_data.get("url_count"),
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

    _persist_urlhaus_entities(
        conn,
        case_id=case_id,
        source_entity_id=entity_id,
        module_id=module_id,
        parsed_data=parsed_data,
    )


def _persist_urlhaus_entities(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    source_entity_id: int,
    module_id: str,
    parsed_data: dict[str, Any],
) -> None:
    """Create URL/host entities and relationships from URLhaus metadata."""
    if parsed_data.get("private_local_ip"):
        return

    urlhaus_entity = create_or_get_entity(
        case_id,
        "organization",
        "URLhaus (abuse.ch)",
        label="URLhaus (abuse.ch)",
        source=module_id,
        confidence=70,
        conn=conn,
    )

    lookup_type = parsed_data.get("lookup_type")
    if lookup_type == "url":
        url_value = parsed_data.get("lookup_value") or parsed_data.get("target")
        if url_value:
            url_entity = create_or_get_entity(
                case_id,
                "url",
                str(url_value),
                label=str(url_value),
                source=module_id,
                confidence=75,
                conn=conn,
            )
            create_relationship(
                case_id,
                url_entity["id"],
                "reported_by",
                urlhaus_entity["id"],
                source_module=module_id,
                confidence=75,
                conn=conn,
            )
            host_value = parsed_data.get("host")
            if host_value:
                host_entity = create_or_get_entity(
                    case_id,
                    _urlhaus_host_entity_type(str(host_value)),
                    str(host_value),
                    label=str(host_value),
                    source=module_id,
                    confidence=75,
                    conn=conn,
                )
                create_relationship(
                    case_id,
                    url_entity["id"],
                    "hosted_on",
                    host_entity["id"],
                    source_module=module_id,
                    confidence=75,
                    conn=conn,
                )
            for signature in (parsed_data.get("signatures") or parsed_data.get("tags") or [])[:5]:
                if not signature:
                    continue
                sig_entity = create_or_get_entity(
                    case_id,
                    "malware_signature",
                    str(signature),
                    label=str(signature),
                    source=module_id,
                    confidence=65,
                    conn=conn,
                )
                create_relationship(
                    case_id,
                    url_entity["id"],
                    "associated_with",
                    sig_entity["id"],
                    source_module=module_id,
                    confidence=65,
                    conn=conn,
                )
        return

    host_value = parsed_data.get("host") or parsed_data.get("lookup_value") or parsed_data.get("target")
    if not host_value:
        return
    host_entity = create_or_get_entity(
        case_id,
        _urlhaus_host_entity_type(str(host_value)),
        str(host_value),
        label=str(host_value),
        source=module_id,
        confidence=75,
        conn=conn,
    )
    create_relationship(
        case_id,
        host_entity["id"],
        "reported_by",
        urlhaus_entity["id"],
        source_module=module_id,
        confidence=70,
        conn=conn,
    )

    for item in (parsed_data.get("sampled_urls") or [])[:50]:
        if not isinstance(item, dict):
            continue
        url_text = item.get("url")
        if not url_text:
            continue
        url_entity = create_or_get_entity(
            case_id,
            "url",
            str(url_text),
            label=str(url_text),
            source=module_id,
            confidence=65,
            conn=conn,
        )
        create_relationship(
            case_id,
            host_entity["id"],
            "has_reported_url",
            url_entity["id"],
            source_module=module_id,
            confidence=65,
            conn=conn,
        )


def _persist_pcap_records(
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
    """Save PCAP review operations, observations, findings, and entities."""
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
        "packet_capture_review",
        "PCAP evidence review",
        summary=result["summary"],
        data_json=json.dumps(
            {
                "module_id": module_id,
                "success": result["success"],
                "status": result["status"],
                "filename": parsed_data.get("filename"),
                "sha256": parsed_data.get("sha256"),
                "file_size_bytes": parsed_data.get("file_size_bytes"),
                "packet_count": parsed_data.get("packet_count"),
                "packets_analysed": parsed_data.get("packets_analysed"),
                "duration_seconds": parsed_data.get("duration_seconds"),
                "protocols": parsed_data.get("protocols"),
                "parser_available": parsed_data.get("parser_available"),
                "analysis_capped": parsed_data.get("analysis_capped"),
                "interpreter_findings": result.get("interpreter_findings", []),
                "warnings": result.get("warnings", []),
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

    _persist_pcap_entities(
        conn,
        case_id=case_id,
        file_entity_id=entity_id,
        module_id=module_id,
        parsed_data=parsed_data,
    )


def _persist_file_metadata_records(
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
    """Save file metadata review operations, observations, entities, and relationships."""
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
    files = list(parsed_data.get("files") or [])

    for row in files:
        sha256 = row.get("sha256") or "unknown"
        filename = row.get("filename") or "file"
        file_entity = create_or_get_entity(
            case_id,
            "artefact",
            f"{sha256}:{filename}",
            label=filename[:120],
            source=module_id,
            confidence=90,
            conn=conn,
        )
        create_relationship(
            case_id,
            entity_id,
            "identifies_file",
            file_entity["id"],
            source_module=module_id,
            confidence=90,
            conn=conn,
        )
        document = row.get("document") or {}
        producer = document.get("producer") or document.get("application")
        if producer and row.get("notable"):
            software_entity = create_or_get_entity(
                case_id,
                "software",
                str(producer)[:120],
                label=str(producer)[:120],
                source=module_id,
                confidence=70,
                conn=conn,
            )
            create_relationship(
                case_id,
                file_entity["id"],
                "identifies_product",
                software_entity["id"],
                source_module=module_id,
                confidence=70,
                conn=conn,
            )

    safe_files = [
        {
            key: value
            for key, value in row.items()
            if key not in {"gps_details", "raw_metadata"}
        }
        for row in files
    ]
    observation = create_observation(
        case_id,
        entity_id,
        module_id,
        "file_metadata_review",
        "Document and image metadata review",
        summary=result["summary"],
        data_json=json.dumps(
            {
                "module_id": module_id,
                "success": result["success"],
                "status": result["status"],
                "file_count": parsed_data.get("file_count"),
                "notable_count": parsed_data.get("notable_count"),
                "privacy_notes": parsed_data.get("privacy_notes"),
                "files": safe_files,
                "interpreter_findings": result.get("interpreter_findings", []),
                "warnings": result.get("warnings", []),
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


def _persist_pcap_entities(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    file_entity_id: int,
    module_id: str,
    parsed_data: dict[str, Any],
) -> None:
    """Create IP/domain/service entities from bounded PCAP previews."""
    preview = parsed_data.get("entities_preview") or {}
    ip_ids: dict[str, int] = {}

    for ip_value in preview.get("ips") or []:
        ip_text = str(ip_value).strip()
        if not ip_text:
            continue
        entity = create_or_get_entity(
            case_id,
            "ip_address",
            ip_text,
            label=ip_text,
            source=module_id,
            confidence=70,
            conn=conn,
        )
        ip_ids[ip_text] = entity["id"]

    for domain_value in preview.get("domains") or []:
        domain_text = str(domain_value).strip().lower().rstrip(".")
        if not domain_text:
            continue
        domain_entity = create_or_get_entity(
            case_id,
            "domain",
            domain_text,
            label=domain_text,
            source=module_id,
            confidence=65,
            conn=conn,
        )
        src_ip = None
        for dns in parsed_data.get("dns_queries") or []:
            if dns.get("query") == domain_text:
                for candidate in preview.get("ips") or []:
                    src_ip = str(candidate)
                    break
                break
        if src_ip and src_ip in ip_ids:
            create_relationship(
                case_id,
                ip_ids[src_ip],
                "queried_domain",
                domain_entity["id"],
                source_module=module_id,
                confidence=60,
                conn=conn,
            )

    for service_value in preview.get("services") or []:
        service_text = str(service_value).strip()
        if not service_text:
            continue
        service_entity = create_or_get_entity(
            case_id,
            "service",
            service_text,
            label=service_text,
            source=module_id,
            confidence=60,
            conn=conn,
        )
        host_part = service_text.split(":", 1)[0]
        if host_part in ip_ids:
            create_relationship(
                case_id,
                ip_ids[host_part],
                "connected_to_service",
                service_entity["id"],
                source_module=module_id,
                confidence=60,
                conn=conn,
            )

    conversations = parsed_data.get("top_conversations") or []
    for item in conversations[:15]:
        conv = str(item.get("conversation") or "")
        if "->" not in conv:
            continue
        left, _right = conv.split("->", 1)
        src = left.split(":", 1)[0].strip()
        dst = _right.split(":", 1)[0].strip()
        if src in ip_ids and dst in ip_ids and src != dst:
            create_relationship(
                case_id,
                ip_ids[src],
                "communicated_with",
                ip_ids[dst],
                source_module=module_id,
                confidence=55,
                conn=conn,
            )


def _persist_live_capture_records(
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
    """Save live capture operations, observations, findings, and PCAP-derived entities."""
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
    capture = parsed_data.get("capture") or {}
    pcap_review = parsed_data.get("pcap_review") or {}
    pcap_parsed = pcap_review.get("parsed_data") or {}

    observation = create_observation(
        case_id,
        entity_id,
        module_id,
        "live_packet_capture",
        "Personal Lab packet capture",
        summary=result["summary"],
        data_json=json.dumps(
            {
                "module_id": module_id,
                "success": result["success"],
                "status": result["status"],
                "capture": {
                    "backend": capture.get("backend"),
                    "interface": capture.get("interface"),
                    "duration_seconds": capture.get("duration_seconds"),
                    "packet_cap": capture.get("packet_cap"),
                    "filter_preset": capture.get("filter_preset"),
                    "filename": capture.get("filename"),
                    "sha256": capture.get("sha256"),
                    "file_size_bytes": capture.get("file_size_bytes"),
                },
                "pcap_review_summary": pcap_review.get("summary"),
                "packets_analysed": pcap_parsed.get("packets_analysed"),
                "protocols": pcap_parsed.get("protocols"),
                "triage_narrative": (parsed_data.get("triage") or {}).get("narrative_text"),
                "network_picture": ((parsed_data.get("triage") or {}).get("network_picture") or {}).get("one_liner"),
                "investigate_entities": [
                    item.get("value")
                    for item in ((parsed_data.get("triage") or {}).get("ranked_entities") or [])
                    if item.get("tier") == "investigate"
                ][:10],
                "interpreter_findings": result.get("interpreter_findings", []),
                "warnings": result.get("warnings", []),
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

    if pcap_parsed:
        _persist_pcap_entities(
            conn,
            case_id=case_id,
            file_entity_id=entity_id,
            module_id=module_id,
            parsed_data=pcap_parsed,
        )


"""Capture module run artefacts into the Evidence Locker."""

from __future__ import annotations

import base64
import json
import sqlite3
from typing import Any

from database.db_setup import create_evidence_item, link_evidence_to_finding, list_evidence_items
from utils.evidence_model import (
    EVIDENCE_DIRECT_OBSERVATION,
    EVIDENCE_SYSTEM_GENERATED,
    EVIDENCE_THIRD_PARTY_SOURCE,
    EVIDENCE_UNAVAILABLE_SOURCE,
    RELIABILITY_HIGH,
    RELIABILITY_MEDIUM,
    RELIABILITY_UNKNOWN,
    observation_evidence_for_module,
)

# Large artefacts spill to database/evidence_files/ when content exceeds EVIDENCE_INLINE_MAX_BYTES.


def _decode_hint_bytes(value: Any) -> bytes | None:
    if value is None:
        return None
    if isinstance(value, bytes):
        return value
    if isinstance(value, str):
        try:
            return base64.b64decode(value, validate=True)
        except Exception:
            return value.encode("utf-8")
    return None


def _text_summary(data: Any, *, max_len: int = 8000) -> str:
    if data is None:
        return ""
    if isinstance(data, str):
        text = data
    else:
        text = json.dumps(data, indent=2, default=str)
    if len(text) > max_len:
        return text[:max_len] + "\n... [truncated for evidence locker storage]"
    return text


def _create_item(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    title: str,
    summary: str,
    content_text: str | None = None,
    content_bytes: bytes | None = None,
    content_type: str = "text/plain",
    evidence_type: str | None = None,
    source_name: str | None = None,
    source_url: str | None = None,
    collection_method: str | None = None,
    reliability: str | None = None,
    confidence: int | None = None,
) -> dict[str, Any]:
    defaults = observation_evidence_for_module(module_id, None)
    return create_evidence_item(
        case_id,
        module_id,
        title,
        summary=summary,
        content_text=content_text,
        content_bytes=content_bytes,
        entity_id=entity_id,
        observation_id=observation_id,
        evidence_type=evidence_type or defaults.get("evidence_type"),
        source_name=source_name or defaults.get("source_name"),
        source_url=source_url or defaults.get("source_url"),
        collection_method=collection_method or defaults.get("collection_method"),
        reliability=reliability or defaults.get("reliability"),
        confidence=confidence,
        content_type=content_type,
        conn=conn,
    )


def capture_result_evidence_hints(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    """Create evidence locker items from result['evidence'] SDK hints."""
    items: list[dict[str, Any]] = []
    defaults = observation_evidence_for_module(module_id, result)

    for hint in result.get("evidence") or []:
        if not isinstance(hint, dict):
            continue
        title = str(hint.get("title") or "Module evidence artefact").strip()
        if not title:
            continue
        content_text = hint.get("content_text")
        if content_text is None and hint.get("content") is not None:
            content = hint.get("content")
            content_text = content if isinstance(content, str) else _text_summary(content)
        content_bytes = _decode_hint_bytes(hint.get("content_bytes"))
        if not content_text and not content_bytes:
            continue

        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title=title,
                summary=str(hint.get("summary") or "Evidence artefact declared by module result contract."),
                content_text=str(content_text) if content_text else None,
                content_bytes=content_bytes,
                content_type=str(hint.get("content_type") or "text/plain"),
                evidence_type=hint.get("evidence_type") or defaults.get("evidence_type"),
                source_name=hint.get("source_name") or defaults.get("source_name"),
                source_url=hint.get("source_url") or defaults.get("source_url"),
                collection_method=hint.get("collection_method") or defaults.get("collection_method"),
                reliability=hint.get("reliability") or defaults.get("reliability"),
                confidence=hint.get("confidence"),
            )
        )
    return items


def capture_nmap_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    parsed_data = result.get("parsed_data") or {}
    raw_output = result.get("raw_output") or ""

    if raw_output.strip():
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Nmap raw text output",
                summary="Directly observed during local Nmap execution.",
                content_text=raw_output,
                content_type="text/plain",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="local_nmap",
                collection_method="local_command",
                reliability=RELIABILITY_HIGH,
            )
        )

    xml_output = parsed_data.get("xml_output") or ""
    if xml_output.strip():
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Nmap XML output",
                summary="Structured Nmap XML captured from the local scan.",
                content_text=xml_output,
                content_type="application/xml",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="local_nmap",
                collection_method="local_command",
                reliability=RELIABILITY_HIGH,
            )
        )

    structured = {
        "parsed_ports": parsed_data.get("parsed_ports", []),
        "parsed_services": parsed_data.get("parsed_services", []),
        "os_matches": parsed_data.get("os_matches", []),
        "script_results": parsed_data.get("script_results", []),
        "parse_source": parsed_data.get("parse_source"),
    }
    if any(structured.values()):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Nmap parsed scan data",
                summary="Structured port and service data parsed from Nmap output.",
                content_text=_text_summary(structured),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="local_nmap",
                collection_method="parser_inferred",
                reliability=RELIABILITY_HIGH,
            )
        )
    return items


def capture_domain_intel_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    parsed_data = result.get("parsed_data") or {}
    dns = parsed_data.get("dns") or {}
    http = parsed_data.get("http") or {}
    tls = parsed_data.get("tls") or {}
    security_headers = parsed_data.get("security_headers") or {}
    wayback = parsed_data.get("wayback") or {}

    if dns:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="DNS lookup summary",
                summary="Passive DNS record answers collected during domain intelligence.",
                content_text=_text_summary(dns),
                content_type="application/json",
                evidence_type=EVIDENCE_THIRD_PARTY_SOURCE,
                source_name="dns_lookup",
                collection_method="passive_lookup",
                reliability=RELIABILITY_HIGH,
            )
        )

    if http or tls or security_headers:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="HTTP/TLS response summary",
                summary="Direct HTTP/TLS checks performed against the target host.",
                content_text=_text_summary(
                    {"http": http, "tls": tls, "security_headers": security_headers}
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="http_response",
                collection_method="http_request",
                reliability=RELIABILITY_HIGH,
            )
        )

    if wayback:
        wayback_reliability = RELIABILITY_MEDIUM
        evidence_type = EVIDENCE_THIRD_PARTY_SOURCE
        if wayback.get("error"):
            wayback_reliability = RELIABILITY_UNKNOWN
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Wayback lookup summary",
                summary="Internet Archive / Wayback lookup result or limitation.",
                content_text=_text_summary(wayback),
                content_type="application/json",
                evidence_type=evidence_type,
                source_name="wayback",
                source_url="https://web.archive.org/",
                collection_method="passive_lookup",
                reliability=wayback_reliability,
            )
        )

    raw_output = result.get("raw_output") or ""
    if raw_output.strip() and not items:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Domain intelligence raw output",
                summary="Module raw output summary.",
                content_text=raw_output,
                content_type="text/plain",
                evidence_type=EVIDENCE_THIRD_PARTY_SOURCE,
                source_name="dns_and_public_lookups",
                collection_method="passive_lookup",
                reliability=RELIABILITY_MEDIUM,
            )
        )
    return items


def capture_cert_subdomain_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    parsed_data = result.get("parsed_data") or {}
    warning = parsed_data.get("warning") or ""
    raw_output = result.get("raw_output") or ""
    status = result.get("status", "")

    unavailable = bool(warning) or status in {"partial", "error"} or not parsed_data.get("subdomains")
    evidence_type = EVIDENCE_UNAVAILABLE_SOURCE if warning else EVIDENCE_THIRD_PARTY_SOURCE
    reliability = RELIABILITY_UNKNOWN if warning else RELIABILITY_MEDIUM

    payload = {
        "domain": parsed_data.get("domain"),
        "subdomains": parsed_data.get("subdomains", []),
        "certificates": parsed_data.get("certificates", []),
        "source": parsed_data.get("source") or "crt.sh",
        "warning": warning or None,
        "wildcard_observed": parsed_data.get("wildcard_observed"),
        "truncated": parsed_data.get("truncated"),
    }
    content = _text_summary(payload) if any(payload.values()) else raw_output
    summary = (
        "Certificate transparency lookup was unavailable or incomplete during this run."
        if warning
        else "Observed via certificate transparency data (names are leads, not confirmed live hosts)."
    )

    item = _create_item(
        conn,
        case_id=case_id,
        entity_id=entity_id,
        observation_id=observation_id,
        module_id=module_id,
        title="Certificate transparency lookup",
        summary=summary,
        content_text=content or warning or "No certificate transparency data captured.",
        content_type="application/json" if payload.get("subdomains") else "text/plain",
        evidence_type=evidence_type if warning else EVIDENCE_THIRD_PARTY_SOURCE,
        source_name="crt.sh",
        source_url="https://crt.sh/",
        collection_method="certificate_transparency",
        reliability=reliability if not unavailable or warning else RELIABILITY_UNKNOWN,
    )
    return [item]


def capture_website_metadata_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    parsed_data = result.get("parsed_data") or {}
    homepage = parsed_data.get("homepage") or {}
    robots_txt = parsed_data.get("robots_txt") or {}
    sitemap_hints = parsed_data.get("sitemap_hints") or {}

    homepage_reliability = RELIABILITY_HIGH if homepage.get("reachable") else RELIABILITY_UNKNOWN
    if homepage:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Homepage metadata",
                summary="Direct HTTP response metadata from the target homepage.",
                content_text=_text_summary(homepage),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="http_response",
                collection_method="http_request",
                reliability=homepage_reliability,
            )
        )

    robots_reliability = RELIABILITY_HIGH if robots_txt.get("available") else RELIABILITY_UNKNOWN
    if robots_txt:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="robots.txt summary",
                summary="Direct fetch of robots.txt or unavailable notice.",
                content_text=_text_summary(robots_txt),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="http_response",
                collection_method="http_request",
                reliability=robots_reliability,
            )
        )

    sitemap_reliability = (
        RELIABILITY_MEDIUM if (sitemap_hints.get("reachable_count") or 0) > 0 else RELIABILITY_UNKNOWN
    )
    if sitemap_hints:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Sitemap hints summary",
                summary="Sitemap discovery results from robots.txt references and common paths.",
                content_text=_text_summary(sitemap_hints),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="http_response",
                collection_method="http_request",
                reliability=sitemap_reliability,
            )
        )
    return items


def capture_http_security_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    parsed_data = result.get("parsed_data") or {}
    response = parsed_data.get("response") or {}
    headers = parsed_data.get("headers") or {}
    security = parsed_data.get("security_headers") or {}
    cookies = parsed_data.get("cookies") or []
    well_known = parsed_data.get("well_known") or {}

    items.append(
        _create_item(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            title="HTTP response summary",
            summary="Controlled HTTP security header review response summary.",
            content_text=_text_summary(
                {
                    "requested_url": parsed_data.get("requested_url"),
                    "final_url": response.get("final_url"),
                    "status_code": response.get("status_code"),
                    "redirect_chain": response.get("redirect_chain"),
                    "content_type": response.get("content_type"),
                    "content_length": response.get("content_length"),
                    "error": response.get("error"),
                }
            ),
            content_type="application/json",
            evidence_type=EVIDENCE_DIRECT_OBSERVATION,
            source_name="http_response",
            collection_method="controlled_http_header_review",
            reliability=RELIABILITY_HIGH if response.get("success") else RELIABILITY_MEDIUM,
        )
    )

    items.append(
        _create_item(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            title="Security header summary",
            summary="Security header presence summary from authorised HTTP review.",
            content_text=_text_summary(
                {
                    "security_headers": security,
                    "server": headers.get("server"),
                    "x_powered_by": headers.get("x_powered_by"),
                    "cache_control": headers.get("cache_control"),
                }
            ),
            content_type="application/json",
            evidence_type=EVIDENCE_DIRECT_OBSERVATION,
            source_name="http_response",
            collection_method="controlled_http_header_review",
            reliability=RELIABILITY_HIGH if response.get("success") else RELIABILITY_MEDIUM,
        )
    )

    if cookies:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Cookie flag summary",
                summary="Observed cookie names and flags only — values not stored.",
                content_text=_text_summary({"cookies": cookies}),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="http_response",
                collection_method="controlled_http_header_review",
                reliability=RELIABILITY_HIGH,
            )
        )

    if well_known:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Well-known file check summary",
                summary="security.txt and robots.txt check summary.",
                content_text=_text_summary(well_known),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="http_response",
                collection_method="controlled_http_header_review",
                reliability=RELIABILITY_MEDIUM,
            )
        )

    return items


def capture_tls_review_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    parsed_data = result.get("parsed_data") or {}
    host = parsed_data.get("host") or "target"
    port = parsed_data.get("port") or 443
    conn_info = parsed_data.get("connection") or {}
    tls_info = parsed_data.get("tls") or {}
    cert = parsed_data.get("certificate") or {}

    if parsed_data.get("scope_blocked"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="TLS review scope block",
                summary=parsed_data.get("scope_blocked_reason") or "TLS review blocked by scope/ROE.",
                content_text=_text_summary(
                    {
                        "scope_blocked": True,
                        "reason": parsed_data.get("scope_blocked_reason"),
                        "target": parsed_data.get("target"),
                    }
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_SYSTEM_GENERATED,
                source_name="project_overwatch",
                collection_method="controlled_tls_review",
                reliability=RELIABILITY_HIGH,
            )
        )
        return items

    handshake_payload = {
        "host": host,
        "port": port,
        "sni": parsed_data.get("sni"),
        "connection_success": conn_info.get("success"),
        "connection_error": conn_info.get("error"),
        "tls_version": tls_info.get("version"),
        "cipher": tls_info.get("cipher"),
    }
    items.append(
        _create_item(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            title="TLS handshake summary",
            summary=f"Controlled TLS review handshake summary for {host}:{port}.",
            content_text=_text_summary(handshake_payload),
            content_type="application/json",
            evidence_type=EVIDENCE_DIRECT_OBSERVATION,
            source_name="TLS handshake",
            collection_method="controlled_tls_review",
            reliability=RELIABILITY_HIGH if conn_info.get("success") else RELIABILITY_MEDIUM,
        )
    )

    if cert.get("subject") or cert.get("issuer"):
        cert_summary = {
            "subject": cert.get("subject"),
            "issuer": cert.get("issuer"),
            "not_before": cert.get("not_before"),
            "not_after": cert.get("not_after"),
            "days_until_expiry": cert.get("days_until_expiry"),
            "san_dns_count": len(cert.get("san_dns_names") or []),
            "san_dns_sample": (cert.get("san_dns_names") or [])[:5],
            "hostname_valid": cert.get("hostname_valid"),
            "chain_valid": cert.get("chain_valid"),
            "fingerprint_sha256": cert.get("fingerprint_sha256"),
        }
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Certificate summary",
                summary=f"Certificate observed during TLS review for {host}:{port}.",
                content_text=_text_summary(cert_summary),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="TLS handshake",
                collection_method="controlled_tls_review",
                reliability=RELIABILITY_HIGH if conn_info.get("success") else RELIABILITY_MEDIUM,
            )
        )

    probes = tls_info.get("protocol_probe") or {}
    if probes:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="TLS protocol probe summary",
                summary=f"Controlled per-version TLS probes for {host}:{port}.",
                content_text=_text_summary(probes),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="TLS handshake",
                collection_method="controlled_tls_review",
                reliability=RELIABILITY_HIGH,
            )
        )

    if conn_info.get("error") and not conn_info.get("success"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="TLS connection failure summary",
                summary=f"TLS connection to {host}:{port} did not complete.",
                content_text=_text_summary(
                    {"error": conn_info.get("error"), "host": host, "port": port}
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_UNAVAILABLE_SOURCE,
                source_name="TLS handshake",
                collection_method="controlled_tls_review",
                reliability=RELIABILITY_MEDIUM,
            )
        )

    return items


def capture_email_security_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    parsed_data = result.get("parsed_data") or {}
    domain = parsed_data.get("domain") or "target"

    summary_payload = {
        "domain": domain,
        "spf": parsed_data.get("spf"),
        "dmarc": parsed_data.get("dmarc"),
        "mx_count": len(parsed_data.get("mx") or []),
        "caa_count": len(parsed_data.get("caa") or []),
        "mta_sts": {
            "txt_present": (parsed_data.get("mta_sts") or {}).get("txt_present"),
            "policy_reachable": (parsed_data.get("mta_sts") or {}).get("policy_reachable"),
            "mode": (parsed_data.get("mta_sts") or {}).get("mode"),
        },
        "tls_rpt_present": (parsed_data.get("tls_rpt") or {}).get("present"),
        "bimi_present": (parsed_data.get("bimi") or {}).get("present"),
        "warning": parsed_data.get("warning"),
    }
    items.append(
        _create_item(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            title="Email security DNS summary",
            summary="Passive SPF, DMARC, MX, CAA, MTA-STS, TLS-RPT and BIMI posture summary.",
            content_text=_text_summary(summary_payload),
            content_type="application/json",
            evidence_type=EVIDENCE_DIRECT_OBSERVATION,
            source_name="dns_lookup",
            collection_method="passive_dns_email_security_lookup",
            reliability=RELIABILITY_HIGH,
        )
    )

    spf = parsed_data.get("spf") or {}
    if spf.get("present") or spf.get("record"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="SPF record",
                summary=f"SPF TXT record observed for {domain}.",
                content_text=_text_summary(spf),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="dns_lookup",
                collection_method="passive_dns_email_security_lookup",
                reliability=RELIABILITY_HIGH,
            )
        )

    dmarc = parsed_data.get("dmarc") or {}
    if dmarc.get("present") or dmarc.get("record"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="DMARC record",
                summary=f"DMARC TXT record observed for {domain}.",
                content_text=_text_summary(dmarc),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="dns_lookup",
                collection_method="passive_dns_email_security_lookup",
                reliability=RELIABILITY_HIGH,
            )
        )

    mx = parsed_data.get("mx") or []
    if mx:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="MX records",
                summary=f"{len(mx)} MX record(s) observed for {domain}.",
                content_text=_text_summary(mx),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="dns_lookup",
                collection_method="passive_dns_email_security_lookup",
                reliability=RELIABILITY_HIGH,
            )
        )

    caa = parsed_data.get("caa") or []
    if caa:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="CAA records",
                summary=f"{len(caa)} CAA record(s) observed for {domain}.",
                content_text=_text_summary(caa),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="dns_lookup",
                collection_method="passive_dns_email_security_lookup",
                reliability=RELIABILITY_HIGH,
            )
        )

    mta_sts = parsed_data.get("mta_sts") or {}
    if mta_sts.get("txt_present") or mta_sts.get("policy_fetch"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="MTA-STS summary",
                summary="MTA-STS TXT and optional HTTPS policy fetch summary.",
                content_text=_text_summary(mta_sts),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="dns_lookup / https_mta_sts_policy",
                collection_method="passive_dns_email_security_lookup",
                reliability=RELIABILITY_HIGH if mta_sts.get("policy_reachable") else RELIABILITY_MEDIUM,
            )
        )

    tls_rpt = parsed_data.get("tls_rpt") or {}
    if tls_rpt.get("present") or tls_rpt.get("record"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="TLS-RPT record",
                summary=f"TLS-RPT TXT record summary for {domain}.",
                content_text=_text_summary(tls_rpt),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="dns_lookup",
                collection_method="passive_dns_email_security_lookup",
                reliability=RELIABILITY_HIGH,
            )
        )

    bimi = parsed_data.get("bimi") or {}
    if bimi.get("present") or bimi.get("record"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="BIMI record",
                summary=f"BIMI TXT record summary for {domain}.",
                content_text=_text_summary(bimi),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="dns_lookup",
                collection_method="passive_dns_email_security_lookup",
                reliability=RELIABILITY_HIGH,
            )
        )

    if parsed_data.get("warning"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Email security lookup notice",
                summary=parsed_data["warning"],
                content_text=parsed_data["warning"],
                content_type="text/plain",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="dns_lookup",
                collection_method="passive_dns_email_security_lookup",
                reliability=RELIABILITY_MEDIUM,
            )
        )
    return items


def capture_virustotal_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    parsed_data = result.get("parsed_data") or {}
    raw_response = parsed_data.get("raw_response")
    api_meta = parsed_data.get("api") or {}

    if parsed_data.get("private_local_ip"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Private/local IP — no VirusTotal lookup",
                summary="Public reputation lookup is not applicable for private/local addresses.",
                content_text="Private/local IP address — public reputation lookup is not applicable.",
                content_type="text/plain",
                evidence_type=EVIDENCE_SYSTEM_GENERATED,
                source_name="VirusTotal",
                collection_method="policy_skip",
                reliability=RELIABILITY_HIGH,
            )
        )
        return items

    if raw_response:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="VirusTotal API response",
                summary="Third-party reputation response from VirusTotal API v3 (redacted summary).",
                content_text=_text_summary(raw_response),
                content_type="application/json",
                evidence_type=EVIDENCE_THIRD_PARTY_SOURCE,
                source_name="VirusTotal",
                source_url="https://www.virustotal.com/",
                collection_method="api_reputation_lookup",
                reliability=RELIABILITY_MEDIUM,
            )
        )

    stats = parsed_data.get("last_analysis_stats") or {}
    if stats or parsed_data.get("reputation") is not None:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="VirusTotal reputation summary",
                summary="Parsed security vendor analysis counts and reputation metadata.",
                content_text=_text_summary(
                    {
                        "target": parsed_data.get("target"),
                        "target_type": parsed_data.get("target_type"),
                        "resource_id": parsed_data.get("resource_id"),
                        "last_analysis_stats": stats,
                        "last_analysis_date_label": parsed_data.get("last_analysis_date_label"),
                        "reputation": parsed_data.get("reputation"),
                        "flagged_vendor_count": parsed_data.get("flagged_vendor_count"),
                        "country": parsed_data.get("country"),
                        "asn": parsed_data.get("asn"),
                        "as_owner": parsed_data.get("as_owner"),
                        "registrar": parsed_data.get("registrar"),
                    }
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_THIRD_PARTY_SOURCE,
                source_name="VirusTotal",
                source_url="https://www.virustotal.com/",
                collection_method="api_reputation_lookup",
                reliability=RELIABILITY_MEDIUM,
            )
        )

    if api_meta.get("error") or api_meta.get("status_code") == 429:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="VirusTotal lookup limitation",
                summary="VirusTotal source was unavailable, rate limited, or returned an error during this run.",
                content_text=_text_summary(api_meta),
                content_type="application/json",
                evidence_type=EVIDENCE_UNAVAILABLE_SOURCE,
                source_name="VirusTotal",
                source_url="https://www.virustotal.com/",
                collection_method="api_reputation_lookup",
                reliability=RELIABILITY_UNKNOWN,
            )
        )

    return items


def capture_abuseipdb_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    parsed_data = result.get("parsed_data") or {}
    raw_response = parsed_data.get("raw_response")
    api_meta = parsed_data.get("api") or {}

    if parsed_data.get("private_local_ip"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Private/local IP — no AbuseIPDB lookup",
                summary="Public reputation lookup is not applicable for private/local addresses.",
                content_text="Private/local IP address — public AbuseIPDB reputation lookup is not applicable.",
                content_type="text/plain",
                evidence_type=EVIDENCE_SYSTEM_GENERATED,
                source_name="AbuseIPDB",
                collection_method="policy_skip",
                reliability=RELIABILITY_HIGH,
            )
        )
        return items

    if api_meta.get("error") == "AbuseIPDB API key is not configured." or api_meta.get("status_code") in {401, 403}:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="AbuseIPDB API key not configured",
                summary="AbuseIPDB lookup was blocked because the API key is missing or rejected.",
                content_text=_text_summary(api_meta),
                content_type="application/json",
                evidence_type=EVIDENCE_SYSTEM_GENERATED,
                source_name="AbuseIPDB",
                collection_method="policy_skip",
                reliability=RELIABILITY_HIGH,
            )
        )
        return items

    if raw_response:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="AbuseIPDB API response",
                summary="Third-party abuse-confidence response from AbuseIPDB (redacted summary).",
                content_text=_text_summary(raw_response),
                content_type="application/json",
                evidence_type=EVIDENCE_THIRD_PARTY_SOURCE,
                source_name="AbuseIPDB",
                source_url="https://www.abuseipdb.com/",
                collection_method="api_reputation_lookup",
                reliability=RELIABILITY_MEDIUM,
            )
        )

    if parsed_data.get("abuse_confidence_score") is not None or parsed_data.get("total_reports") is not None:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="AbuseIPDB reputation summary",
                summary="Parsed abuse confidence score and report metadata.",
                content_text=_text_summary(
                    {
                        "target": parsed_data.get("target"),
                        "ip_address": parsed_data.get("ip_address"),
                        "abuse_confidence_score": parsed_data.get("abuse_confidence_score"),
                        "total_reports": parsed_data.get("total_reports"),
                        "num_distinct_users": parsed_data.get("num_distinct_users"),
                        "country_code": parsed_data.get("country_code"),
                        "country_name": parsed_data.get("country_name"),
                        "isp": parsed_data.get("isp"),
                        "domain": parsed_data.get("domain"),
                        "usage_type": parsed_data.get("usage_type"),
                        "last_reported_label": parsed_data.get("last_reported_label"),
                        "is_whitelisted": parsed_data.get("is_whitelisted"),
                    }
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_THIRD_PARTY_SOURCE,
                source_name="AbuseIPDB",
                source_url="https://www.abuseipdb.com/",
                collection_method="api_reputation_lookup",
                reliability=RELIABILITY_MEDIUM,
            )
        )

    if api_meta.get("error") or api_meta.get("status_code") == 429:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="AbuseIPDB lookup limitation",
                summary="AbuseIPDB source was unavailable, rate limited, or returned an error during this run.",
                content_text=_text_summary(api_meta),
                content_type="application/json",
                evidence_type=EVIDENCE_UNAVAILABLE_SOURCE,
                source_name="AbuseIPDB",
                source_url="https://www.abuseipdb.com/",
                collection_method="api_reputation_lookup",
                reliability=RELIABILITY_UNKNOWN,
            )
        )

    return items


def capture_greynoise_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    parsed_data = result.get("parsed_data") or {}
    raw_response = parsed_data.get("raw_response")
    api_meta = parsed_data.get("api") or {}

    if parsed_data.get("private_local_ip"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Private/local IP — no GreyNoise lookup",
                summary="Public internet-noise lookup is not applicable for private/local addresses.",
                content_text=(
                    "Private/local IP address — public GreyNoise internet-noise lookup is not applicable."
                ),
                content_type="text/plain",
                evidence_type=EVIDENCE_SYSTEM_GENERATED,
                source_name="GreyNoise",
                collection_method="policy_skip",
                reliability=RELIABILITY_HIGH,
            )
        )
        return items

    if raw_response:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="GreyNoise API response",
                summary="Third-party internet-noise response from GreyNoise Community API (redacted summary).",
                content_text=_text_summary(raw_response),
                content_type="application/json",
                evidence_type=EVIDENCE_THIRD_PARTY_SOURCE,
                source_name="GreyNoise",
                source_url="https://www.greynoise.io/",
                collection_method="api_reputation_lookup",
                reliability=RELIABILITY_MEDIUM,
            )
        )

    if any(parsed_data.get(field) is not None for field in ("noise", "riot", "classification", "name")):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="GreyNoise internet-noise summary",
                summary="Parsed noise/RIOT/classification metadata.",
                content_text=_text_summary(
                    {
                        "target": parsed_data.get("target"),
                        "ip_address": parsed_data.get("ip_address"),
                        "noise": parsed_data.get("noise"),
                        "riot": parsed_data.get("riot"),
                        "classification": parsed_data.get("classification"),
                        "name": parsed_data.get("name"),
                        "last_seen": parsed_data.get("last_seen"),
                        "message": parsed_data.get("message"),
                        "link": parsed_data.get("link"),
                        "authenticated": api_meta.get("authenticated"),
                    }
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_THIRD_PARTY_SOURCE,
                source_name="GreyNoise",
                source_url="https://www.greynoise.io/",
                collection_method="api_reputation_lookup",
                reliability=RELIABILITY_MEDIUM,
            )
        )

    if api_meta.get("error") or api_meta.get("status_code") == 429:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="GreyNoise lookup limitation",
                summary="GreyNoise source was unavailable, rate limited, unauthenticated, or returned an error.",
                content_text=_text_summary(api_meta),
                content_type="application/json",
                evidence_type=EVIDENCE_UNAVAILABLE_SOURCE,
                source_name="GreyNoise",
                source_url="https://www.greynoise.io/",
                collection_method="api_reputation_lookup",
                reliability=RELIABILITY_UNKNOWN,
            )
        )

    return items


def capture_shodan_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    parsed_data = result.get("parsed_data") or {}
    raw_response = parsed_data.get("raw_response")
    api_meta = parsed_data.get("api") or {}

    if parsed_data.get("private_local_ip"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Private/local IP — no Shodan lookup",
                summary="Public internet-exposure lookup is not applicable for private/local addresses.",
                content_text=(
                    "Private/local IP address — public Shodan internet-exposure lookup is not applicable."
                ),
                content_type="text/plain",
                evidence_type=EVIDENCE_SYSTEM_GENERATED,
                source_name="Shodan",
                collection_method="policy_skip",
                reliability=RELIABILITY_HIGH,
            )
        )
        return items

    if api_meta.get("error") == "Shodan API key is not configured." or api_meta.get("status_code") in {401, 403}:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Shodan API key not configured",
                summary="Shodan lookup was blocked because the API key is missing or rejected.",
                content_text=_text_summary(api_meta),
                content_type="application/json",
                evidence_type=EVIDENCE_SYSTEM_GENERATED,
                source_name="Shodan",
                collection_method="policy_skip",
                reliability=RELIABILITY_HIGH,
            )
        )
        return items

    if raw_response:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Shodan API response",
                summary="Third-party host exposure response from Shodan (redacted summary, no exploit detail).",
                content_text=_text_summary(raw_response),
                content_type="application/json",
                evidence_type=EVIDENCE_THIRD_PARTY_SOURCE,
                source_name="Shodan",
                source_url="https://www.shodan.io/",
                collection_method="api_exposure_lookup",
                reliability=RELIABILITY_MEDIUM,
            )
        )

    if parsed_data.get("services") or parsed_data.get("service_count"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Shodan service exposure summary",
                summary="Parsed service/port exposure summary reported by Shodan.",
                content_text=_text_summary(
                    {
                        "target": parsed_data.get("target"),
                        "ip_address": parsed_data.get("ip_address"),
                        "service_count": parsed_data.get("service_count"),
                        "ports": parsed_data.get("ports"),
                        "services": (parsed_data.get("services") or [])[:25],
                        "last_update": parsed_data.get("last_update"),
                        "vulnerability_count": parsed_data.get("vulnerability_count"),
                    }
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_THIRD_PARTY_SOURCE,
                source_name="Shodan",
                source_url="https://www.shodan.io/",
                collection_method="api_exposure_lookup",
                reliability=RELIABILITY_MEDIUM,
            )
        )

    if api_meta.get("error") or api_meta.get("status_code") == 429:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Shodan lookup limitation",
                summary="Shodan source was unavailable, rate limited, or returned an error.",
                content_text=_text_summary(api_meta),
                content_type="application/json",
                evidence_type=EVIDENCE_UNAVAILABLE_SOURCE,
                source_name="Shodan",
                source_url="https://www.shodan.io/",
                collection_method="api_exposure_lookup",
                reliability=RELIABILITY_UNKNOWN,
            )
        )

    return items


def capture_urlhaus_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    parsed_data = result.get("parsed_data") or {}
    raw_response = parsed_data.get("raw_response")
    api_meta = parsed_data.get("api") or {}

    if parsed_data.get("private_local_ip"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Private/local IP — no URLhaus lookup",
                summary="Public URLhaus malware URL lookup is not applicable for private/local addresses.",
                content_text=(
                    "Private/local IP address — public URLhaus malware URL lookup is not applicable."
                ),
                content_type="text/plain",
                evidence_type=EVIDENCE_SYSTEM_GENERATED,
                source_name="URLhaus",
                collection_method="policy_skip",
                reliability=RELIABILITY_HIGH,
            )
        )
        return items

    if api_meta.get("error") == "URLhaus / abuse.ch Auth-Key is not configured." or api_meta.get(
        "status_code"
    ) in {401, 403}:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="URLhaus Auth-Key not configured",
                summary="URLhaus lookup was blocked because the Auth-Key is missing or rejected.",
                content_text=_text_summary(api_meta),
                content_type="application/json",
                evidence_type=EVIDENCE_SYSTEM_GENERATED,
                source_name="URLhaus",
                collection_method="policy_skip",
                reliability=RELIABILITY_HIGH,
            )
        )
        return items

    lookup_type = parsed_data.get("lookup_type")
    if lookup_type == "url":
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="URLhaus URL lookup summary",
                summary="Parsed URLhaus malware URL intelligence (Auth-Key redacted, no download links).",
                content_text=_text_summary(
                    {
                        "target": parsed_data.get("target"),
                        "lookup_value": parsed_data.get("lookup_value"),
                        "query_status": parsed_data.get("query_status"),
                        "url_status": parsed_data.get("url_status"),
                        "threat": parsed_data.get("threat"),
                        "tags": parsed_data.get("tags"),
                        "blacklist_summary": parsed_data.get("blacklist_summary"),
                        "payload_hashes": parsed_data.get("payload_hashes"),
                    }
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_THIRD_PARTY_SOURCE,
                source_name="URLhaus",
                source_url="https://urlhaus.abuse.ch/",
                collection_method="api_malware_url_lookup",
                reliability=RELIABILITY_MEDIUM,
            )
        )
    else:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="URLhaus host lookup summary",
                summary="Parsed URLhaus host malware URL intelligence (capped sample, no download links).",
                content_text=_text_summary(
                    {
                        "target": parsed_data.get("target"),
                        "lookup_value": parsed_data.get("lookup_value"),
                        "query_status": parsed_data.get("query_status"),
                        "url_count": parsed_data.get("url_count"),
                        "active_url_count": parsed_data.get("active_url_count"),
                        "offline_url_count": parsed_data.get("offline_url_count"),
                        "blacklist_summary": parsed_data.get("blacklist_summary"),
                        "sampled_urls": parsed_data.get("sampled_urls"),
                        "output_capped": parsed_data.get("output_capped"),
                    }
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_THIRD_PARTY_SOURCE,
                source_name="URLhaus",
                source_url="https://urlhaus.abuse.ch/",
                collection_method="api_malware_url_lookup",
                reliability=RELIABILITY_MEDIUM,
            )
        )

    if raw_response:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="URLhaus API response",
                summary="Third-party URLhaus response summary (download links stripped).",
                content_text=_text_summary(raw_response),
                content_type="application/json",
                evidence_type=EVIDENCE_THIRD_PARTY_SOURCE,
                source_name="URLhaus",
                source_url="https://urlhaus.abuse.ch/",
                collection_method="api_malware_url_lookup",
                reliability=RELIABILITY_MEDIUM,
            )
        )

    if api_meta.get("error") or api_meta.get("status_code") == 429:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="URLhaus lookup limitation",
                summary="URLhaus source was unavailable, rate limited, or returned an error.",
                content_text=_text_summary(api_meta),
                content_type="application/json",
                evidence_type=EVIDENCE_UNAVAILABLE_SOURCE,
                source_name="URLhaus",
                source_url="https://urlhaus.abuse.ch/",
                collection_method="api_malware_url_lookup",
                reliability=RELIABILITY_UNKNOWN,
            )
        )

    return items


def capture_pcap_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    parsed_data = result.get("parsed_data") or {}
    filename = parsed_data.get("filename") or "capture"

    items.append(
        _create_item(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            title="PCAP capture file summary",
            summary="Metadata for the supplied packet capture file (hash and size only).",
            content_text=_text_summary(
                {
                    "filename": filename,
                    "sha256": parsed_data.get("sha256"),
                    "file_size_bytes": parsed_data.get("file_size_bytes"),
                    "packets_analysed": parsed_data.get("packets_analysed"),
                    "duration_seconds": parsed_data.get("duration_seconds"),
                }
            ),
            content_type="application/json",
            evidence_type=EVIDENCE_DIRECT_OBSERVATION,
            source_name="uploaded_pcap",
            collection_method="local_packet_capture_review",
            reliability=RELIABILITY_HIGH,
        )
    )

    if not parsed_data.get("parser_available"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="PCAP parser dependency unavailable",
                summary="Deep packet parsing was not available during this run.",
                content_text=_text_summary(
                    {
                        "parser_available": False,
                        "note": "Install pyshark and Wireshark/tshark for deeper parsing.",
                    }
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_UNAVAILABLE_SOURCE,
                source_name="uploaded_pcap",
                collection_method="local_packet_capture_review",
                reliability=RELIABILITY_HIGH,
            )
        )
        return items

    if parsed_data.get("protocols"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Protocol summary",
                summary="Protocols observed in the supplied capture (bounded sample).",
                content_text=_text_summary({"protocols": parsed_data.get("protocols")}),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="uploaded_pcap",
                collection_method="local_packet_capture_review",
                reliability=RELIABILITY_HIGH,
            )
        )

    if parsed_data.get("top_conversations"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Top conversations summary",
                summary="Highest-volume endpoint conversations in the supplied capture.",
                content_text=_text_summary({"top_conversations": parsed_data.get("top_conversations")}),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="uploaded_pcap",
                collection_method="local_packet_capture_review",
                reliability=RELIABILITY_HIGH,
            )
        )

    if parsed_data.get("dns_queries"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="DNS query summary",
                summary="Sampled DNS queries from the supplied capture.",
                content_text=_text_summary({"dns_queries": parsed_data.get("dns_queries")}),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="uploaded_pcap",
                collection_method="local_packet_capture_review",
                reliability=RELIABILITY_HIGH,
            )
        )

    if parsed_data.get("http_entries"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="HTTP traffic summary",
                summary="Sampled HTTP hosts/methods/status codes — no raw payloads stored.",
                content_text=_text_summary({"http_entries": parsed_data.get("http_entries")}),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="uploaded_pcap",
                collection_method="local_packet_capture_review",
                reliability=RELIABILITY_HIGH,
            )
        )

    if parsed_data.get("tls_sni"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="TLS / SNI summary",
                summary="Sampled TLS server names from the supplied capture.",
                content_text=_text_summary({"tls_sni": parsed_data.get("tls_sni")}),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="uploaded_pcap",
                collection_method="local_packet_capture_review",
                reliability=RELIABILITY_HIGH,
            )
        )

    if parsed_data.get("analysis_capped"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Packet analysis capped",
                summary="Analysis stopped at the configured packet cap.",
                content_text=_text_summary(
                    {
                        "analysis_capped": True,
                        "packets_analysed": parsed_data.get("packets_analysed"),
                    }
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_SYSTEM_GENERATED,
                source_name="uploaded_pcap",
                collection_method="local_packet_capture_review",
                reliability=RELIABILITY_HIGH,
            )
        )

    if parsed_data.get("sensitive_values_redacted"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Sensitive value redaction note",
                summary="Sensitive-looking HTTP material was detected and redacted from stored output.",
                content_text=_text_summary(
                    {
                        "sensitive_values_redacted": True,
                        "note": "Inspect the original capture offline under controlled conditions if required.",
                    }
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_SYSTEM_GENERATED,
                source_name="uploaded_pcap",
                collection_method="local_packet_capture_review",
                reliability=RELIABILITY_HIGH,
            )
        )

    for warning in result.get("warnings") or []:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="PCAP parser warning",
                summary=str(warning)[:200],
                content_text=str(warning),
                content_type="text/plain",
                evidence_type=EVIDENCE_SYSTEM_GENERATED,
                source_name="uploaded_pcap",
                collection_method="local_packet_capture_review",
                reliability=RELIABILITY_HIGH,
            )
        )

    return items


def capture_live_capture_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    parsed_data = result.get("parsed_data") or {}
    capture = parsed_data.get("capture") or {}
    pcap_review = parsed_data.get("pcap_review") or {}
    pcap_parsed = pcap_review.get("parsed_data") or {}

    items.append(
        _create_item(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            title="Live capture settings",
            summary="Bounded Personal Lab capture parameters used for this run.",
            content_text=_text_summary(
                {
                    "backend": capture.get("backend"),
                    "interface": capture.get("interface"),
                    "duration_seconds": capture.get("duration_seconds"),
                    "packet_cap": capture.get("packet_cap"),
                    "filter_preset": capture.get("filter_preset"),
                    "bpf_filter": capture.get("bpf_filter"),
                }
            ),
            content_type="application/json",
            evidence_type=EVIDENCE_DIRECT_OBSERVATION,
            source_name="personal_lab_packet_capture",
            collection_method="controlled_live_packet_capture",
            reliability=RELIABILITY_HIGH,
        )
    )

    if capture.get("filename"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Capture file metadata",
                summary="Saved PCAP file metadata from the live capture.",
                content_text=_text_summary(
                    {
                        "filename": capture.get("filename"),
                        "sha256": capture.get("sha256"),
                        "file_size_bytes": capture.get("file_size_bytes"),
                    }
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="personal_lab_packet_capture",
                collection_method="controlled_live_packet_capture",
                reliability=RELIABILITY_HIGH,
            )
        )

    if capture.get("backend"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Capture backend used",
                summary=f"Capture backend: {capture.get('backend')}",
                content_text=_text_summary({"backend": capture.get("backend")}),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="personal_lab_packet_capture",
                collection_method="controlled_live_packet_capture",
                reliability=RELIABILITY_HIGH,
            )
        )

    if pcap_parsed:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="PCAP analysis summary",
                summary="Bounded PCAP Evidence Review summary for the captured file.",
                content_text=_text_summary(
                    {
                        "packets_analysed": pcap_parsed.get("packets_analysed"),
                        "protocols": pcap_parsed.get("protocols"),
                        "top_source_ips": pcap_parsed.get("top_source_ips"),
                        "dns_queries": (pcap_parsed.get("dns_queries") or [])[:20],
                    }
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_DIRECT_OBSERVATION,
                source_name="personal_lab_packet_capture",
                collection_method="controlled_live_packet_capture",
                reliability=RELIABILITY_HIGH,
            )
        )

    if capture.get("permission_denied"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Capture permission issue",
                summary="Live capture failed due to local permission restrictions.",
                content_text=_text_summary(
                    {
                        "manual_command": capture.get("manual_command"),
                        "permission_denied": True,
                    }
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_UNAVAILABLE_SOURCE,
                source_name="personal_lab_packet_capture",
                collection_method="controlled_live_packet_capture",
                reliability=RELIABILITY_HIGH,
            )
        )

    return items


def capture_whois_rdap_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    parsed_data = result.get("parsed_data") or result.get("data") or {}

    if parsed_data.get("private_local_ip"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="Private/local IP RDAP notice",
                summary="Public RDAP allocation lookup is not applicable for this address.",
                content_text=_text_summary(parsed_data),
                content_type="application/json",
                evidence_type=EVIDENCE_SYSTEM_GENERATED,
                source_name="project_overwatch",
                collection_method="local_classification",
                reliability=RELIABILITY_HIGH,
            )
        )
        return items

    rdap_summary = parsed_data.get("rdap_summary")
    source = parsed_data.get("source")
    if rdap_summary:
        is_whois = source == "whois"
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="WHOIS fallback summary" if is_whois else "RDAP response summary",
                summary=(
                    "Structured registration metadata from WHOIS port-43 fallback."
                    if is_whois
                    else "Structured registration/allocation metadata from public RDAP."
                ),
                content_text=_text_summary(
                    {
                        "source": source,
                        "rdap_url": parsed_data.get("rdap_url"),
                        "whois_fallback": parsed_data.get("whois_fallback"),
                        "rdap_summary": rdap_summary,
                        "from_cache": parsed_data.get("from_cache"),
                    }
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_THIRD_PARTY_SOURCE,
                source_name=(parsed_data.get("whois_fallback") or {}).get("whois_server") or "rdap.org",
                source_url=None if is_whois else "https://rdap.org/",
                collection_method="whois_fallback" if is_whois else "public_rdap_lookup",
                reliability=RELIABILITY_MEDIUM,
            )
        )

    if parsed_data.get("lookup_status") == "unavailable" or parsed_data.get("warning"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="RDAP lookup limitation",
                summary="RDAP source was unavailable or incomplete during this run.",
                content_text=_text_summary(
                    {
                        "warning": parsed_data.get("warning"),
                        "rdap_url": parsed_data.get("rdap_url"),
                        "lookup_status": parsed_data.get("lookup_status"),
                    }
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_UNAVAILABLE_SOURCE,
                source_name="rdap.org",
                source_url="https://rdap.org/",
                collection_method="public_rdap_lookup",
                reliability=RELIABILITY_UNKNOWN,
            )
        )

    return items


def capture_module_evidence(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int,
    observation_id: int,
    module_id: str,
    result: dict[str, Any],
) -> list[dict[str, Any]]:
    """Create evidence locker items for a completed module observation."""
    if module_id == "infra_nmap":
        return capture_nmap_evidence(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            result=result,
        )
    if module_id == "infra_domain_intel":
        return capture_domain_intel_evidence(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            result=result,
        )
    if module_id == "infra_cert_subdomain":
        return capture_cert_subdomain_evidence(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            result=result,
        )
    if module_id == "infra_website_metadata":
        return capture_website_metadata_evidence(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            result=result,
        )
    if module_id == "infra_tls_review":
        return capture_tls_review_evidence(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            result=result,
        )
    if module_id == "infra_http_security":
        return capture_http_security_evidence(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            result=result,
        )
    if module_id == "infra_email_security":
        return capture_email_security_evidence(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            result=result,
        )
    if module_id == "infra_whois_rdap":
        items = capture_whois_rdap_evidence(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            result=result,
        )
    elif module_id == "intel_virustotal":
        items = capture_virustotal_evidence(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            result=result,
        )
    elif module_id == "intel_abuseipdb":
        items = capture_abuseipdb_evidence(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            result=result,
        )
    elif module_id == "intel_greynoise":
        items = capture_greynoise_evidence(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            result=result,
        )
    elif module_id == "intel_shodan":
        items = capture_shodan_evidence(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            result=result,
        )
    elif module_id == "intel_urlhaus":
        items = capture_urlhaus_evidence(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            result=result,
        )
    elif module_id == "net_pcap_review":
        items = capture_pcap_evidence(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            result=result,
        )
    elif module_id == "net_live_capture":
        items = capture_live_capture_evidence(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            result=result,
        )
    else:
        items = []

    items.extend(
        capture_result_evidence_hints(
            conn,
            case_id=case_id,
            entity_id=entity_id,
            observation_id=observation_id,
            module_id=module_id,
            result=result,
        )
    )
    return items


def link_observation_evidence_to_findings(
    conn: sqlite3.Connection,
    observation_id: int,
    findings: list[dict[str, Any]],
) -> None:
    """Link observation evidence items to all findings from the same module run."""
    if not findings:
        return
    evidence_items = list_evidence_items(observation_id=observation_id, conn=conn)
    if not evidence_items:
        return
    for finding in findings:
        finding_id = finding.get("id")
        if finding_id is None:
            continue
        for item in evidence_items:
            link_evidence_to_finding(item["id"], int(finding_id), conn=conn)

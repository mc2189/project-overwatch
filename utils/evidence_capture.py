"""Capture module run artefacts into the Evidence Locker."""

from __future__ import annotations

import base64
import json
import sqlite3
from typing import Any

from database.db_setup import create_evidence_item, link_evidence_to_finding, list_evidence_items
from utils.evidence_model import (
    EVIDENCE_DIRECT_OBSERVATION,
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

    if raw_response:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="VirusTotal API response",
                summary="Third-party threat intelligence response from VirusTotal API v3.",
                content_text=_text_summary(raw_response),
                content_type="application/json",
                evidence_type=EVIDENCE_THIRD_PARTY_SOURCE,
                source_name="virustotal",
                source_url="https://www.virustotal.com/",
                collection_method="api_lookup",
                reliability=RELIABILITY_MEDIUM,
            )
        )

    stats = parsed_data.get("last_analysis_stats") or {}
    if stats:
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="VirusTotal analysis summary",
                summary="Parsed detection counts and metadata from the VirusTotal lookup.",
                content_text=_text_summary(
                    {
                        "target": parsed_data.get("target"),
                        "target_type": parsed_data.get("target_type"),
                        "resource_id": parsed_data.get("resource_id"),
                        "last_analysis_stats": stats,
                        "last_analysis_date": parsed_data.get("last_analysis_date"),
                        "reputation": parsed_data.get("reputation"),
                        "api": api_meta,
                    }
                ),
                content_type="application/json",
                evidence_type=EVIDENCE_THIRD_PARTY_SOURCE,
                source_name="virustotal",
                source_url="https://www.virustotal.com/",
                collection_method="parser_inferred",
                reliability=RELIABILITY_MEDIUM,
            )
        )

    if api_meta.get("error"):
        items.append(
            _create_item(
                conn,
                case_id=case_id,
                entity_id=entity_id,
                observation_id=observation_id,
                module_id=module_id,
                title="VirusTotal lookup limitation",
                summary="VirusTotal source was unavailable or returned an error during this run.",
                content_text=_text_summary(api_meta),
                content_type="application/json",
                evidence_type=EVIDENCE_UNAVAILABLE_SOURCE,
                source_name="virustotal",
                source_url="https://www.virustotal.com/",
                collection_method="api_lookup",
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
    if module_id == "intel_virustotal":
        items = capture_virustotal_evidence(
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

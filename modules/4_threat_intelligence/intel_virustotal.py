"""VirusTotal Reputation Intelligence — passive API enrichment for Project Overwatch."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote

import requests

from utils.result_status import (
    STATUS_BLOCKED,
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_WARNINGS,
    STATUS_ERROR,
    STATUS_PARTIAL,
    resolve_collection_status,
)
from utils.security import is_private_or_local_ip, redact_secrets_from_text
from utils.target_detection import get_target_type, normalize_target_value
from utils.api_module_helpers import project_user_agent, respect_api_courtesy_delay

VT_API_BASE = "https://www.virustotal.com/api/v3"
MISSING_KEY_MESSAGE = "VirusTotal API key is not configured."
PRIVATE_IP_MESSAGE = "Private/local IP address — public reputation lookup is not applicable."


def _request_timeout() -> int:
    try:
        from utils.settings_manager import default_timeout_seconds

        return default_timeout_seconds()
    except Exception:
        return 30


def _user_agent() -> str:
    return project_user_agent()


def _url_resource_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")


def _vt_headers(api_key: str) -> dict[str, str]:
    return {
        "x-apikey": api_key,
        "Accept": "application/json",
        "User-Agent": _user_agent(),
    }


def _normalise_target(target: str, target_type: str | None = None) -> tuple[str, str]:
    cleaned = target.strip()
    resolved_type = target_type or get_target_type(cleaned)
    if resolved_type in {"domain", "url", "ipv4"}:
        cleaned = normalize_target_value(cleaned, resolved_type)
    return cleaned, resolved_type


def _classify_http_status(status_code: int | None) -> tuple[str, bool, list[str], list[str]]:
    """Return result status, success flag, warnings, and errors for HTTP codes."""
    if status_code is None:
        return STATUS_ERROR, False, [], ["VirusTotal request failed before a response was received."]
    if status_code == 200:
        return STATUS_COMPLETED, True, [], []
    if status_code in {400, 404}:
        return STATUS_COMPLETED, True, ["VirusTotal returned no data for this resource."], []
    if status_code in {401, 403}:
        return (
            STATUS_BLOCKED,
            False,
            [],
            ["VirusTotal rejected the API key (unauthorised). Check VIRUSTOTAL_API_KEY in your local .env file."],
        )
    if status_code == 429:
        return (
            STATUS_COMPLETED_WITH_WARNINGS,
            True,
            ["VirusTotal rate limit reached — retry later or reduce batch frequency."],
            [],
        )
    if status_code and status_code >= 500:
        return (
            STATUS_ERROR,
            False,
            [],
            [f"VirusTotal provider error (HTTP {status_code}). Retry later."],
        )
    return STATUS_PARTIAL, False, [], [f"Unexpected VirusTotal response (HTTP {status_code})."]


def _request_json(
    method: str,
    path: str,
    *,
    api_key: str,
    params: dict[str, Any] | None = None,
    data: dict[str, Any] | None = None,
    session: requests.Session | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Perform a VirusTotal API request and return parsed JSON plus API metadata."""
    respect_api_courtesy_delay()
    http = session or requests
    url = f"{VT_API_BASE}/{path.lstrip('/')}"
    meta: dict[str, Any] = {"status_code": None, "path": path}
    try:
        response = http.request(
            method,
            url,
            headers=_vt_headers(api_key),
            params=params,
            data=data,
            timeout=_request_timeout(),
        )
    except requests.Timeout:
        meta["error"] = "VirusTotal request timed out."
        return None, meta
    except requests.RequestException as exc:
        meta["error"] = redact_secrets_from_text(str(exc))
        return None, meta

    meta["status_code"] = response.status_code
    try:
        payload = response.json()
    except ValueError:
        payload = None
        meta["error"] = redact_secrets_from_text(response.text[:500] or f"HTTP {response.status_code}")

    if response.status_code >= 400:
        detail = ""
        if isinstance(payload, dict):
            detail = (payload.get("error") or {}).get("message") or json.dumps(payload)[:300]
        meta["error"] = redact_secrets_from_text(detail or response.text[:300] or f"HTTP {response.status_code}")
        return payload if isinstance(payload, dict) else None, meta

    return payload if isinstance(payload, dict) else None, meta


def _lookup_url(api_key: str, target: str, *, session: requests.Session | None = None) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    resource_id = _url_resource_id(target)
    payload, meta = _request_json("GET", f"urls/{resource_id}", api_key=api_key, session=session)
    if meta.get("status_code") == 404:
        payload, meta = _request_json(
            "POST",
            "urls",
            api_key=api_key,
            data={"url": target},
            session=session,
        )
    return payload, meta


def _lookup_resource(
    api_key: str,
    target: str,
    target_type: str,
    *,
    session: requests.Session | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    if target_type == "ipv4":
        return _request_json(
            "GET",
            f"ip_addresses/{quote(target, safe='')}",
            api_key=api_key,
            session=session,
        )
    if target_type == "domain":
        return _request_json(
            "GET",
            f"domains/{quote(target.lower(), safe='')}",
            api_key=api_key,
            session=session,
        )
    if target_type == "url":
        return _lookup_url(api_key, target, session=session)
    return None, {"status_code": None, "error": f"Unsupported target type: {target_type}"}


def _parse_engine_results(attributes: dict[str, Any]) -> list[dict[str, str]]:
    """Extract per-engine analysis rows for UI display (flagged engines first)."""
    raw = attributes.get("last_analysis_results") or {}
    if not isinstance(raw, dict):
        return []
    priority = {"malicious": 0, "suspicious": 1, "timeout": 2, "undetected": 3, "harmless": 4}
    rows: list[dict[str, str]] = []
    for engine, detail in raw.items():
        if not isinstance(detail, dict):
            continue
        category = str(detail.get("category") or "undetected")
        rows.append(
            {
                "engine": str(engine),
                "category": category,
                "result": str(detail.get("result") or ""),
            }
        )
    rows.sort(key=lambda item: (priority.get(item["category"], 9), item["engine"]))
    return rows


def _format_analysis_date(value: Any) -> str | None:
    if value in (None, ""):
        return None
    try:
        timestamp = int(value)
        return datetime.fromtimestamp(timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    except (TypeError, ValueError):
        return str(value)


def parse_virustotal_response(
    target: str,
    target_type: str,
    payload: dict[str, Any] | None,
    api_meta: dict[str, Any],
) -> dict[str, Any]:
    """Normalise a VirusTotal API payload into structured parsed data."""
    data = (payload or {}).get("data") or {}
    attributes = data.get("attributes") or {}
    stats = attributes.get("last_analysis_stats") or {}

    engine_rows = _parse_engine_results(attributes)
    return {
        "target": target,
        "target_type": target_type,
        "resource_id": data.get("id"),
        "resource_type": data.get("type"),
        "last_analysis_stats": stats,
        "harmless_count": int(stats.get("harmless") or 0),
        "suspicious_count": int(stats.get("suspicious") or 0),
        "malicious_count": int(stats.get("malicious") or 0),
        "undetected_count": int(stats.get("undetected") or 0),
        "timeout_count": int(stats.get("timeout") or 0),
        "flagged_vendor_count": int(stats.get("malicious") or 0) + int(stats.get("suspicious") or 0),
        "last_analysis_date": attributes.get("last_analysis_date"),
        "last_analysis_date_label": _format_analysis_date(attributes.get("last_analysis_date")),
        "reputation": attributes.get("reputation"),
        "total_votes": attributes.get("total_votes") or {},
        "country": attributes.get("country"),
        "asn": attributes.get("asn"),
        "as_owner": attributes.get("as_owner"),
        "network": attributes.get("network"),
        "registrar": attributes.get("registrar"),
        "creation_date": attributes.get("creation_date"),
        "creation_date_label": _format_analysis_date(attributes.get("creation_date")),
        "categories": attributes.get("categories") or {},
        "tags": attributes.get("tags") or [],
        "engine_results": engine_rows,
        "engine_results_flagged": [
            row for row in engine_rows if row.get("category") in {"malicious", "suspicious"}
        ],
        "private_local_ip": False,
        "api": api_meta,
        "raw_response": payload,
    }


def _build_summary(parsed_data: dict[str, Any]) -> str:
    if parsed_data.get("private_local_ip"):
        return PRIVATE_IP_MESSAGE
    target = parsed_data.get("target") or "target"
    stats = parsed_data.get("last_analysis_stats") or {}
    if parsed_data.get("api", {}).get("status_code") in {401, 403}:
        return MISSING_KEY_MESSAGE
    if not stats and parsed_data.get("api", {}).get("status_code") in {400, 404}:
        return f"VirusTotal returned no reputation data for {target}."
    flagged = parsed_data.get("flagged_vendor_count") or 0
    harmless = parsed_data.get("harmless_count") or 0
    return (
        f"VirusTotal reported {flagged} security vendor flag(s) and {harmless} harmless result(s) for {target}."
    )


def _build_findings(parsed_data: dict[str, Any]) -> list[str]:
    target = parsed_data.get("target") or "target"
    if parsed_data.get("private_local_ip"):
        return [PRIVATE_IP_MESSAGE]
    stats = parsed_data.get("last_analysis_stats") or {}
    if not stats:
        return [f"VirusTotal lookup completed for {target}."]
    return [
        (
            f"VirusTotal stats for {target}: malicious={stats.get('malicious', 0)}, "
            f"suspicious={stats.get('suspicious', 0)}, harmless={stats.get('harmless', 0)}, "
            f"undetected={stats.get('undetected', 0)}."
        )
    ]


def _build_raw_output(parsed_data: dict[str, Any]) -> str:
    target = parsed_data.get("target") or "target"
    target_type = parsed_data.get("target_type") or "unknown"
    lines = [f"VirusTotal lookup: {target_type}={target}"]
    if parsed_data.get("private_local_ip"):
        lines.append(PRIVATE_IP_MESSAGE)
        return redact_secrets_from_text("\n".join(lines))

    lines.append(f"resource_id={parsed_data.get('resource_id') or 'n/a'}")
    if parsed_data.get("api", {}).get("error"):
        lines.append(f"error={parsed_data['api']['error']}")
    stats = parsed_data.get("last_analysis_stats") or {}
    if stats:
        lines.append(
            "stats="
            + ", ".join(
                f"{key}={stats.get(key, 0)}"
                for key in ("malicious", "suspicious", "harmless", "undetected", "timeout")
            )
        )
    if parsed_data.get("reputation") is not None:
        lines.append(f"reputation={parsed_data['reputation']}")
    if parsed_data.get("last_analysis_date_label"):
        lines.append(f"last_analysis_date={parsed_data['last_analysis_date_label']}")
    return redact_secrets_from_text("\n".join(lines))


def _private_ip_result(cleaned: str, resolved_type: str) -> dict[str, Any]:
    parsed_data = {
        "target": cleaned,
        "target_type": resolved_type,
        "private_local_ip": True,
        "last_analysis_stats": {},
        "api": {"status_code": None, "skipped": "private_local_ip"},
    }
    return {
        "success": True,
        "status": STATUS_COMPLETED,
        "parsed_data": parsed_data,
        "raw_output": _build_raw_output(parsed_data),
        "findings": _build_findings(parsed_data),
        "warnings": [],
        "errors": [],
        "evidence": [
            {
                "title": "Private/local IP — no public reputation lookup",
                "summary": PRIVATE_IP_MESSAGE,
                "content_text": PRIVATE_IP_MESSAGE,
                "content_type": "text/plain",
                "source_name": "VirusTotal",
                "evidence_type": "system_generated",
                "reliability": "high",
                "collection_method": "policy_skip",
            }
        ],
    }


def _missing_key_result(cleaned: str, resolved_type: str) -> dict[str, Any]:
    parsed_data = {"target": cleaned, "target_type": resolved_type, "api": {"status_code": None, "error": MISSING_KEY_MESSAGE}}
    message = f"{MISSING_KEY_MESSAGE} Add VIRUSTOTAL_API_KEY to your local .env file."
    return {
        "success": False,
        "status": STATUS_BLOCKED,
        "parsed_data": parsed_data,
        "raw_output": redact_secrets_from_text(message),
        "findings": [],
        "warnings": [],
        "errors": [message],
        "evidence": [
            {
                "title": "VirusTotal API key not configured",
                "summary": message,
                "content_text": message,
                "content_type": "text/plain",
                "source_name": "VirusTotal",
                "evidence_type": "system_generated",
                "reliability": "high",
                "collection_method": "policy_skip",
            }
        ],
    }


def run_virustotal_lookup(
    target: str,
    *,
    api_key: str,
    target_type: str | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Query VirusTotal API v3 for an IPv4 address, domain, or URL."""
    options = options or {}
    cleaned, resolved_type = _normalise_target(target, target_type)

    if not cleaned:
        return {
            "success": False,
            "status": STATUS_BLOCKED,
            "errors": ["No target provided."],
            "parsed_data": {"target": cleaned, "target_type": resolved_type},
            "raw_output": "Error: no target provided.",
            "findings": [],
            "warnings": [],
            "evidence": [],
        }

    if resolved_type not in {"ipv4", "domain", "url"}:
        return {
            "success": False,
            "status": STATUS_BLOCKED,
            "errors": [f"Unsupported target type for VirusTotal: {resolved_type}"],
            "parsed_data": {"target": cleaned, "target_type": resolved_type},
            "raw_output": f"Error: unsupported target type: {resolved_type}",
            "findings": [],
            "warnings": [],
            "evidence": [],
        }

    if resolved_type == "ipv4" and is_private_or_local_ip(cleaned):
        return _private_ip_result(cleaned, resolved_type)

    if not api_key or not api_key.strip():
        return _missing_key_result(cleaned, resolved_type)

    if options.get("mock_response") is not None:
        payload = options["mock_response"]
        api_meta = {"status_code": 200, "path": "mock", "mock": True}
    else:
        payload, api_meta = _lookup_resource(api_key.strip(), cleaned, resolved_type)

    http_status, http_success, http_warnings, http_errors = _classify_http_status(api_meta.get("status_code"))
    parsed_data = parse_virustotal_response(cleaned, resolved_type, payload, api_meta)
    warnings = list(http_warnings)
    errors = list(http_errors)

    if api_meta.get("error") and api_meta.get("status_code") not in {400, 404, 429}:
        if api_meta["status_code"] not in {401, 403}:
            warnings.append(f"VirusTotal API note: {api_meta['error']}")

    if resolved_type == "url" and api_meta.get("status_code") == 200 and not parsed_data.get("last_analysis_stats"):
        warnings.append("URL may still be queued for analysis — stats can appear on a later lookup.")

    has_core_data = bool(parsed_data.get("last_analysis_stats")) or bool(parsed_data.get("resource_id"))
    if http_status in {STATUS_BLOCKED, STATUS_ERROR} and not has_core_data:
        status = http_status
        success = http_success
    else:
        status = resolve_collection_status(warnings=warnings, errors=errors, has_core_data=has_core_data)
        success = status in {STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_PARTIAL}

    evidence = [
        {
            "title": "VirusTotal response summary",
            "summary": "Parsed VirusTotal reputation summary (API key redacted).",
            "content_text": redact_secrets_from_text(
                json.dumps(
                    {
                        "target": parsed_data.get("target"),
                        "target_type": parsed_data.get("target_type"),
                        "last_analysis_stats": parsed_data.get("last_analysis_stats"),
                        "reputation": parsed_data.get("reputation"),
                        "last_analysis_date_label": parsed_data.get("last_analysis_date_label"),
                        "api_status": api_meta.get("status_code"),
                    },
                    indent=2,
                    default=str,
                )
            ),
            "content_type": "application/json",
            "source_name": "VirusTotal",
            "evidence_type": "third_party_source",
            "reliability": "medium",
            "collection_method": "api_reputation_lookup",
        }
    ]

    return {
        "success": success,
        "status": status,
        "parsed_data": parsed_data,
        "raw_output": _build_raw_output(parsed_data),
        "findings": _build_findings(parsed_data),
        "warnings": warnings,
        "errors": errors if not success and not has_core_data else [],
        "evidence": evidence,
    }

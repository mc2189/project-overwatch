"""VirusTotal threat intelligence lookup for Project Overwatch."""

from __future__ import annotations

import base64
import json
from typing import Any
from urllib.parse import quote

import requests

from utils.result_status import resolve_collection_status
from utils.target_detection import get_target_type

VT_API_BASE = "https://www.virustotal.com/api/v3"
REQUEST_TIMEOUT = 20


def _url_resource_id(url: str) -> str:
    return base64.urlsafe_b64encode(url.encode("utf-8")).decode("utf-8").strip("=")


def _vt_headers(api_key: str) -> dict[str, str]:
    return {"x-apikey": api_key, "Accept": "application/json"}


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
    http = session or requests
    url = f"{VT_API_BASE}/{path.lstrip('/')}"
    try:
        response = http.request(
            method,
            url,
            headers=_vt_headers(api_key),
            params=params,
            data=data,
            timeout=REQUEST_TIMEOUT,
        )
    except requests.RequestException as exc:
        return None, {"status_code": None, "error": str(exc), "path": path}

    meta: dict[str, Any] = {
        "status_code": response.status_code,
        "path": path,
    }
    try:
        payload = response.json()
    except ValueError:
        payload = None
        meta["error"] = response.text[:500] or f"HTTP {response.status_code}"

    if response.status_code >= 400:
        detail = ""
        if isinstance(payload, dict):
            detail = (payload.get("error") or {}).get("message") or json.dumps(payload)[:300]
        meta["error"] = detail or response.text[:300] or f"HTTP {response.status_code}"
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

    return {
        "target": target,
        "target_type": target_type,
        "resource_id": data.get("id"),
        "resource_type": data.get("type"),
        "last_analysis_stats": stats,
        "last_analysis_date": attributes.get("last_analysis_date"),
        "reputation": attributes.get("reputation"),
        "total_votes": attributes.get("total_votes") or {},
        "country": attributes.get("country"),
        "as_owner": attributes.get("as_owner"),
        "registrar": attributes.get("registrar"),
        "categories": attributes.get("categories") or {},
        "tags": attributes.get("tags") or [],
        "api": api_meta,
        "raw_response": payload,
    }


def _build_findings(parsed_data: dict[str, Any]) -> list[str]:
    stats = parsed_data.get("last_analysis_stats") or {}
    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    target = parsed_data.get("target") or "target"

    if parsed_data.get("api", {}).get("error"):
        return [f"VirusTotal lookup incomplete for {target}."]

    lines = [
        f"VirusTotal stats for {target}: malicious={malicious}, suspicious={suspicious}, "
        f"harmless={harmless}, undetected={undetected}."
    ]
    reputation = parsed_data.get("reputation")
    if isinstance(reputation, int):
        lines.append(f"Community reputation score: {reputation}.")
    return lines


def _build_raw_output(parsed_data: dict[str, Any]) -> str:
    stats = parsed_data.get("last_analysis_stats") or {}
    target = parsed_data.get("target") or "target"
    target_type = parsed_data.get("target_type") or "unknown"
    lines = [
        f"VirusTotal lookup: {target_type}={target}",
        f"resource_id={parsed_data.get('resource_id') or 'n/a'}",
    ]
    if parsed_data.get("api", {}).get("error"):
        lines.append(f"error={parsed_data['api']['error']}")
    else:
        lines.append(
            "stats="
            + ", ".join(f"{key}={stats.get(key, 0)}" for key in ("malicious", "suspicious", "harmless", "undetected"))
        )
        if parsed_data.get("reputation") is not None:
            lines.append(f"reputation={parsed_data['reputation']}")
    return "\n".join(lines)


def run_virustotal_lookup(
    target: str,
    *,
    api_key: str,
    target_type: str | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Query VirusTotal API v3 for an IPv4 address, domain, or URL."""
    options = options or {}
    cleaned = target.strip()
    resolved_type = target_type or get_target_type(cleaned)

    if not cleaned:
        return {
            "success": False,
            "errors": ["No target provided."],
            "parsed_data": {"target": cleaned, "target_type": resolved_type},
            "raw_output": "Error: no target provided.",
            "findings": [],
        }

    if resolved_type not in {"ipv4", "domain", "url"}:
        return {
            "success": False,
            "errors": [f"Unsupported target type for VirusTotal: {resolved_type}"],
            "parsed_data": {"target": cleaned, "target_type": resolved_type},
            "raw_output": f"Error: unsupported target type: {resolved_type}",
            "findings": [],
        }

    if not api_key:
        return {
            "success": False,
            "errors": ["VIRUSTOTAL_API_KEY is not configured."],
            "parsed_data": {"target": cleaned, "target_type": resolved_type},
            "raw_output": "Error: VIRUSTOTAL_API_KEY is not configured.",
            "findings": [],
        }

    if options.get("mock_response") is not None:
        payload = options["mock_response"]
        api_meta = {"status_code": 200, "path": "mock", "mock": True}
    else:
        payload, api_meta = _lookup_resource(api_key, cleaned, resolved_type)

    parsed_data = parse_virustotal_response(cleaned, resolved_type, payload, api_meta)
    findings = _build_findings(parsed_data)
    raw_output = _build_raw_output(parsed_data)
    warnings: list[str] = []

    if api_meta.get("error"):
        warnings.append(f"VirusTotal API limitation: {api_meta['error']}")
    if resolved_type == "url" and api_meta.get("status_code") == 200 and not parsed_data.get("last_analysis_stats"):
        warnings.append("URL may still be queued for analysis — stats can appear on a later lookup.")

    has_core_data = bool(parsed_data.get("last_analysis_stats")) or bool(parsed_data.get("resource_id"))
    status = resolve_collection_status(warnings=warnings, has_core_data=has_core_data)

    evidence = []
    if parsed_data.get("raw_response"):
        evidence.append(
            {
                "title": "VirusTotal raw API payload",
                "summary": "Module-declared evidence hint for the VirusTotal JSON response.",
                "content_text": json.dumps(parsed_data["raw_response"], indent=2, default=str),
                "content_type": "application/json",
                "source_name": "virustotal",
                "evidence_type": "third_party_source",
                "reliability": "medium",
                "collection_method": "api_lookup",
            }
        )

    return {
        "success": not api_meta.get("error") or has_core_data,
        "status": status,
        "parsed_data": parsed_data,
        "raw_output": raw_output,
        "findings": findings,
        "warnings": warnings,
        "errors": [api_meta["error"]] if api_meta.get("error") and not has_core_data else [],
        "evidence": evidence,
    }

"""Shodan Internet Exposure Intelligence — passive host lookup for Project Overwatch."""

from __future__ import annotations

import json
from typing import Any

import requests

from utils.api_module_helpers import (
    classify_provider_http_status,
    missing_api_key_blocked_result,
    project_user_agent,
    redact_api_error_text,
    request_timeout_seconds,
    respect_api_courtesy_delay,
)
from utils.result_status import (
    STATUS_BLOCKED,
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_WARNINGS,
    STATUS_ERROR,
    STATUS_PARTIAL,
    resolve_collection_status,
)
from utils.security import is_private_or_local_ip, redact_secrets_from_dict, redact_secrets_from_text
from utils.target_detection import get_target_type, normalize_target_value

SHODAN_HOST_URL = "https://api.shodan.io/shodan/host/{ip}"
MODULE_ID = "intel_shodan"
PROVIDER_LABEL = "Shodan"
ENV_KEY_NAME = "SHODAN_API_KEY"
MISSING_KEY_MESSAGE = "Shodan API key is not configured."
PRIVATE_IP_MESSAGE = (
    "Private/local IP address — public Shodan internet-exposure lookup is not applicable."
)
MAX_SERVICE_SUMMARIES = 50


def _normalise_target(target: str, target_type: str | None = None) -> tuple[str, str]:
    cleaned = target.strip()
    resolved_type = target_type or get_target_type(cleaned)
    if resolved_type == "ipv4":
        cleaned = normalize_target_value(cleaned, "ipv4")
    return cleaned, resolved_type


def _extract_service_summary(entry: dict[str, Any]) -> dict[str, Any]:
    http = entry.get("http") if isinstance(entry.get("http"), dict) else {}
    shodan_meta = entry.get("_shodan") if isinstance(entry.get("_shodan"), dict) else {}
    return {
        "port": entry.get("port"),
        "transport": entry.get("transport") or "tcp",
        "product": entry.get("product"),
        "version": entry.get("version"),
        "timestamp": entry.get("timestamp"),
        "ssl_present": bool(entry.get("ssl")),
        "title": http.get("title"),
        "module": shodan_meta.get("module"),
    }


def _sanitize_raw_response(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    """Strip exploit/vulnerability detail before persistence — count only."""
    if not isinstance(payload, dict):
        return payload
    sanitized = dict(payload)
    vulns = sanitized.pop("vulns", None)
    if vulns is not None:
        if isinstance(vulns, dict):
            sanitized["vulnerability_count"] = len(vulns)
        elif isinstance(vulns, list):
            sanitized["vulnerability_count"] = len(vulns)
        else:
            sanitized["vulnerability_count"] = 0
    data = sanitized.get("data")
    if isinstance(data, list) and len(data) > MAX_SERVICE_SUMMARIES:
        sanitized["data"] = data[:MAX_SERVICE_SUMMARIES]
        sanitized["data_truncated"] = True
    return redact_secrets_from_dict(sanitized)


def _vulnerability_count(payload: dict[str, Any] | None) -> int:
    if not isinstance(payload, dict):
        return 0
    vulns = payload.get("vulns")
    if isinstance(vulns, dict):
        return len(vulns)
    if isinstance(vulns, list):
        return len(vulns)
    return 0


def parse_shodan_response(
    target: str,
    payload: dict[str, Any] | None,
    api_meta: dict[str, Any],
) -> dict[str, Any]:
    """Normalise a Shodan host API payload into structured parsed data."""
    data = payload or {}
    services_raw = data.get("data") if isinstance(data.get("data"), list) else []
    services = [_extract_service_summary(item) for item in services_raw if isinstance(item, dict)]
    ports = data.get("ports") if isinstance(data.get("ports"), list) else []
    port_numbers = [int(port) for port in ports if isinstance(port, int)]
    if not port_numbers and services:
        port_numbers = [int(item["port"]) for item in services if isinstance(item.get("port"), int)]

    asn_value = data.get("asn")
    if asn_value not in (None, "") and not str(asn_value).upper().startswith("AS"):
        asn_value = f"AS{asn_value}"

    return {
        "target": target,
        "target_type": "ipv4",
        "ip_address": data.get("ip_str") or target,
        "organisation": data.get("org"),
        "isp": data.get("isp"),
        "asn": asn_value,
        "country_name": data.get("country_name"),
        "country_code": data.get("country_code"),
        "city": data.get("city"),
        "hostnames": data.get("hostnames") or [],
        "domains": data.get("domains") or [],
        "ports": port_numbers,
        "service_count": len(services) or len(port_numbers),
        "services": services[:MAX_SERVICE_SUMMARIES],
        "tags": data.get("tags") or [],
        "last_update": data.get("last_update"),
        "vulnerability_count": _vulnerability_count(data),
        "private_local_ip": False,
        "api": api_meta,
        "raw_response": _sanitize_raw_response(payload),
    }


def _request_host(
    api_key: str,
    ip_address: str,
    *,
    session: requests.Session | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Query Shodan host endpoint (lookup-only — no scan/search/exploit APIs)."""
    respect_api_courtesy_delay()
    http = session or requests
    meta: dict[str, Any] = {"status_code": None, "endpoint": "shodan/host"}
    url = SHODAN_HOST_URL.format(ip=ip_address)
    try:
        response = http.get(
            url,
            params={"key": api_key},
            headers={"User-Agent": project_user_agent(), "Accept": "application/json"},
            timeout=request_timeout_seconds(),
        )
    except requests.Timeout:
        meta["error"] = "Shodan request timed out."
        return None, meta
    except requests.RequestException as exc:
        meta["error"] = redact_api_error_text(str(exc))
        return None, meta

    meta["status_code"] = response.status_code
    try:
        payload = response.json()
    except ValueError:
        payload = None
        meta["error"] = redact_api_error_text(response.text[:500] or f"HTTP {response.status_code}")

    if response.status_code >= 400:
        detail = ""
        if isinstance(payload, dict):
            detail = str(payload.get("error") or json.dumps(payload)[:300])
        meta["error"] = redact_api_error_text(detail or response.text[:300] or f"HTTP {response.status_code}")
        return payload if isinstance(payload, dict) else None, meta

    return payload if isinstance(payload, dict) else None, meta


def _build_summary(parsed_data: dict[str, Any]) -> str:
    if parsed_data.get("private_local_ip"):
        return PRIVATE_IP_MESSAGE
    target = parsed_data.get("ip_address") or parsed_data.get("target") or "target"
    api = parsed_data.get("api") or {}
    if api.get("error") == MISSING_KEY_MESSAGE:
        return MISSING_KEY_MESSAGE
    if api.get("status_code") in {401, 403}:
        return MISSING_KEY_MESSAGE
    service_count = parsed_data.get("service_count") or 0
    if service_count == 0 and api.get("status_code") in {400, 404, None}:
        return f"Shodan returned no prior internet-exposure host data for {target}."
    org = parsed_data.get("organisation") or parsed_data.get("isp")
    org_text = f" ({org})" if org else ""
    return (
        f"Shodan reported {service_count} prior service(s) for {target}{org_text}. "
        "Data may be stale — reported by Shodan, not locally verified."
    )


def _build_findings(parsed_data: dict[str, Any]) -> list[str]:
    target = parsed_data.get("ip_address") or parsed_data.get("target") or "target"
    if parsed_data.get("private_local_ip"):
        return [PRIVATE_IP_MESSAGE]
    service_count = parsed_data.get("service_count") or 0
    ports = parsed_data.get("ports") or []
    port_text = ", ".join(str(port) for port in ports[:20]) if ports else "none"
    return [
        (
            f"Shodan exposure summary for {target}: services={service_count}, "
            f"ports={port_text}, vuln_refs={parsed_data.get('vulnerability_count', 0)}."
        )
    ]


def _build_raw_output(parsed_data: dict[str, Any]) -> str:
    target = parsed_data.get("ip_address") or parsed_data.get("target") or "target"
    lines = [f"Shodan host lookup: ipv4={target}"]
    if parsed_data.get("private_local_ip"):
        lines.append(PRIVATE_IP_MESSAGE)
        return redact_secrets_from_text("\n".join(lines))

    api = parsed_data.get("api") or {}
    if api.get("error"):
        lines.append(f"error={api['error']}")
    if parsed_data.get("organisation"):
        lines.append(f"org={parsed_data['organisation']}")
    if parsed_data.get("isp"):
        lines.append(f"isp={parsed_data['isp']}")
    if parsed_data.get("asn"):
        lines.append(f"asn={parsed_data['asn']}")
    if parsed_data.get("country_name"):
        lines.append(f"country={parsed_data['country_name']}")
    if parsed_data.get("city"):
        lines.append(f"city={parsed_data['city']}")
    if parsed_data.get("hostnames"):
        lines.append(f"hostnames={', '.join(str(item) for item in parsed_data['hostnames'][:10])}")
    if parsed_data.get("service_count") is not None:
        lines.append(f"service_count={parsed_data['service_count']}")
    if parsed_data.get("ports"):
        lines.append(f"ports={', '.join(str(port) for port in parsed_data['ports'][:30])}")
    if parsed_data.get("last_update"):
        lines.append(f"last_update={parsed_data['last_update']}")
    if parsed_data.get("vulnerability_count"):
        lines.append(f"vulnerability_count={parsed_data['vulnerability_count']}")
    return redact_secrets_from_text("\n".join(lines))


def _private_ip_result(cleaned: str, resolved_type: str) -> dict[str, Any]:
    parsed_data = {
        "target": cleaned,
        "target_type": resolved_type,
        "ip_address": cleaned,
        "private_local_ip": True,
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
                "title": "Private/local IP — no public Shodan lookup",
                "summary": PRIVATE_IP_MESSAGE,
                "content_text": PRIVATE_IP_MESSAGE,
                "content_type": "text/plain",
                "source_name": PROVIDER_LABEL,
                "evidence_type": "system_generated",
                "reliability": "high",
                "collection_method": "policy_skip",
            }
        ],
    }


def _unsupported_target_result(cleaned: str, resolved_type: str) -> dict[str, Any]:
    # TODO: optional future enrichment from known case IP entities for domain/url targets.
    message = (
        f"Unsupported target type for Shodan: {resolved_type}. "
        "Only public IPv4 addresses are supported in v2.5."
    )
    return {
        "success": False,
        "status": STATUS_BLOCKED,
        "errors": [message],
        "parsed_data": {"target": cleaned, "target_type": resolved_type},
        "raw_output": redact_secrets_from_text(message),
        "findings": [],
        "warnings": [],
        "evidence": [],
    }


def run_shodan_lookup(
    target: str,
    *,
    api_key: str,
    target_type: str | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Query Shodan host API for a public IPv4 address (lookup-only)."""
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

    if resolved_type != "ipv4":
        return _unsupported_target_result(cleaned, resolved_type)

    if is_private_or_local_ip(cleaned):
        return _private_ip_result(cleaned, resolved_type)

    if not api_key or not api_key.strip():
        blocked = missing_api_key_blocked_result(
            module_id=MODULE_ID,
            env_key_name=ENV_KEY_NAME,
            provider_label=PROVIDER_LABEL,
            target=cleaned,
            target_type=resolved_type,
            message=MISSING_KEY_MESSAGE,
        )
        blocked["parsed_data"]["ip_address"] = cleaned
        blocked["parsed_data"]["api"] = {"status_code": None, "error": MISSING_KEY_MESSAGE}
        return blocked

    if options.get("mock_response") is not None:
        payload = options["mock_response"]
        api_meta = {"status_code": 200, "endpoint": "shodan/host", "mock": True}
    else:
        payload, api_meta = _request_host(api_key.strip(), cleaned)

    http_status, http_success, http_warnings, http_errors = classify_provider_http_status(
        api_meta.get("status_code")
    )
    if api_meta.get("status_code") == 404:
        http_status = STATUS_COMPLETED
        http_success = True
        http_warnings = ["Shodan returned no host data for this IP address."]
        http_errors = []

    parsed_data = parse_shodan_response(cleaned, payload, api_meta)
    warnings = list(http_warnings)
    errors = list(http_errors)

    if api_meta.get("error") and api_meta.get("status_code") not in {400, 404, 429}:
        if api_meta.get("status_code") not in {401, 403}:
            warnings.append(f"Shodan API note: {api_meta['error']}")

    has_core_data = bool(
        parsed_data.get("service_count")
        or parsed_data.get("ports")
        or parsed_data.get("organisation")
        or parsed_data.get("isp")
    )
    if http_status in {STATUS_BLOCKED, STATUS_ERROR} and not has_core_data:
        status = http_status
        success = http_success
    else:
        status = resolve_collection_status(warnings=warnings, errors=errors, has_core_data=has_core_data)
        success = status in {STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_PARTIAL}

    evidence = [
        {
            "title": "Shodan exposure summary",
            "summary": "Parsed Shodan host exposure summary (API key and vulnerability detail redacted).",
            "content_text": redact_secrets_from_text(
                json.dumps(
                    {
                        "target": parsed_data.get("target"),
                        "ip_address": parsed_data.get("ip_address"),
                        "organisation": parsed_data.get("organisation"),
                        "isp": parsed_data.get("isp"),
                        "asn": parsed_data.get("asn"),
                        "country_name": parsed_data.get("country_name"),
                        "city": parsed_data.get("city"),
                        "hostnames": parsed_data.get("hostnames"),
                        "domains": parsed_data.get("domains"),
                        "service_count": parsed_data.get("service_count"),
                        "ports": parsed_data.get("ports"),
                        "last_update": parsed_data.get("last_update"),
                        "vulnerability_count": parsed_data.get("vulnerability_count"),
                        "api_status": api_meta.get("status_code"),
                    },
                    indent=2,
                    default=str,
                )
            ),
            "content_type": "application/json",
            "source_name": PROVIDER_LABEL,
            "evidence_type": "third_party_source",
            "reliability": "medium",
            "collection_method": "api_exposure_lookup",
        }
    ]
    if parsed_data.get("services"):
        evidence.append(
            {
                "title": "Shodan reported services summary",
                "summary": "Condensed service/port summaries reported by Shodan (no exploit detail).",
                "content_text": redact_secrets_from_text(
                    json.dumps(parsed_data.get("services")[:25], indent=2, default=str)
                ),
                "content_type": "application/json",
                "source_name": PROVIDER_LABEL,
                "evidence_type": "third_party_source",
                "reliability": "medium",
                "collection_method": "api_exposure_lookup",
            }
        )

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

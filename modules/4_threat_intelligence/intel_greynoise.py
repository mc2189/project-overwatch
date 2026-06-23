"""GreyNoise Internet Noise Intelligence — passive community lookup for Project Overwatch."""

from __future__ import annotations

import json
from typing import Any

import requests

from utils.api_module_helpers import (
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
from utils.security import is_private_or_local_ip, redact_secrets_from_text
from utils.target_detection import get_target_type, normalize_target_value

GREYNOISE_COMMUNITY_URL = "https://api.greynoise.io/v3/community/{ip}"
MODULE_ID = "intel_greynoise"
PROVIDER_LABEL = "GreyNoise"
ENV_KEY_NAME = "GREYNOISE_API_KEY"
MISSING_KEY_WARNING = (
    "GreyNoise API key is not configured. Community lookup may be limited or unavailable."
)
PRIVATE_IP_MESSAGE = (
    "Private/local IP address — public GreyNoise internet-noise lookup is not applicable."
)


def _normalise_target(target: str, target_type: str | None = None) -> tuple[str, str]:
    cleaned = target.strip()
    resolved_type = target_type or get_target_type(cleaned)
    if resolved_type == "ipv4":
        cleaned = normalize_target_value(cleaned, "ipv4")
    return cleaned, resolved_type


def _greynoise_headers(api_key: str | None) -> dict[str, str]:
    headers = {
        "Accept": "application/json",
        "User-Agent": project_user_agent(),
    }
    if api_key and api_key.strip():
        headers["key"] = api_key.strip()
    return headers


def _classify_greynoise_status(
    status_code: int | None,
    *,
    has_api_key: bool,
    payload: dict[str, Any] | None = None,
) -> tuple[str, bool, list[str], list[str]]:
    if status_code is None:
        return STATUS_ERROR, False, [], ["GreyNoise request failed before a response was received."]
    if status_code == 200:
        return STATUS_COMPLETED, True, [], []
    if status_code == 404 and isinstance(payload, dict) and payload.get("ip"):
        return STATUS_COMPLETED, True, [], []
    if status_code == 400:
        return STATUS_COMPLETED, True, ["GreyNoise rejected the request for this IP address."], []
    if status_code in {401, 403}:
        if has_api_key:
            return (
                STATUS_BLOCKED,
                False,
                [],
                ["GreyNoise rejected the API key (unauthorised). Check GREYNOISE_API_KEY in your local .env file."],
            )
        return STATUS_COMPLETED_WITH_WARNINGS, True, [MISSING_KEY_WARNING], []
    if status_code == 429:
        return (
            STATUS_COMPLETED_WITH_WARNINGS,
            True,
            ["GreyNoise rate limit reached — retry later or reduce batch frequency."],
            [],
        )
    if status_code and status_code >= 500:
        return STATUS_ERROR, False, [], [f"GreyNoise provider error (HTTP {status_code}). Retry later."]
    return STATUS_PARTIAL, False, [], [f"Unexpected GreyNoise response (HTTP {status_code})."]


def _request_community_lookup(
    ip_address: str,
    api_key: str | None,
    *,
    session: requests.Session | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Query GreyNoise v3 Community API (lookup-only)."""
    respect_api_courtesy_delay()
    http = session or requests
    url = GREYNOISE_COMMUNITY_URL.format(ip=ip_address)
    meta: dict[str, Any] = {
        "status_code": None,
        "endpoint": "community",
        "authenticated": bool(api_key and api_key.strip()),
    }
    try:
        response = http.get(
            url,
            headers=_greynoise_headers(api_key),
            timeout=request_timeout_seconds(),
        )
    except requests.Timeout:
        meta["error"] = "GreyNoise request timed out."
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

    if response.status_code >= 400 and not (
        response.status_code == 404 and isinstance(payload, dict) and payload.get("ip")
    ):
        detail = ""
        if isinstance(payload, dict):
            detail = str(payload.get("message") or json.dumps(payload)[:300])
        meta["error"] = redact_api_error_text(detail or response.text[:300] or f"HTTP {response.status_code}")
        return payload if isinstance(payload, dict) else None, meta

    return payload if isinstance(payload, dict) else None, meta


def parse_greynoise_response(
    target: str,
    payload: dict[str, Any] | None,
    api_meta: dict[str, Any],
) -> dict[str, Any]:
    """Normalise a GreyNoise Community API payload into structured parsed data."""
    data = payload or {}
    return {
        "target": target,
        "target_type": "ipv4",
        "ip_address": data.get("ip") or target,
        "noise": data.get("noise"),
        "riot": data.get("riot"),
        "classification": data.get("classification"),
        "name": data.get("name"),
        "link": data.get("link"),
        "last_seen": data.get("last_seen"),
        "message": data.get("message"),
        "private_local_ip": False,
        "api": api_meta,
        "raw_response": payload,
    }


def _build_summary(parsed_data: dict[str, Any]) -> str:
    if parsed_data.get("private_local_ip"):
        return PRIVATE_IP_MESSAGE
    target = parsed_data.get("ip_address") or parsed_data.get("target") or "target"
    if parsed_data.get("riot"):
        name = parsed_data.get("name") or "common business service"
        return f"GreyNoise reported {target} in RIOT data as {name}."
    if parsed_data.get("noise"):
        classification = parsed_data.get("classification") or "unknown"
        return f"GreyNoise reported {target} as internet noise (classification: {classification})."
    if parsed_data.get("message"):
        return f"GreyNoise community lookup for {target}: {parsed_data['message']}"
    return f"GreyNoise returned no internet-noise or RIOT data for {target}."


def _build_findings(parsed_data: dict[str, Any]) -> list[str]:
    target = parsed_data.get("ip_address") or parsed_data.get("target") or "target"
    if parsed_data.get("private_local_ip"):
        return [PRIVATE_IP_MESSAGE]
    bits = [
        f"noise={parsed_data.get('noise')}",
        f"riot={parsed_data.get('riot')}",
        f"classification={parsed_data.get('classification')}",
    ]
    return [f"GreyNoise stats for {target}: " + ", ".join(bits) + "."]


def _build_raw_output(parsed_data: dict[str, Any]) -> str:
    target = parsed_data.get("ip_address") or parsed_data.get("target") or "target"
    lines = [f"GreyNoise lookup: ipv4={target}"]
    if parsed_data.get("private_local_ip"):
        lines.append(PRIVATE_IP_MESSAGE)
        return redact_secrets_from_text("\n".join(lines))

    api = parsed_data.get("api") or {}
    if not api.get("authenticated"):
        lines.append("authenticated=false")
    if api.get("error"):
        lines.append(f"error={api['error']}")
    for field in ("noise", "riot", "classification", "name", "last_seen", "message"):
        value = parsed_data.get(field)
        if value is not None and value != "":
            lines.append(f"{field}={value}")
    if parsed_data.get("link"):
        lines.append(f"link={parsed_data['link']}")
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
                "title": "Private/local IP — no public GreyNoise lookup",
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
    message = (
        f"Unsupported target type for GreyNoise: {resolved_type}. "
        "Only public IPv4 addresses are supported."
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


def run_greynoise_lookup(
    target: str,
    *,
    api_key: str | None = None,
    target_type: str | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Query GreyNoise v3 Community API for a public IPv4 address (lookup-only)."""
    options = options or {}
    cleaned, resolved_type = _normalise_target(target, target_type)
    key_configured = bool(api_key and api_key.strip())

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

    warnings: list[str] = []
    if not key_configured:
        warnings.append(MISSING_KEY_WARNING)

    if options.get("mock_response") is not None:
        payload = options["mock_response"]
        api_meta = {"status_code": 200, "endpoint": "community", "mock": True, "authenticated": key_configured}
    else:
        payload, api_meta = _request_community_lookup(cleaned, api_key)

    http_status, http_success, http_warnings, http_errors = _classify_greynoise_status(
        api_meta.get("status_code"),
        has_api_key=key_configured,
        payload=payload,
    )
    warnings.extend(http_warnings)
    errors = list(http_errors)

    if api_meta.get("error") and api_meta.get("status_code") not in {200, 404, 400, 429}:
        if api_meta.get("status_code") not in {401, 403}:
            warnings.append(f"GreyNoise API note: {api_meta['error']}")

    parsed_data = parse_greynoise_response(cleaned, payload, api_meta)
    has_core_data = any(
        parsed_data.get(field) is not None
        for field in ("noise", "riot", "classification", "name", "message")
    )

    if http_status in {STATUS_BLOCKED, STATUS_ERROR} and not has_core_data:
        status = http_status
        success = http_success
    else:
        status = resolve_collection_status(warnings=warnings, errors=errors, has_core_data=has_core_data)
        success = status in {STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_PARTIAL}

    evidence = [
        {
            "title": "GreyNoise response summary",
            "summary": "Parsed GreyNoise community lookup summary (API key redacted).",
            "content_text": redact_secrets_from_text(
                json.dumps(
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
                        "api_status": api_meta.get("status_code"),
                        "authenticated": api_meta.get("authenticated"),
                    },
                    indent=2,
                    default=str,
                )
            ),
            "content_type": "application/json",
            "source_name": PROVIDER_LABEL,
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

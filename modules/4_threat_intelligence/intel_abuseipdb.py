"""AbuseIPDB Reputation Intelligence — passive abuse-confidence lookup for Project Overwatch."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

import requests

from utils.api_module_helpers import (
    api_key_header,
    classify_provider_http_status,
    missing_api_key_blocked_result,
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

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
MODULE_ID = "intel_abuseipdb"
PROVIDER_LABEL = "AbuseIPDB"
ENV_KEY_NAME = "ABUSEIPDB_API_KEY"
MISSING_KEY_MESSAGE = "AbuseIPDB API key is not configured."
PRIVATE_IP_MESSAGE = "Private/local IP address — public AbuseIPDB reputation lookup is not applicable."
DEFAULT_MAX_AGE_DAYS = 90


def _normalise_target(target: str, target_type: str | None = None) -> tuple[str, str]:
    cleaned = target.strip()
    resolved_type = target_type or get_target_type(cleaned)
    if resolved_type == "ipv4":
        cleaned = normalize_target_value(cleaned, "ipv4")
    return cleaned, resolved_type


def _format_reported_date(value: Any) -> str | None:
    if value in (None, ""):
        return None
    text = str(value).strip()
    try:
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return text


def _request_check(
    api_key: str,
    ip_address: str,
    *,
    max_age_days: int = DEFAULT_MAX_AGE_DAYS,
    session: requests.Session | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Query AbuseIPDB check endpoint (lookup-only — no report/submission)."""
    respect_api_courtesy_delay()
    http = session or requests
    meta: dict[str, Any] = {"status_code": None, "endpoint": "check"}
    try:
        response = http.get(
            ABUSEIPDB_CHECK_URL,
            headers=api_key_header(api_key, header_name="Key"),
            params={"ipAddress": ip_address, "maxAgeInDays": max_age_days},
            timeout=request_timeout_seconds(),
        )
    except requests.Timeout:
        meta["error"] = "AbuseIPDB request timed out."
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
            errors = payload.get("errors")
            if isinstance(errors, list) and errors:
                detail = "; ".join(str(item.get("detail") or item) for item in errors if item)
            elif payload.get("message"):
                detail = str(payload["message"])
            else:
                detail = json.dumps(payload)[:300]
        meta["error"] = redact_api_error_text(detail or response.text[:300] or f"HTTP {response.status_code}")
        return payload if isinstance(payload, dict) else None, meta

    return payload if isinstance(payload, dict) else None, meta


def parse_abuseipdb_response(
    target: str,
    payload: dict[str, Any] | None,
    api_meta: dict[str, Any],
) -> dict[str, Any]:
    """Normalise an AbuseIPDB check response into structured parsed data."""
    data = (payload or {}).get("data") or {}
    return {
        "target": target,
        "target_type": "ipv4",
        "ip_address": data.get("ipAddress") or target,
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "total_reports": data.get("totalReports"),
        "num_distinct_users": data.get("numDistinctUsers"),
        "country_code": data.get("countryCode"),
        "country_name": data.get("countryName"),
        "isp": data.get("isp"),
        "domain": data.get("domain"),
        "usage_type": data.get("usageType"),
        "is_whitelisted": data.get("isWhitelisted"),
        "last_reported_at": data.get("lastReportedAt"),
        "last_reported_label": _format_reported_date(data.get("lastReportedAt")),
        "hostnames": data.get("hostnames") or [],
        "is_public": data.get("isPublic"),
        "private_local_ip": False,
        "api": api_meta,
        "raw_response": payload,
    }


def _build_summary(parsed_data: dict[str, Any]) -> str:
    if parsed_data.get("private_local_ip"):
        return PRIVATE_IP_MESSAGE
    target = parsed_data.get("ip_address") or parsed_data.get("target") or "target"
    api = parsed_data.get("api") or {}
    if api.get("status_code") in {401, 403}:
        return MISSING_KEY_MESSAGE
    if api.get("error") == MISSING_KEY_MESSAGE:
        return MISSING_KEY_MESSAGE
    score = parsed_data.get("abuse_confidence_score")
    reports = parsed_data.get("total_reports")
    if score is None and reports is None and api.get("status_code") not in {200, 429}:
        return f"AbuseIPDB did not return reputation data for {target}."
    score_text = score if score is not None else "n/a"
    reports_text = reports if reports is not None else "n/a"
    return (
        f"AbuseIPDB reported abuse confidence {score_text} with {reports_text} total report(s) for {target}."
    )


def _build_findings(parsed_data: dict[str, Any]) -> list[str]:
    target = parsed_data.get("ip_address") or parsed_data.get("target") or "target"
    if parsed_data.get("private_local_ip"):
        return [PRIVATE_IP_MESSAGE]
    score = parsed_data.get("abuse_confidence_score")
    reports = parsed_data.get("total_reports")
    if score is None and reports is None:
        return [f"AbuseIPDB lookup completed for {target}."]
    return [
        (
            f"AbuseIPDB stats for {target}: abuse_confidence_score={score}, "
            f"total_reports={reports}, distinct_users={parsed_data.get('num_distinct_users')}."
        )
    ]


def _build_raw_output(parsed_data: dict[str, Any]) -> str:
    target = parsed_data.get("ip_address") or parsed_data.get("target") or "target"
    lines = [f"AbuseIPDB lookup: ipv4={target}"]
    if parsed_data.get("private_local_ip"):
        lines.append(PRIVATE_IP_MESSAGE)
        return redact_secrets_from_text("\n".join(lines))

    api = parsed_data.get("api") or {}
    if api.get("error"):
        lines.append(f"error={api['error']}")
    if parsed_data.get("abuse_confidence_score") is not None:
        lines.append(f"abuse_confidence_score={parsed_data['abuse_confidence_score']}")
    if parsed_data.get("total_reports") is not None:
        lines.append(f"total_reports={parsed_data['total_reports']}")
    if parsed_data.get("num_distinct_users") is not None:
        lines.append(f"num_distinct_users={parsed_data['num_distinct_users']}")
    if parsed_data.get("country_code"):
        lines.append(f"country={parsed_data.get('country_code')}")
    if parsed_data.get("isp"):
        lines.append(f"isp={parsed_data['isp']}")
    if parsed_data.get("usage_type"):
        lines.append(f"usage_type={parsed_data['usage_type']}")
    if parsed_data.get("last_reported_label"):
        lines.append(f"last_reported={parsed_data['last_reported_label']}")
    if parsed_data.get("is_whitelisted") is not None:
        lines.append(f"is_whitelisted={parsed_data['is_whitelisted']}")
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
                "title": "Private/local IP — no public AbuseIPDB lookup",
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
    message = f"Unsupported target type for AbuseIPDB: {resolved_type}. Only public IPv4 addresses are supported."
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


def run_abuseipdb_lookup(
    target: str,
    *,
    api_key: str,
    target_type: str | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Query AbuseIPDB check API for a public IPv4 address (lookup-only)."""
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
        return blocked

    if options.get("mock_response") is not None:
        payload = options["mock_response"]
        api_meta = {"status_code": 200, "endpoint": "check", "mock": True}
    else:
        payload, api_meta = _request_check(api_key.strip(), cleaned)

    http_status, http_success, http_warnings, http_errors = classify_provider_http_status(
        api_meta.get("status_code")
    )
    if api_meta.get("status_code") == 422:
        http_status = STATUS_COMPLETED
        http_success = True
        http_warnings = ["AbuseIPDB rejected the request parameters for this IP."]
        http_errors = []

    parsed_data = parse_abuseipdb_response(cleaned, payload, api_meta)
    warnings = list(http_warnings)
    errors = list(http_errors)

    if api_meta.get("error") and api_meta.get("status_code") not in {400, 404, 422, 429}:
        if api_meta.get("status_code") not in {401, 403}:
            warnings.append(f"AbuseIPDB API note: {api_meta['error']}")

    has_core_data = any(
        parsed_data.get(field) is not None
        for field in ("abuse_confidence_score", "total_reports", "num_distinct_users")
    )
    if http_status in {STATUS_BLOCKED, STATUS_ERROR} and not has_core_data:
        status = http_status
        success = http_success
    else:
        status = resolve_collection_status(warnings=warnings, errors=errors, has_core_data=has_core_data)
        success = status in {STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_PARTIAL}

    evidence = [
        {
            "title": "AbuseIPDB response summary",
            "summary": "Parsed AbuseIPDB abuse-confidence summary (API key redacted).",
            "content_text": redact_secrets_from_text(
                json.dumps(
                    {
                        "target": parsed_data.get("target"),
                        "ip_address": parsed_data.get("ip_address"),
                        "abuse_confidence_score": parsed_data.get("abuse_confidence_score"),
                        "total_reports": parsed_data.get("total_reports"),
                        "num_distinct_users": parsed_data.get("num_distinct_users"),
                        "country_code": parsed_data.get("country_code"),
                        "isp": parsed_data.get("isp"),
                        "usage_type": parsed_data.get("usage_type"),
                        "last_reported_label": parsed_data.get("last_reported_label"),
                        "is_whitelisted": parsed_data.get("is_whitelisted"),
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

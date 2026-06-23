"""URLhaus Malware URL Intelligence — passive abuse.ch lookup for Project Overwatch."""

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
from utils.settings_manager import get_urlhaus_auth_key
from utils.target_detection import get_target_type, normalize_target_value

URLHAUS_URL_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/url/"
URLHAUS_HOST_ENDPOINT = "https://urlhaus-api.abuse.ch/v1/host/"
MODULE_ID = "intel_urlhaus"
PROVIDER_LABEL = "URLhaus"
ENV_KEY_NAME = "ABUSECH_AUTH_KEY"
MISSING_KEY_MESSAGE = "URLhaus / abuse.ch Auth-Key is not configured."
PRIVATE_IP_MESSAGE = (
    "Private/local IP address — public URLhaus malware URL lookup is not applicable."
)
MAX_DISPLAY_URLS = 20
MAX_URL_ENTITIES = 50
MAX_STORE_URLS = 100


def _normalise_url_for_lookup(value: str) -> str:
    """Preserve scheme/path for URLhaus URL endpoint lookups."""
    cleaned = value.strip()
    if not cleaned:
        return cleaned
    if "://" not in cleaned:
        return f"http://{cleaned}"
    return cleaned


def _normalise_target(target: str, target_type: str | None = None) -> tuple[str, str]:
    cleaned = target.strip()
    resolved_type = target_type or get_target_type(cleaned)
    if resolved_type == "ipv4":
        cleaned = normalize_target_value(cleaned, "ipv4")
    elif resolved_type == "domain":
        cleaned = normalize_target_value(cleaned, "domain")
    elif resolved_type == "url":
        cleaned = _normalise_url_for_lookup(cleaned)
    return cleaned, resolved_type


def _auth_headers(auth_key: str) -> dict[str, str]:
    return {
        "Auth-Key": auth_key,
        "User-Agent": project_user_agent(),
        "Accept": "application/json",
    }


def _strip_download_fields(value: Any) -> Any:
    """Remove malware download links from payload structures before persistence."""
    if isinstance(value, dict):
        cleaned = {key: _strip_download_fields(item) for key, item in value.items()}
        cleaned.pop("urlhaus_download", None)
        return cleaned
    if isinstance(value, list):
        return [_strip_download_fields(item) for item in value]
    return value


def _payload_hash_summaries(payloads: list[Any] | None) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    for item in payloads or []:
        if not isinstance(item, dict):
            continue
        summaries.append(
            {
                "filename": item.get("filename"),
                "file_type": item.get("file_type"),
                "response_size": item.get("response_size"),
                "sha256_hash": item.get("sha256_hash") or item.get("sha256"),
                "md5_hash": item.get("md5_hash") or item.get("md5"),
                "signature": item.get("signature"),
                "virustotal_percent": (item.get("virustotal") or {}).get("percent")
                if isinstance(item.get("virustotal"), dict)
                else None,
            }
        )
    return summaries


def _blacklist_summary(blacklists: Any) -> dict[str, str]:
    if not isinstance(blacklists, dict):
        return {}
    return {str(key): str(value) for key, value in blacklists.items()}


def _summarise_url_entry(entry: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": entry.get("id"),
        "url": entry.get("url"),
        "url_status": entry.get("url_status"),
        "host": entry.get("host"),
        "date_added": entry.get("date_added"),
        "last_online": entry.get("last_online"),
        "threat": entry.get("threat"),
        "tags": entry.get("tags") or [],
        "blacklists": _blacklist_summary(entry.get("blacklists")),
        "urlhaus_reference": entry.get("urlhaus_reference"),
        "reporter": entry.get("reporter"),
        "larted": entry.get("larted"),
        "payload_count": len(entry.get("payloads") or []) if isinstance(entry.get("payloads"), list) else 0,
        "payload_hashes": _payload_hash_summaries(entry.get("payloads") if isinstance(entry.get("payloads"), list) else []),
        "virustotal": entry.get("virustotal"),
    }


def _count_url_statuses(urls: list[dict[str, Any]]) -> dict[str, int]:
    counts = {"online": 0, "offline": 0, "unknown": 0}
    for item in urls:
        status = str(item.get("url_status") or "unknown").lower()
        if status in counts:
            counts[status] += 1
        else:
            counts["unknown"] += 1
    return counts


def _sanitize_raw_response(payload: dict[str, Any] | None) -> dict[str, Any] | None:
    if not isinstance(payload, dict):
        return payload
    sanitized = _strip_download_fields(dict(payload))
    urls = sanitized.get("urls")
    if isinstance(urls, list) and len(urls) > MAX_STORE_URLS:
        sanitized["urls"] = urls[:MAX_STORE_URLS]
        sanitized["urls_truncated"] = True
    return redact_secrets_from_dict(sanitized)


def _request_urlhaus(
    endpoint: str,
    form_data: dict[str, str],
    auth_key: str,
    *,
    session: requests.Session | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """POST to a URLhaus v1 lookup endpoint (lookup-only)."""
    respect_api_courtesy_delay()
    http = session or requests
    endpoint_name = "url" if endpoint.rstrip("/").endswith("/url") else "host"
    meta: dict[str, Any] = {"status_code": None, "endpoint": endpoint_name}
    try:
        response = http.post(
            endpoint,
            data=form_data,
            headers=_auth_headers(auth_key),
            timeout=request_timeout_seconds(),
        )
    except requests.Timeout:
        meta["error"] = "URLhaus request timed out."
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
            detail = str(payload.get("query_status") or payload.get("error") or json.dumps(payload)[:300])
        meta["error"] = redact_api_error_text(detail or response.text[:300] or f"HTTP {response.status_code}")
        return payload if isinstance(payload, dict) else None, meta

    return payload if isinstance(payload, dict) else None, meta


def parse_urlhaus_url_response(
    target: str,
    target_type: str,
    payload: dict[str, Any] | None,
    api_meta: dict[str, Any],
) -> dict[str, Any]:
    data = payload or {}
    query_status = str(data.get("query_status") or "").lower()
    tags = data.get("tags") if isinstance(data.get("tags"), list) else []
    signatures = [tag for tag in tags if isinstance(tag, str)]
    return {
        "target": target,
        "target_type": target_type,
        "lookup_type": "url",
        "lookup_value": data.get("url") or target,
        "query_status": query_status,
        "urlhaus_id": data.get("id"),
        "urlhaus_reference": data.get("urlhaus_reference"),
        "url_status": data.get("url_status"),
        "host": data.get("host"),
        "date_added": data.get("date_added"),
        "last_online": data.get("last_online"),
        "threat": data.get("threat"),
        "blacklist_summary": _blacklist_summary(data.get("blacklists")),
        "tags": tags,
        "signatures": signatures,
        "reporter": data.get("reporter"),
        "larted": data.get("larted"),
        "payload_count": len(data.get("payloads") or []) if isinstance(data.get("payloads"), list) else 0,
        "payload_hashes": _payload_hash_summaries(data.get("payloads") if isinstance(data.get("payloads"), list) else []),
        "virustotal_summary": data.get("virustotal"),
        "sampled_urls": [],
        "url_count": 1 if query_status == "ok" else 0,
        "active_url_count": 1 if str(data.get("url_status") or "").lower() == "online" else 0,
        "offline_url_count": 1 if str(data.get("url_status") or "").lower() == "offline" else 0,
        "unknown_url_count": 0,
        "output_capped": False,
        "private_local_ip": False,
        "api": api_meta,
        "raw_response": _sanitize_raw_response(payload),
    }


def parse_urlhaus_host_response(
    target: str,
    target_type: str,
    payload: dict[str, Any] | None,
    api_meta: dict[str, Any],
) -> dict[str, Any]:
    data = payload or {}
    query_status = str(data.get("query_status") or "").lower()
    urls_raw = data.get("urls") if isinstance(data.get("urls"), list) else []
    total_urls = len(urls_raw)
    output_capped = total_urls > MAX_DISPLAY_URLS
    sampled = [_summarise_url_entry(item) for item in urls_raw[:MAX_DISPLAY_URLS] if isinstance(item, dict)]
    status_counts = _count_url_statuses(urls_raw)
    tags: list[str] = []
    for item in urls_raw[:MAX_STORE_URLS]:
        if isinstance(item, dict):
            for tag in item.get("tags") or []:
                if isinstance(tag, str) and tag not in tags:
                    tags.append(tag)
    return {
        "target": target,
        "target_type": target_type,
        "lookup_type": "host",
        "lookup_value": data.get("host") or target,
        "query_status": query_status,
        "urlhaus_reference": data.get("urlhaus_reference"),
        "host": data.get("host") or target,
        "first_seen": data.get("firstseen") or data.get("first_seen"),
        "url_count": int(data.get("url_count") or total_urls or 0),
        "blacklist_summary": _blacklist_summary(data.get("blacklists")),
        "tags": tags[:25],
        "signatures": tags[:25],
        "sampled_urls": sampled,
        "active_url_count": status_counts["online"],
        "offline_url_count": status_counts["offline"],
        "unknown_url_count": status_counts["unknown"],
        "output_capped": output_capped,
        "private_local_ip": False,
        "api": api_meta,
        "raw_response": _sanitize_raw_response(payload),
    }


def _classify_query_status(query_status: str) -> tuple[str, bool, list[str], list[str]]:
    status = query_status.lower()
    if status == "ok":
        return STATUS_COMPLETED, True, [], []
    if status == "no_results":
        return STATUS_COMPLETED, True, [], []
    if status in {"invalid_url", "invalid_host"}:
        return STATUS_COMPLETED, True, [f"URLhaus reported {status.replace('_', ' ')}."], []
    return STATUS_PARTIAL, False, [], [f"Unexpected URLhaus query_status: {query_status or 'unknown'}"]


def _build_summary(parsed_data: dict[str, Any]) -> str:
    if parsed_data.get("private_local_ip"):
        return PRIVATE_IP_MESSAGE
    if parsed_data.get("api", {}).get("error") == MISSING_KEY_MESSAGE:
        return MISSING_KEY_MESSAGE
    target = parsed_data.get("lookup_value") or parsed_data.get("target") or "target"
    query_status = parsed_data.get("query_status") or "unknown"
    if query_status == "no_results":
        return f"URLhaus returned no malware URL intelligence for {target}."
    if parsed_data.get("lookup_type") == "url":
        url_status = parsed_data.get("url_status") or "unknown"
        return (
            f"URLhaus reported URL intelligence for {target} "
            f"(status: {url_status}, query: {query_status}). "
            "Reported by URLhaus — not independently verified by Overwatch."
        )
    url_count = parsed_data.get("url_count") or 0
    active = parsed_data.get("active_url_count") or 0
    return (
        f"URLhaus reported host intelligence for {target} "
        f"({url_count} URL(s), {active} active). "
        "Reported by URLhaus — not independently verified by Overwatch."
    )


def _build_findings(parsed_data: dict[str, Any]) -> list[str]:
    target = parsed_data.get("lookup_value") or parsed_data.get("target") or "target"
    if parsed_data.get("private_local_ip"):
        return [PRIVATE_IP_MESSAGE]
    return [
        (
            f"URLhaus summary for {target}: lookup={parsed_data.get('lookup_type')}, "
            f"query_status={parsed_data.get('query_status')}, "
            f"url_count={parsed_data.get('url_count')}, "
            f"active={parsed_data.get('active_url_count')}, "
            f"offline={parsed_data.get('offline_url_count')}."
        )
    ]


def _build_raw_output(parsed_data: dict[str, Any]) -> str:
    target = parsed_data.get("lookup_value") or parsed_data.get("target") or "target"
    lines = [
        f"URLhaus lookup: type={parsed_data.get('lookup_type')}, target={target}",
    ]
    if parsed_data.get("private_local_ip"):
        lines.append(PRIVATE_IP_MESSAGE)
        return redact_secrets_from_text("\n".join(lines))
    api = parsed_data.get("api") or {}
    if api.get("error"):
        lines.append(f"error={api['error']}")
    lines.append(f"query_status={parsed_data.get('query_status')}")
    if parsed_data.get("url_status"):
        lines.append(f"url_status={parsed_data['url_status']}")
    if parsed_data.get("threat"):
        lines.append(f"threat={parsed_data['threat']}")
    if parsed_data.get("url_count") is not None:
        lines.append(f"url_count={parsed_data.get('url_count')}")
    if parsed_data.get("active_url_count") is not None:
        lines.append(f"active_urls={parsed_data.get('active_url_count')}")
    if parsed_data.get("output_capped"):
        lines.append("output_capped=true")
    return redact_secrets_from_text("\n".join(lines))


def _private_ip_result(cleaned: str, resolved_type: str) -> dict[str, Any]:
    parsed_data = {
        "target": cleaned,
        "target_type": resolved_type,
        "lookup_type": "host",
        "lookup_value": cleaned,
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
                "title": "Private/local IP — no URLhaus lookup",
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
        f"Unsupported target type for URLhaus: {resolved_type}. "
        "Only URL, domain, and public IPv4 targets are supported."
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


def _build_evidence(parsed_data: dict[str, Any], api_meta: dict[str, Any]) -> list[dict[str, Any]]:
    summary_payload = {
        "target": parsed_data.get("target"),
        "lookup_type": parsed_data.get("lookup_type"),
        "lookup_value": parsed_data.get("lookup_value"),
        "query_status": parsed_data.get("query_status"),
        "url_status": parsed_data.get("url_status"),
        "host": parsed_data.get("host"),
        "threat": parsed_data.get("threat"),
        "url_count": parsed_data.get("url_count"),
        "active_url_count": parsed_data.get("active_url_count"),
        "offline_url_count": parsed_data.get("offline_url_count"),
        "blacklist_summary": parsed_data.get("blacklist_summary"),
        "tags": parsed_data.get("tags"),
        "date_added": parsed_data.get("date_added"),
        "first_seen": parsed_data.get("first_seen"),
        "last_online": parsed_data.get("last_online"),
        "output_capped": parsed_data.get("output_capped"),
        "api_status": api_meta.get("status_code"),
    }
    items = [
        {
            "title": "URLhaus lookup summary",
            "summary": "Parsed URLhaus malware URL intelligence summary (Auth-Key redacted).",
            "content_text": redact_secrets_from_text(json.dumps(summary_payload, indent=2, default=str)),
            "content_type": "application/json",
            "source_name": PROVIDER_LABEL,
            "evidence_type": "third_party_source",
            "reliability": "medium",
            "collection_method": "api_malware_url_lookup",
        }
    ]
    if parsed_data.get("lookup_type") == "host" and parsed_data.get("sampled_urls"):
        items.append(
            {
                "title": "URLhaus host URL sample summary",
                "summary": "Capped sample of malware URLs reported by URLhaus for the host (no download links).",
                "content_text": redact_secrets_from_text(
                    json.dumps(parsed_data.get("sampled_urls"), indent=2, default=str)
                ),
                "content_type": "application/json",
                "source_name": PROVIDER_LABEL,
                "evidence_type": "third_party_source",
                "reliability": "medium",
                "collection_method": "api_malware_url_lookup",
            }
        )
    elif parsed_data.get("lookup_type") == "url" and parsed_data.get("payload_hashes"):
        items.append(
            {
                "title": "URLhaus URL payload hash summary",
                "summary": "Payload hash summaries only — no malware samples downloaded.",
                "content_text": redact_secrets_from_text(
                    json.dumps(parsed_data.get("payload_hashes"), indent=2, default=str)
                ),
                "content_type": "application/json",
                "source_name": PROVIDER_LABEL,
                "evidence_type": "third_party_source",
                "reliability": "medium",
                "collection_method": "api_malware_url_lookup",
            }
        )
    return items


def run_urlhaus_lookup(
    target: str,
    *,
    auth_key: str | None = None,
    target_type: str | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Query URLhaus v1 URL or host endpoints (lookup-only)."""
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

    if resolved_type not in {"url", "domain", "ipv4"}:
        return _unsupported_target_result(cleaned, resolved_type)

    if resolved_type == "ipv4" and is_private_or_local_ip(cleaned):
        return _private_ip_result(cleaned, resolved_type)

    if auth_key is None:
        key = (get_urlhaus_auth_key() or "").strip()
    else:
        key = (auth_key or "").strip()
    if not key:
        blocked = missing_api_key_blocked_result(
            module_id=MODULE_ID,
            env_key_name=ENV_KEY_NAME,
            provider_label=PROVIDER_LABEL,
            target=cleaned,
            target_type=resolved_type,
            message=MISSING_KEY_MESSAGE,
        )
        blocked["parsed_data"]["lookup_value"] = cleaned
        blocked["parsed_data"]["api"] = {"status_code": None, "error": MISSING_KEY_MESSAGE}
        return blocked

    if options.get("mock_response") is not None:
        payload = options["mock_response"]
        lookup_kind = options.get("mock_lookup_type") or (
            "url" if resolved_type == "url" else "host"
        )
        api_meta = {"status_code": 200, "endpoint": lookup_kind, "mock": True}
    elif resolved_type == "url":
        payload, api_meta = _request_urlhaus(URLHAUS_URL_ENDPOINT, {"url": cleaned}, key)
        lookup_kind = "url"
    else:
        host_value = cleaned
        payload, api_meta = _request_urlhaus(URLHAUS_HOST_ENDPOINT, {"host": host_value}, key)
        lookup_kind = "host"

    http_status, http_success, http_warnings, http_errors = classify_provider_http_status(
        api_meta.get("status_code")
    )
    query_status = str((payload or {}).get("query_status") or "").lower()
    qs_status, qs_success, qs_warnings, qs_errors = _classify_query_status(query_status)
    warnings = list(http_warnings) + list(qs_warnings)
    errors = list(http_errors) + list(qs_errors)

    if lookup_kind == "url":
        parsed_data = parse_urlhaus_url_response(cleaned, resolved_type, payload, api_meta)
    else:
        parsed_data = parse_urlhaus_host_response(cleaned, resolved_type, payload, api_meta)

    if parsed_data.get("output_capped"):
        warnings.append(
            "URLhaus returned a large result set; displayed/stored entity output was capped for usability."
        )

    if api_meta.get("error") and api_meta.get("status_code") not in {400, 404, 429}:
        if api_meta.get("status_code") not in {401, 403}:
            warnings.append(f"URLhaus API note: {api_meta['error']}")

    has_core_data = query_status in {"ok", "no_results"} or bool(parsed_data.get("sampled_urls"))
    if http_status in {STATUS_BLOCKED, STATUS_ERROR} and not has_core_data:
        status = http_status
        success = http_success
    elif qs_status == STATUS_PARTIAL and has_core_data:
        status = resolve_collection_status(warnings=warnings, errors=errors, has_core_data=True)
        success = status in {STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_PARTIAL}
    elif qs_status in {STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS}:
        status = resolve_collection_status(warnings=warnings, errors=errors, has_core_data=has_core_data)
        success = status in {STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_PARTIAL}
    else:
        status = http_status if not has_core_data else qs_status
        success = status in {STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_PARTIAL}

    return {
        "success": success,
        "status": status,
        "parsed_data": parsed_data,
        "raw_output": _build_raw_output(parsed_data),
        "findings": _build_findings(parsed_data),
        "warnings": warnings,
        "errors": errors if not success and not has_core_data else [],
        "evidence": _build_evidence(parsed_data, api_meta),
    }

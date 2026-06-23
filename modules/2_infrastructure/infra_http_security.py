"""Controlled HTTP security header review for Project Overwatch."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from utils.api_module_helpers import project_user_agent, request_timeout_seconds, respect_api_courtesy_delay
from utils.result_status import resolve_collection_status
from utils.security import is_private_or_local_ip, redact_secrets_from_text
from utils.target_detection import DOMAIN_PATTERN, get_target_type, normalize_target_value

MODULE_ID = "infra_http_security"
MAX_REDIRECTS = 5
MAX_BODY_PREVIEW = 512
MAX_WELL_KNOWN_BYTES = 8_192

SECURITY_HEADER_SPECS: tuple[tuple[str, str], ...] = (
    ("strict-transport-security", "hsts"),
    ("content-security-policy", "csp"),
    ("x-frame-options", "x_frame_options"),
    ("x-content-type-options", "x_content_type_options"),
    ("referrer-policy", "referrer_policy"),
    ("permissions-policy", "permissions_policy"),
    ("cross-origin-opener-policy", "coop"),
    ("cross-origin-embedder-policy", "coep"),
    ("cross-origin-resource-policy", "corp"),
    ("x-xss-protection", "x_xss_protection"),
)

SESSION_COOKIE_PATTERN = re.compile(
    r"(session|sess|auth|token|jwt|sid|phpsessid|connect\.sid|asp\.net_sessionid)",
    re.IGNORECASE,
)

SECURITY_TXT_PATHS = ("/.well-known/security.txt", "/security.txt")


def _is_session_like_cookie(name: str) -> bool:
    return bool(SESSION_COOKIE_PATTERN.search(name))


def parse_set_cookie_header(header: str) -> dict[str, Any]:
    """Parse a Set-Cookie header into name and flags only — never the value."""
    segments = [segment.strip() for segment in header.split(";") if segment.strip()]
    if not segments:
        return {"name": "unknown", "secure": False, "httponly": False, "samesite": None, "session_like": False}

    name_part = segments[0]
    name = name_part.split("=", 1)[0].strip() if "=" in name_part else name_part.strip()
    secure = False
    httponly = False
    samesite: str | None = None
    for segment in segments[1:]:
        key, _, value = segment.partition("=")
        key_lower = key.strip().lower()
        if key_lower == "secure":
            secure = True
        elif key_lower == "httponly":
            httponly = True
        elif key_lower == "samesite":
            samesite = (value or "unspecified").strip() or "unspecified"

    return {
        "name": name,
        "secure": secure,
        "httponly": httponly,
        "samesite": samesite,
        "session_like": _is_session_like_cookie(name),
    }


def extract_set_cookies(response: requests.Response) -> list[dict[str, Any]]:
    """Extract cookie metadata from a response without storing values."""
    headers: list[str] = []
    raw_msg = getattr(getattr(response, "raw", None), "msg", None)
    if raw_msg is not None and hasattr(raw_msg, "get_all"):
        headers = list(raw_msg.get_all("Set-Cookie") or [])
    if not headers:
        single = response.headers.get("Set-Cookie")
        if single:
            headers = [single]
    return [parse_set_cookie_header(header) for header in headers]


def parse_http_target(
    target: str,
    *,
    target_type: str | None = None,
    scheme_override: str | None = None,
    port_override: int | None = None,
    path_override: str | None = None,
    requested_url_override: str | None = None,
) -> dict[str, Any]:
    """Build the request URL and host metadata from a domain, URL, or IPv4 target."""
    cleaned = target.strip()
    resolved_type = target_type or get_target_type(cleaned)
    host = ""
    scheme = "https"
    port: int | None = None
    path = "/"
    requested_url = ""

    if resolved_type == "url":
        parsed = urlparse(cleaned if "://" in cleaned else f"https://{cleaned}")
        host = (parsed.hostname or "").lower().rstrip(".")
        scheme = (parsed.scheme or "https").lower()
        port = parsed.port
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        requested_url = cleaned if "://" in cleaned else f"https://{cleaned.lstrip('/')}"
    elif resolved_type == "domain":
        host = normalize_target_value(cleaned, "domain")
        requested_url = f"https://{host}/"
    elif resolved_type == "ipv4":
        host = normalize_target_value(cleaned, "ipv4")
        requested_url = f"https://{host}/"
    else:
        return {
            "original_target": cleaned,
            "target_type": resolved_type,
            "host": "",
            "scheme": scheme,
            "port": None,
            "requested_url": "",
            "valid": False,
        }

    if port is None:
        port = 443 if scheme == "https" else 80

    if scheme_override:
        scheme = scheme_override.lower()
    if port_override is not None:
        port = int(port_override)
    if path_override:
        path = path_override if path_override.startswith("/") else f"/{path_override}"
    if requested_url_override:
        requested_url = requested_url_override
    elif host:
        if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
            requested_url = f"{scheme}://{host}{path}"
        else:
            requested_url = f"{scheme}://{host}:{port}{path}"

    valid = bool(host) and bool(requested_url)
    if resolved_type == "domain" and not DOMAIN_PATTERN.match(host):
        valid = False

    return {
        "original_target": cleaned,
        "target_type": resolved_type,
        "host": host,
        "scheme": scheme,
        "port": port,
        "path": path,
        "requested_url": requested_url,
        "valid": valid,
    }


def _sanitize_header_map(headers: dict[str, str]) -> dict[str, str]:
    sanitized: dict[str, str] = {}
    for key, value in headers.items():
        lower = key.lower()
        if lower in {"set-cookie", "cookie"}:
            sanitized[key] = "[redacted]"
        else:
            sanitized[key] = redact_secrets_from_text(value)
    return sanitized


def _analyze_security_headers(headers: dict[str, str]) -> dict[str, Any]:
    lower_headers = {key.lower(): value for key, value in headers.items()}
    analysis: dict[str, Any] = {}
    for header_name, field_key in SECURITY_HEADER_SPECS:
        value = lower_headers.get(header_name)
        analysis[field_key] = {
            "present": bool(value),
            "value": redact_secrets_from_text(value) if value else None,
        }
    return analysis


def _build_redirect_chain(response: requests.Response) -> list[dict[str, Any]]:
    chain: list[dict[str, Any]] = []
    for item in response.history:
        chain.append({"url": item.url, "status_code": item.status_code})
    chain.append({"url": response.url, "status_code": response.status_code})
    return chain


def _request_url(
    url: str,
    *,
    method: str,
    timeout: float,
    stream: bool = False,
) -> requests.Response:
    respect_api_courtesy_delay()
    return requests.request(
        method.upper(),
        url,
        timeout=timeout,
        allow_redirects=True,
        headers={"User-Agent": project_user_agent()},
        stream=stream,
    )


def _fetch_main_response(
    requested_url: str,
    *,
    method: str,
    timeout: float,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "success": False,
        "status_code": None,
        "final_url": requested_url,
        "redirect_chain": [],
        "headers": {},
        "content_type": None,
        "content_length": None,
        "body_preview": None,
        "error": None,
        "cookies": [],
    }
    try:
        use_stream = method.upper() == "GET"
        response = _request_url(requested_url, method=method, timeout=timeout, stream=use_stream)
        result["success"] = True
        result["status_code"] = response.status_code
        result["final_url"] = response.url
        result["redirect_chain"] = _build_redirect_chain(response)
        if len(response.history) > MAX_REDIRECTS:
            result["error"] = f"Redirect chain exceeded configured limit ({MAX_REDIRECTS})"
        header_map = {key.lower(): value for key, value in response.headers.items()}
        result["headers"] = _sanitize_header_map(header_map)
        result["content_type"] = header_map.get("content-type")
        if header_map.get("content-length"):
            try:
                result["content_length"] = int(header_map["content-length"])
            except ValueError:
                result["content_length"] = None
        result["cookies"] = extract_set_cookies(response)
        if use_stream:
            preview_chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=256):
                if not chunk:
                    continue
                preview_chunks.append(chunk)
                total += len(chunk)
                if total >= MAX_BODY_PREVIEW:
                    break
            if preview_chunks:
                encoding = response.encoding or "utf-8"
                preview = b"".join(preview_chunks).decode(encoding, errors="replace")
                result["body_preview"] = redact_secrets_from_text(preview[:MAX_BODY_PREVIEW])
            response.close()
    except requests.RequestException as exc:
        result["error"] = str(exc)
    return result


def _fetch_well_known_path(base_url: str, path: str, *, timeout: float) -> dict[str, Any]:
    url = urljoin(base_url if base_url.endswith("/") else f"{base_url}/", path.lstrip("/"))
    info: dict[str, Any] = {
        "url": url,
        "observed": False,
        "status_code": None,
        "error": None,
    }
    try:
        respect_api_courtesy_delay()
        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={"User-Agent": project_user_agent()},
            stream=True,
        )
        info["status_code"] = response.status_code
        info["observed"] = response.status_code < 400
        total = 0
        for chunk in response.iter_content(chunk_size=1024):
            if not chunk:
                continue
            total += len(chunk)
            if total >= MAX_WELL_KNOWN_BYTES:
                break
        response.close()
    except requests.RequestException as exc:
        info["error"] = str(exc)
    return info


def _collect_well_known(base_url: str, *, timeout: float) -> dict[str, Any]:
    security_attempts: list[dict[str, Any]] = []
    for path in SECURITY_TXT_PATHS:
        attempt = _fetch_well_known_path(base_url, path, timeout=timeout)
        security_attempts.append(attempt)
        if attempt.get("observed"):
            break

    robots = _fetch_well_known_path(base_url, "/robots.txt", timeout=timeout)
    found_security = next((item for item in security_attempts if item.get("observed")), None)
    return {
        "security_txt": {
            "attempts": security_attempts,
            "observed": bool(found_security),
            "status_code": (found_security or {}).get("status_code"),
            "url": (found_security or {}).get("url"),
        },
        "robots_txt": robots,
    }


def _build_raw_output(data: dict[str, Any]) -> str:
    response = data.get("response") or {}
    headers = data.get("headers") or {}
    security = data.get("security_headers") or {}
    lines = [
        f"HTTP security review for {data.get('requested_url')}",
        f"Final URL: {response.get('final_url')}",
        f"Status: {response.get('status_code')}",
    ]
    if response.get("error"):
        lines.append(f"Error: {response['error']}")
    if response.get("redirect_chain"):
        lines.append("Redirects:")
        for hop in response["redirect_chain"]:
            lines.append(f"  {hop.get('status_code')} {hop.get('url')}")
    for field_key, label in (
        ("hsts", "Strict-Transport-Security"),
        ("csp", "Content-Security-Policy"),
        ("x_frame_options", "X-Frame-Options"),
        ("x_content_type_options", "X-Content-Type-Options"),
    ):
        item = security.get(field_key) or {}
        lines.append(f"{label}: {'present' if item.get('present') else 'not observed'}")
    cookies = data.get("cookies") or []
    if cookies:
        lines.append(f"Cookies observed: {len(cookies)} (names/flags only)")
    well_known = data.get("well_known") or {}
    sec = well_known.get("security_txt") or {}
    lines.append(
        f"security.txt: {'observed' if sec.get('observed') else 'not observed'} "
        f"(status {sec.get('status_code')})"
    )
    robots = well_known.get("robots_txt") or {}
    lines.append(
        f"robots.txt: {'observed' if robots.get('observed') else 'not observed'} "
        f"(status {robots.get('status_code')})"
    )
    if headers.get("server"):
        lines.append(f"Server: {headers['server']}")
    if headers.get("x-powered-by"):
        lines.append(f"X-Powered-By: {headers['x-powered-by']}")
    return "\n".join(lines)


def _build_summary(data: dict[str, Any]) -> str:
    response = data.get("response") or {}
    url = data.get("requested_url") or data.get("target") or "target"
    host = data.get("host") or "target"
    port = data.get("port")
    scheme = (data.get("scheme") or "https").lower()
    connection = data.get("connection_outcome") or {}
    if not response.get("success"):
        error = response.get("error") or connection.get("error") or "request failed"
        endpoint = f"{scheme}://{host}:{port}" if port else url
        return (
            f"No HTTP response from {endpoint}. "
            f"The selected service was not reachable ({error})."
        )
    status = response.get("status_code")
    security = data.get("security_headers") or {}
    present = sum(1 for key in security if (security.get(key) or {}).get("present"))
    return (
        f"HTTP security review completed for {url}: status {status}; "
        f"{present}/{len(SECURITY_HEADER_SPECS)} reviewed security headers observed."
    )


def _build_module_notes(data: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    response = data.get("response") or {}
    if not response.get("success"):
        return notes
    notes.append(
        f"HTTP response observed for {data.get('requested_url')} during authorised HTTP header review."
    )
    security = data.get("security_headers") or {}
    if data.get("scheme") == "https" and not (security.get("hsts") or {}).get("present"):
        notes.append("HSTS header not observed on HTTPS response (point-in-time result).")
    return notes


def run_http_security_review(target: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Perform a controlled HTTP security header review."""
    options = options or {}
    method = str(options.get("request_method") or "GET").upper()
    if method not in {"GET", "HEAD"}:
        method = "GET"

    parsed_target = parse_http_target(
        target,
        target_type=options.get("target_type"),
        scheme_override=options.get("scheme_override"),
        port_override=options.get("port_override"),
        path_override=options.get("path_override"),
        requested_url_override=options.get("requested_url"),
    )
    target_source = options.get("target_source") or "default_assumption"
    from utils.web_port_planner import http_target_note

    base_data: dict[str, Any] = {
        "target": parsed_target.get("original_target"),
        "host": parsed_target.get("host"),
        "scheme": parsed_target.get("scheme"),
        "port": parsed_target.get("port"),
        "path": parsed_target.get("path", "/"),
        "target_type": parsed_target.get("target_type"),
        "requested_url": parsed_target.get("requested_url"),
        "target_source": target_source,
        "target_selection_note": http_target_note(target_source=target_source),
        "connection_outcome": {
            "reachable": False,
            "host": parsed_target.get("host"),
            "port": parsed_target.get("port"),
            "scheme": parsed_target.get("scheme"),
            "error": None,
        },
        "response": {
            "success": False,
            "status_code": None,
            "final_url": parsed_target.get("requested_url"),
            "redirect_chain": [],
            "error": None,
            "content_type": None,
            "content_length": None,
            "body_preview": None,
        },
        "headers": {},
        "security_headers": {},
        "cookies": [],
        "well_known": {},
    }

    if not parsed_target.get("valid"):
        message = f"Invalid or unsupported target for HTTP security review: {target}"
        return {
            "module_id": MODULE_ID,
            "success": False,
            "status": "blocked",
            "summary": message,
            "raw_output": message,
            "findings": [],
            "warnings": [],
            "errors": [message],
            "data": base_data,
        }

    if options.get("mock_data") is not None:
        base_data.update(options["mock_data"])
        status = resolve_collection_status(warnings=base_data.get("warnings") or [], has_core_data=True)
        return {
            "module_id": MODULE_ID,
            "success": True,
            "status": status,
            "summary": _build_summary(base_data),
            "raw_output": _build_raw_output(base_data),
            "findings": _build_module_notes(base_data),
            "warnings": list(base_data.get("warnings") or []),
            "errors": [],
            "data": base_data,
        }

    timeout = float(request_timeout_seconds())
    warnings: list[str] = []
    if parsed_target.get("target_type") == "ipv4" and is_private_or_local_ip(parsed_target["host"]):
        warnings.append(
            "Private/local IP target — HTTP review proceeds only when engagement scope and ROE permit safe active testing."
        )

    main_response = _fetch_main_response(
        parsed_target["requested_url"],
        method=method,
        timeout=timeout,
    )
    base_data["response"] = {
        "success": main_response["success"],
        "status_code": main_response["status_code"],
        "final_url": main_response["final_url"],
        "redirect_chain": main_response["redirect_chain"],
        "error": main_response["error"],
        "content_type": main_response["content_type"],
        "content_length": main_response["content_length"],
        "body_preview": main_response.get("body_preview"),
    }
    header_map = main_response.get("headers") or {}
    base_data["headers"] = {
        "server": header_map.get("server"),
        "x_powered_by": header_map.get("x-powered-by"),
        "cache_control": header_map.get("cache-control"),
        "raw": header_map,
    }
    base_data["security_headers"] = _analyze_security_headers(header_map)
    base_data["cookies"] = main_response.get("cookies") or []
    if main_response.get("success"):
        base_data["connection_outcome"]["reachable"] = True

    base_for_well_known = main_response.get("final_url") or parsed_target["requested_url"]
    if main_response.get("success"):
        base_data["well_known"] = _collect_well_known(base_for_well_known, timeout=timeout)
    else:
        base_data["well_known"] = {
            "security_txt": {"attempts": [], "observed": False, "status_code": None, "url": None},
            "robots_txt": {"observed": False, "status_code": None, "url": None, "error": main_response.get("error")},
        }
        base_data["connection_outcome"]["reachable"] = False
        base_data["connection_outcome"]["error"] = main_response.get("error")
        base_data["security_headers"] = {}
        base_data["cookies"] = []
        warnings.append(
            f"No HTTP response from {parsed_target['host']}:{parsed_target['port']} — "
            "service not reachable on selected scheme/port."
        )

    has_core_data = main_response["success"] or bool(main_response.get("error"))
    status = "partial" if not main_response["success"] and main_response.get("error") else resolve_collection_status(
        warnings=warnings, has_core_data=has_core_data
    )
    success = status in {"completed", "completed_with_warnings", "partial"}

    return {
        "module_id": MODULE_ID,
        "success": success,
        "status": status,
        "summary": _build_summary(base_data),
        "raw_output": _build_raw_output(base_data),
        "findings": _build_module_notes(base_data),
        "warnings": warnings,
        "errors": warnings if status == "error" else [],
        "data": base_data,
    }

"""Identify visible web stack indicators from a normal HTTP page response."""

from __future__ import annotations

import importlib.util
from typing import Any

import requests

from modules.executors.paths import PROJECT_ROOT
from utils.api_module_helpers import project_user_agent, request_timeout_seconds, respect_api_courtesy_delay
from utils.result_status import resolve_collection_status
from utils.security import is_private_or_local_ip, redact_secrets_from_text
from utils.web_stack_indicators import detect_indicators, extract_html_artifacts, summarize_categories

MODULE_ID = "infra_web_stack_identifier"
MAX_REDIRECTS = 5
MAX_BODY_PREVIEW = 2048

_spec = importlib.util.spec_from_file_location(
    "infra_http_security",
    PROJECT_ROOT / "modules" / "2_infrastructure" / "infra_http_security.py",
)
if _spec is None or _spec.loader is None:
    raise ImportError("Could not load HTTP security helper module")
_http_security = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_http_security)
parse_http_target = _http_security.parse_http_target
extract_set_cookies = _http_security.extract_set_cookies


def _fetch_page(url: str, *, timeout: float) -> dict[str, Any]:
    result: dict[str, Any] = {
        "success": False,
        "status_code": None,
        "final_url": url,
        "redirect_chain": [],
        "headers": {},
        "content_type": None,
        "body_preview": None,
        "error": None,
        "cookies": [],
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
        result["success"] = True
        result["status_code"] = response.status_code
        result["final_url"] = response.url
        result["redirect_chain"] = [
            {"url": item.url, "status_code": item.status_code} for item in response.history
        ] + [{"url": response.url, "status_code": response.status_code}]
        if len(response.history) > MAX_REDIRECTS:
            result["error"] = f"Redirect chain exceeded configured limit ({MAX_REDIRECTS})"
        header_map = {key.lower(): value for key, value in response.headers.items()}
        result["headers"] = {
            key: redact_secrets_from_text(value) if key not in {"set-cookie"} else "[redacted]"
            for key, value in header_map.items()
        }
        result["content_type"] = header_map.get("content-type")
        result["cookies"] = extract_set_cookies(response)

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


def _build_summary(data: dict[str, Any]) -> str:
    response = data.get("response") or {}
    url = data.get("requested_url") or data.get("target") or "target"
    if not response.get("success"):
        error = response.get("error") or "request failed"
        return f"Web stack identification could not complete for {url} ({error})."
    count = len(data.get("indicators") or [])
    categories = summarize_categories(data.get("indicators") or [])
    cat_text = ", ".join(categories[:4]) if categories else "none identified"
    return (
        f"Web stack identification completed for {url}: {count} indicator(s) observed "
        f"({cat_text}). Review whether technologies appear expected."
    )


def _build_raw_output(data: dict[str, Any]) -> str:
    response = data.get("response") or {}
    lines = [
        f"Web stack identification for {data.get('requested_url')}",
        f"Final URL: {response.get('final_url')}",
        f"Status: {response.get('status_code')}",
    ]
    if response.get("error"):
        lines.append(f"Error: {response['error']}")
    headers = data.get("headers") or {}
    if headers.get("server"):
        lines.append(f"Server: {headers['server']}")
    if headers.get("x-powered-by"):
        lines.append(f"X-Powered-By: {headers['x-powered-by']}")
    for row in data.get("indicators") or []:
        version = f" {row['version']}" if row.get("version") else ""
        lines.append(
            f"- {row['name']}{version} [{row.get('category_label')}] "
            f"({row.get('confidence')}, {row.get('source')})"
        )
    return "\n".join(lines)


def run_web_stack_identifier(target: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Perform a controlled web stack indicator review via a single HTTP GET."""
    options = options or {}
    parsed_target = parse_http_target(
        target,
        target_type=options.get("target_type"),
        scheme_override=options.get("scheme_override"),
        port_override=options.get("port_override"),
        path_override=options.get("path_override"),
        requested_url_override=options.get("requested_url"),
    )

    base_data: dict[str, Any] = {
        "target": parsed_target.get("original_target"),
        "host": parsed_target.get("host"),
        "scheme": parsed_target.get("scheme"),
        "port": parsed_target.get("port"),
        "path": parsed_target.get("path", "/"),
        "target_type": parsed_target.get("target_type"),
        "requested_url": parsed_target.get("requested_url"),
        "response": {"success": False, "final_url": parsed_target.get("requested_url"), "error": None},
        "headers": {},
        "indicators": [],
        "categories": [],
        "script_sources": [],
        "stylesheet_links": [],
        "meta_generator": None,
    }

    if not parsed_target.get("valid"):
        message = f"Invalid or unsupported target for web stack identification: {target}"
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
            "findings": [],
            "warnings": list(base_data.get("warnings") or []),
            "errors": [],
            "data": base_data,
        }

    warnings: list[str] = []
    if parsed_target.get("target_type") == "ipv4" and is_private_or_local_ip(parsed_target["host"]):
        warnings.append(
            "Private/local IP target — web stack identification proceeds only when scope and ROE permit."
        )

    timeout = float(request_timeout_seconds())
    page = _fetch_page(parsed_target["requested_url"], timeout=timeout)
    base_data["response"] = {
        "success": page["success"],
        "status_code": page["status_code"],
        "final_url": page["final_url"],
        "redirect_chain": page["redirect_chain"],
        "error": page["error"],
        "content_type": page["content_type"],
    }
    base_data["headers"] = {
        "server": (page.get("headers") or {}).get("server"),
        "x-powered-by": (page.get("headers") or {}).get("x-powered-by"),
    }
    artifacts = extract_html_artifacts(page.get("body_preview"))
    base_data["script_sources"] = artifacts["script_sources"]
    base_data["stylesheet_links"] = artifacts["stylesheet_links"]
    base_data["meta_generator"] = artifacts["meta_generator"]

    redirect_urls = [hop.get("url") for hop in page.get("redirect_chain") or [] if hop.get("url")]
    cookie_names = [row.get("name") for row in page.get("cookies") or [] if row.get("name")]

    indicators = detect_indicators(
        headers=page.get("headers") or {},
        body_preview=page.get("body_preview"),
        script_sources=artifacts["script_sources"],
        stylesheet_links=artifacts["stylesheet_links"],
        meta_generator=artifacts["meta_generator"],
        cookie_names=cookie_names,
        redirect_urls=redirect_urls,
    )
    base_data["indicators"] = indicators
    base_data["categories"] = summarize_categories(indicators)

    has_core = page["success"]
    status = resolve_collection_status(warnings=warnings, has_core_data=has_core)
    success = bool(page["success"])

    return {
        "module_id": MODULE_ID,
        "success": success,
        "status": status if success else "error",
        "summary": _build_summary(base_data),
        "raw_output": _build_raw_output(base_data),
        "findings": [],
        "warnings": warnings,
        "errors": [] if success else [page.get("error") or "HTTP request failed"],
        "data": base_data,
    }

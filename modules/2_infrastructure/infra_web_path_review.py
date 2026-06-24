"""Controlled sequential review of curated public web paths."""

from __future__ import annotations

import importlib.util
from typing import Any

import requests

from modules.executors.paths import PROJECT_ROOT
from utils.api_module_helpers import project_user_agent, request_timeout_seconds, respect_api_courtesy_delay
from utils.result_status import resolve_collection_status
from utils.security import is_private_or_local_ip, redact_secrets_from_text
from utils.web_path_catalog import (
    build_base_url,
    build_path_url,
    extract_title,
    is_notable_response,
    is_sensitive_category,
    redirect_target,
    resolve_path_entries,
    response_note,
    summarize_notable_categories,
)

MODULE_ID = "infra_web_path_review"
MAX_REDIRECTS = 3
MAX_BODY_PREVIEW = 512
MAX_PATHS = 24

_spec = importlib.util.spec_from_file_location(
    "infra_http_security",
    PROJECT_ROOT / "modules" / "2_infrastructure" / "infra_http_security.py",
)
if _spec is None or _spec.loader is None:
    raise ImportError("Could not load HTTP security helper module")
_http_security = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_http_security)
parse_http_target = _http_security.parse_http_target


def _request_path(
    url: str,
    *,
    method: str,
    timeout: float,
    allow_preview: bool,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "success": False,
        "status_code": None,
        "final_url": url,
        "content_type": None,
        "content_length": None,
        "redirect_target": None,
        "title": None,
        "body_preview": None,
        "error": None,
    }
    method_upper = method.upper()
    if method_upper not in {"GET", "HEAD"}:
        method_upper = "HEAD" if not allow_preview else "GET"
    try:
        respect_api_courtesy_delay()
        if method_upper == "HEAD":
            response = requests.head(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": project_user_agent()},
            )
            result["success"] = True
            result["status_code"] = response.status_code
            result["final_url"] = response.url
            header_map = {key.lower(): value for key, value in response.headers.items()}
            result["content_type"] = header_map.get("content-type")
            if header_map.get("content-length"):
                try:
                    result["content_length"] = int(header_map["content-length"])
                except ValueError:
                    result["content_length"] = None
            result["redirect_target"] = redirect_target(response.url, url)
            response.close()
            return result

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
        header_map = {key.lower(): value for key, value in response.headers.items()}
        result["content_type"] = header_map.get("content-type")
        if header_map.get("content-length"):
            try:
                result["content_length"] = int(header_map["content-length"])
            except ValueError:
                result["content_length"] = None
        result["redirect_target"] = redirect_target(response.url, url)

        if allow_preview:
            preview_chunks: list[bytes] = []
            total = 0
            for chunk in response.iter_content(chunk_size=128):
                if not chunk:
                    continue
                preview_chunks.append(chunk)
                total += len(chunk)
                if total >= MAX_BODY_PREVIEW:
                    break
            if preview_chunks:
                encoding = response.encoding or "utf-8"
                preview = b"".join(preview_chunks).decode(encoding, errors="replace")
                preview = redact_secrets_from_text(preview[:MAX_BODY_PREVIEW])
                result["body_preview"] = preview
                result["title"] = extract_title(preview)
        response.close()
        if len(getattr(response, "history", []) or []) > MAX_REDIRECTS:
            result["error"] = f"Redirect chain exceeded configured limit ({MAX_REDIRECTS})"
    except requests.RequestException as exc:
        result["error"] = str(exc)
    return result


def _build_summary(data: dict[str, Any]) -> str:
    base_url = data.get("base_url") or data.get("requested_url") or data.get("target") or "target"
    checked = int(data.get("paths_checked") or 0)
    notable = int(data.get("notable_count") or 0)
    if not data.get("reachable") and checked == 0:
        return f"Web path review could not complete for {base_url} (no HTTP responses)."
    return (
        f"Web path review completed for {base_url}: {checked} path(s) checked sequentially, "
        f"{notable} notable response(s) observed. Review whether paths appear expected."
    )


def _build_raw_output(data: dict[str, Any]) -> str:
    lines = [
        f"Controlled web path review for {data.get('base_url') or data.get('requested_url')}",
        f"Paths checked: {data.get('paths_checked', 0)}",
        f"Notable responses: {data.get('notable_count', 0)}",
    ]
    for row in data.get("path_results") or []:
        status = row.get("status_code")
        suffix = f" -> {row['redirect_target']}" if row.get("redirect_target") else ""
        lines.append(
            f"- {row.get('path')} [{row.get('category_label')}] "
            f"status={status}{suffix}"
        )
    return "\n".join(lines)


def run_web_path_review(target: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Perform a controlled sequential review of curated web paths."""
    options = options or {}
    parsed_target = parse_http_target(
        target,
        target_type=options.get("target_type"),
        scheme_override=options.get("scheme_override"),
        port_override=options.get("port_override"),
        path_override="/",
        requested_url_override=options.get("requested_url"),
    )

    base_data: dict[str, Any] = {
        "target": parsed_target.get("original_target"),
        "host": parsed_target.get("host"),
        "scheme": parsed_target.get("scheme"),
        "port": parsed_target.get("port"),
        "target_type": parsed_target.get("target_type"),
        "requested_url": parsed_target.get("requested_url"),
        "base_url": build_base_url(parsed_target) if parsed_target.get("valid") else "",
        "path_results": [],
        "paths_checked": 0,
        "notable_count": 0,
        "notable_categories": [],
        "reachable": False,
    }

    if not parsed_target.get("valid"):
        message = f"Invalid or unsupported target for web path review: {target}"
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
            "Private/local IP target — web path review proceeds only when a known web service and ROE permit."
        )

    path_entries = resolve_path_entries(options)[:MAX_PATHS]
    timeout = float(request_timeout_seconds())
    request_method = str(options.get("request_method") or "GET").upper()
    if request_method not in {"GET", "HEAD"}:
        request_method = "GET"

    base_url = base_data["base_url"]
    path_results: list[dict[str, Any]] = []
    any_success = False

    for entry in path_entries:
        path = entry["path"]
        category = entry["category"]
        full_url = build_path_url(base_url, path)
        sensitive = is_sensitive_category(category)
        method = "HEAD" if sensitive else request_method
        response = _request_path(
            full_url,
            method=method,
            timeout=timeout,
            allow_preview=not sensitive and method == "GET",
        )
        if response.get("success"):
            any_success = True
        row = {
            "path": path,
            "full_url": full_url,
            "category": category,
            "category_label": entry.get("category_label"),
            "note": entry.get("note"),
            "status_code": response.get("status_code"),
            "content_type": response.get("content_type"),
            "content_length": response.get("content_length"),
            "redirect_target": response.get("redirect_target"),
            "title": response.get("title"),
            "response_note": response_note(
                category=category,
                status_code=response.get("status_code"),
                content_type=response.get("content_type"),
            ),
            "notable": is_notable_response(
                {
                    "category": category,
                    "status_code": response.get("status_code"),
                    "error": response.get("error"),
                }
            ),
            "method": method,
            "error": response.get("error"),
        }
        path_results.append(row)

    notable_rows = [row for row in path_results if row.get("notable")]
    base_data["path_results"] = path_results
    base_data["paths_checked"] = len(path_results)
    base_data["notable_count"] = len(notable_rows)
    base_data["notable_categories"] = summarize_notable_categories(path_results)
    base_data["reachable"] = any_success

    has_core = any_success
    status = resolve_collection_status(warnings=warnings, has_core_data=has_core)
    success = has_core

    return {
        "module_id": MODULE_ID,
        "success": success,
        "status": status if success else "error",
        "summary": _build_summary(base_data),
        "raw_output": _build_raw_output(base_data),
        "findings": [],
        "warnings": warnings,
        "errors": [] if success else ["No HTTP responses received during path review."],
        "data": base_data,
    }

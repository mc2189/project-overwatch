"""Web port validation, probing, and IP triage helpers."""

from __future__ import annotations

import re
import socket
from typing import Any

from utils.security import is_private_or_local_ip
from utils.service_discovery import (
    build_http_url,
    build_service_recommendation_table,
    load_discovered_services,
    web_tls_service_rows,
)
from utils.target_detection import get_target_type

DEFAULT_COMMON_WEB_PORTS: tuple[int, ...] = (80, 443, 8080, 8443, 8000, 8888)
MAX_CUSTOM_WEB_PORTS = 10
PROBE_TIMEOUT_SECONDS = 3.0

_RANGE_PATTERN = re.compile(r"\d+\s*-\s*\d+")


def parse_custom_web_port_list(text: str) -> tuple[list[int], str | None]:
    """Parse and validate a custom web port list. Returns (ports, error)."""
    cleaned = (text or "").strip()
    if not cleaned:
        return [], "Enter at least one port."
    if _RANGE_PATTERN.search(cleaned):
        return [], "Port ranges are not allowed — list individual ports only."
    tokens = re.split(r"[\s,;]+", cleaned)
    ports: list[int] = []
    seen: set[int] = set()
    for token in tokens:
        if not token:
            continue
        if not token.isdigit():
            return [], f"Invalid port token: {token!r} (integers only)."
        port = int(token)
        if not 1 <= port <= 65535:
            return [], f"Port {port} is out of range (1–65535)."
        if port in seen:
            continue
        seen.add(port)
        ports.append(port)
        if len(ports) > MAX_CUSTOM_WEB_PORTS:
            return [], f"Maximum {MAX_CUSTOM_WEB_PORTS} custom web ports allowed."
    if not ports:
        return [], "No valid ports found."
    return ports, None


def is_private_ipv4_target(target: str) -> bool:
    cleaned = target.strip()
    return get_target_type(cleaned) == "ipv4" and is_private_or_local_ip(cleaned)


def local_ip_triage_message(*, has_service_data: bool) -> str:
    if has_service_data:
        return (
            "This looks like a local/private IP with known service data. "
            "HTTP/TLS checks will target discovered web ports — not a blind default on 443."
        )
    return (
        "This looks like a local/private IP. Start with Network Service Check to identify "
        "open ports and services before running HTTP/TLS checks."
    )


def journey_guidance_for_private_ip(*, has_service_data: bool) -> list[str]:
    lines = [
        "Network Service Check is recommended first — it identifies which follow-up checks make sense.",
        "HTTP/TLS reviews need a reachable web or TLS service on a known port.",
    ]
    if has_service_data:
        lines.append("Known open web/TLS ports from prior runs will be reused for exact scheme/port targets.")
    else:
        lines.append(
            "Without service data, Overwatch will not assume HTTPS on port 443 as the primary path."
        )
    return lines


def filter_modules_without_service_data(module_ids: list[str]) -> list[str]:
    """Remove blind HTTP/TLS recommendations when no service context exists."""
    blocked = {"infra_tls_review", "infra_http_security", "infra_web_stack_identifier"}
    return [module_id for module_id in module_ids if module_id not in blocked]


def probe_web_ports_sequential(
    host: str,
    ports: list[int] | tuple[int, ...] | None = None,
    *,
    timeout: float = PROBE_TIMEOUT_SECONDS,
) -> list[dict[str, Any]]:
    """Sequentially probe TCP connectivity on common web ports (no HTTP requests)."""
    target_ports = list(ports or DEFAULT_COMMON_WEB_PORTS)
    results: list[dict[str, Any]] = []
    for port in target_ports[: len(DEFAULT_COMMON_WEB_PORTS)]:
        outcome: dict[str, Any] = {
            "port": port,
            "reachable": False,
            "error": None,
            "scheme": "https" if port in {443, 8443, 9443} else "http",
        }
        try:
            with socket.create_connection((host, port), timeout=timeout):
                outcome["reachable"] = True
        except OSError as exc:
            outcome["error"] = str(exc)
        results.append(outcome)
    return results


def reachable_probe_ports(probe_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [row for row in probe_results if row.get("reachable")]


def build_service_context(
    case_id: int,
    target: str,
    *,
    conn: Any,
    latest_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    services = load_discovered_services(case_id, target, conn=conn, latest_results=latest_results)
    web_rows = web_tls_service_rows(services)
    return {
        "services": services,
        "service_table": build_service_recommendation_table(services, target.strip()) if services else [],
        "has_service_data": bool(services),
        "has_web_tls_services": bool(web_rows),
        "web_tls_services": web_rows,
    }


def http_target_note(*, target_source: str) -> str:
    if target_source == "discovered_service":
        return "Using discovered service from prior Network Service Check."
    if target_source == "manual_port":
        return "Using manually selected web port."
    if target_source == "common_web_ports":
        return "Using port from common web port probe."
    return "Assuming HTTPS on port 443 because no service information is known."

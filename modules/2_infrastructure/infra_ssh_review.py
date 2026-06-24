"""Controlled SSH configuration review for Project Overwatch."""

from __future__ import annotations

from typing import Any

from utils.api_module_helpers import request_timeout_seconds, respect_api_courtesy_delay
from utils.remote_access_classifier import nmap_ports_to_service_rows
from utils.result_status import STATUS_BLOCKED, STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_PARTIAL
from utils.security import is_private_or_local_ip
from utils.ssh_banner import (
    DEFAULT_SSH_PORT,
    fetch_optional_ssh_metadata,
    fetch_ssh_banner,
    filter_ssh_services,
    parse_ssh_banner,
    validate_port,
)
from utils.target_detection import DOMAIN_PATTERN, get_target_type, normalize_target_value

MODULE_ID = "infra_ssh_review"


def parse_ssh_target(
    target: str,
    *,
    target_type: str | None = None,
    port_override: int | None = None,
) -> dict[str, Any]:
    cleaned = target.strip()
    resolved_type = target_type or get_target_type(cleaned)
    host = ""
    port = DEFAULT_SSH_PORT

    if resolved_type == "domain":
        host = normalize_target_value(cleaned, "domain")
    elif resolved_type == "ipv4":
        host = normalize_target_value(cleaned, "ipv4")
    elif resolved_type == "url":
        return {
            "original_target": cleaned,
            "target_type": resolved_type,
            "host": "",
            "port": DEFAULT_SSH_PORT,
            "valid": False,
        }
    else:
        return {
            "original_target": cleaned,
            "target_type": resolved_type,
            "host": "",
            "port": DEFAULT_SSH_PORT,
            "valid": False,
        }

    if port_override is not None:
        validated = validate_port(port_override)
        if validated is not None:
            port = validated

    valid = bool(host) and validate_port(port) is not None
    if resolved_type == "domain" and host and not DOMAIN_PATTERN.match(host):
        valid = False

    return {
        "original_target": cleaned,
        "target_type": resolved_type if resolved_type in {"ipv4", "domain"} else resolved_type,
        "host": host,
        "port": port,
        "valid": valid,
    }


def _resolve_ssh_port(
    *,
    port_override: int | None,
    ssh_services: list[dict[str, Any]],
    manual_services: list[dict[str, Any]] | None,
) -> tuple[int, str | None]:
    if port_override is not None:
        validated = validate_port(port_override)
        if validated is not None:
            return validated, "manual_port"
    manual_ssh = filter_ssh_services(list(manual_services or []))
    if manual_ssh:
        port = validate_port(manual_ssh[0].get("port"))
        if port is not None:
            return port, "manual_service"
    if ssh_services:
        port = validate_port(ssh_services[0].get("port"))
        if port is not None:
            return port, "nmap_result"
    return DEFAULT_SSH_PORT, "default_assumption"


def _build_summary(parsed: dict[str, Any]) -> str:
    host = parsed.get("host") or "target"
    port = parsed.get("port") or DEFAULT_SSH_PORT
    connection = parsed.get("connection") or {}
    banner = parsed.get("banner") or {}
    if not connection.get("attempted"):
        return (
            f"SSH review for {host}:{port} completed using available service data only. "
            "Run Network Service Check or select a manual port for a direct banner review."
        )
    if connection.get("success"):
        software = banner.get("software_family") or banner.get("software") or "SSH"
        return (
            f"SSH service observed on {host}:{port}. Banner indicates {software}. "
            "Review whether remote access is expected and restricted to trusted devices."
        )
    error = connection.get("error") or "connection failed"
    return (
        f"SSH review attempted for {host}:{port} but no usable banner was received ({error}). "
        "Run Network Service Check to confirm whether SSH is exposed."
    )


def _build_raw_output(parsed: dict[str, Any]) -> str:
    lines = [
        f"SSH Configuration Review — {parsed.get('host')}:{parsed.get('port')}",
        f"Exposure context: {parsed.get('exposure_context')}",
        f"Data sources: {', '.join(parsed.get('data_sources') or []) or 'none'}",
    ]
    connection = parsed.get("connection") or {}
    lines.append(f"Connection: {'success' if connection.get('success') else 'failed'}")
    if connection.get("error"):
        lines.append(f"Connection error: {connection['error']}")
    banner = parsed.get("banner") or {}
    if banner.get("raw_banner"):
        lines.append(f"Banner: {banner['raw_banner']}")
    nmap = parsed.get("nmap_ssh_service") or {}
    if nmap:
        lines.append(
            "Nmap service: "
            f"{nmap.get('service_name') or nmap.get('service') or 'ssh'} "
            f"{nmap.get('product') or ''} {nmap.get('version') or ''}".strip()
        )
    metadata = parsed.get("optional_metadata")
    if metadata and not metadata.get("error"):
        if metadata.get("key_exchange"):
            lines.append(f"Key exchange (sample): {', '.join(metadata['key_exchange'][:6])}")
    lines.extend(parsed.get("limitations") or [])
    return "\n".join(lines)


def run_ssh_review(target: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Review visible SSH service information without authentication."""
    options = options or {}
    target_type = get_target_type(target)
    if target_type not in {"ipv4", "domain"}:
        return {
            "module_id": MODULE_ID,
            "success": False,
            "status": STATUS_BLOCKED,
            "summary": "Target type is not supported for SSH configuration review.",
            "errors": ["target_incompatible"],
            "data": {"target": target, "target_type": target_type},
        }

    port_override = options.get("port_override")
    if port_override is not None:
        port_override = validate_port(port_override)

    parsed_target = parse_ssh_target(
        target,
        target_type=target_type,
        port_override=port_override,
    )
    if not parsed_target.get("valid"):
        message = f"Invalid or unsupported target for SSH review: {target}"
        return {
            "module_id": MODULE_ID,
            "success": False,
            "status": STATUS_BLOCKED,
            "summary": message,
            "raw_output": message,
            "findings": [],
            "warnings": [],
            "errors": [message],
            "data": {"target": target, "target_type": target_type},
        }

    host = parsed_target["host"]
    is_private = is_private_or_local_ip(host) if get_target_type(host) == "ipv4" else False
    data_sources: list[str] = []
    observed: list[dict[str, Any]] = []

    if options.get("parsed_ports"):
        observed.extend(nmap_ports_to_service_rows(list(options.get("parsed_ports") or [])))
        data_sources.append("nmap_result")
    if options.get("discovered_services"):
        for row in options.get("discovered_services") or []:
            observed.append(dict(row))
        if "case_services" not in data_sources:
            data_sources.append("case_services")
    if options.get("manual_services"):
        for row in options.get("manual_services") or []:
            if isinstance(row, dict):
                observed.append(dict(row))
        data_sources.append("manual_ports")

    ssh_services = filter_ssh_services(observed)
    nmap_ssh = dict(ssh_services[0]) if ssh_services else None
    port, port_source = _resolve_ssh_port(
        port_override=port_override,
        ssh_services=ssh_services,
        manual_services=options.get("manual_services"),
    )
    manual_review = bool(
        port_override is not None
        or options.get("manual_review")
        or options.get("manual_services")
        or options.get("explicit_review")
    )
    no_service_data = not observed

    parsed_data: dict[str, Any] = {
        "target": parsed_target["original_target"],
        "host": host,
        "port": port,
        "port_source": port_source,
        "target_type": target_type,
        "is_private_target": is_private,
        "exposure_context": "local_private" if is_private else "public_or_unknown",
        "data_sources": data_sources,
        "observed_service_count": len(observed),
        "ssh_service_count": len(ssh_services),
        "nmap_ssh_service": nmap_ssh,
        "ssh_services": ssh_services,
        "no_service_data": no_service_data,
        "manual_review": manual_review,
        "connection": {
            "attempted": False,
            "success": False,
            "error": None,
            "source": None,
        },
        "banner": parse_ssh_banner(None),
        "optional_metadata": None,
        "optional_metadata_unavailable": False,
        "limitations": [
            "Visible service review only — no login, passwords, private keys, or remote commands.",
            "This is not an authenticated server configuration inspection.",
            "Results reflect the point in time tested and require validation before remediation.",
        ],
    }

    if options.get("mock_data") is not None:
        parsed_data.update(options["mock_data"])
        status = str(options.get("mock_status") or STATUS_COMPLETED)
        return {
            "module_id": MODULE_ID,
            "success": status != STATUS_BLOCKED,
            "status": status,
            "summary": _build_summary(parsed_data),
            "raw_output": _build_raw_output(parsed_data),
            "findings": [],
            "warnings": list(options.get("mock_warnings") or []),
            "errors": list(options.get("mock_errors") or []),
            "data": parsed_data,
        }

    warnings: list[str] = []
    if no_service_data:
        warnings.append("No Nmap or service observations were available — review uses explicit port selection.")
    if no_service_data and not manual_review and port_source == "default_assumption":
        warnings.append("Run Network Service Check first to corroborate SSH exposure.")

    should_connect = True
    if should_connect:
        timeout = float(request_timeout_seconds())
        respect_api_courtesy_delay()
        parsed_data["connection"]["attempted"] = True
        parsed_data["connection"]["source"] = "direct_banner"
        banner_result = fetch_ssh_banner(host, int(port), timeout=timeout)
        parsed_data["connection"]["success"] = banner_result.get("success", False)
        parsed_data["connection"]["error"] = banner_result.get("error")
        parsed_data["banner"] = banner_result.get("parsed_banner") or parse_ssh_banner(None)
        if banner_result.get("banner") and not parsed_data["banner"].get("raw_banner"):
            parsed_data["banner"] = parse_ssh_banner(banner_result.get("banner"))

        if banner_result.get("success"):
            metadata = fetch_optional_ssh_metadata(host, int(port), timeout=timeout)
            if metadata is None:
                parsed_data["optional_metadata_unavailable"] = True
            else:
                parsed_data["optional_metadata"] = metadata
                if metadata.get("error"):
                    warnings.append("Optional SSH metadata backend returned partial data.")
        elif banner_result.get("error"):
            warnings.append(
                f"SSH banner review could not connect to {host}:{port} — {banner_result['error']}"
            )
    else:
        warnings.append(
            "Direct SSH banner review was not performed — select a manual port or run Network Service Check first."
        )

    status = STATUS_COMPLETED
    if warnings:
        status = STATUS_COMPLETED_WITH_WARNINGS
    if parsed_data["connection"]["attempted"] and not parsed_data["connection"]["success"]:
        status = STATUS_PARTIAL if parsed_data.get("nmap_ssh_service") else STATUS_COMPLETED_WITH_WARNINGS

    return {
        "module_id": MODULE_ID,
        "success": True,
        "status": status,
        "summary": _build_summary(parsed_data),
        "raw_output": _build_raw_output(parsed_data),
        "findings": [],
        "warnings": warnings,
        "errors": [],
        "data": parsed_data,
    }

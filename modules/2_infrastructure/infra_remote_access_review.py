"""Remote access exposure review using observed Nmap and service data."""

from __future__ import annotations

from typing import Any

from utils.remote_access_classifier import (
    filter_remote_access_services,
    nmap_ports_to_service_rows,
)
from utils.result_status import STATUS_BLOCKED, STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS
from utils.security import is_private_or_local_ip
from utils.target_detection import get_target_type, normalize_target_value

MODULE_ID = "infra_remote_access_review"


def _normalize_manual_services(manual_services: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for item in manual_services or []:
        if not isinstance(item, dict):
            continue
        port = item.get("port")
        try:
            port_num = int(port)
        except (TypeError, ValueError):
            continue
        if port_num < 1 or port_num > 65535:
            continue
        rows.append(
            {
                "port": port_num,
                "protocol": str(item.get("protocol") or "tcp").lower(),
                "service_name": item.get("service_name") or item.get("service"),
                "product": item.get("product"),
                "version": item.get("version"),
                "source_module": "manual",
            }
        )
    return rows


def _build_summary(target: str, services: list[dict[str, Any]], *, is_private: bool) -> str:
    if not services:
        return (
            f"Remote access review completed for {target}. "
            "No remote-access service identified from available data."
        )
    labels = [service.get("service_label") or str(service.get("port")) for service in services[:4]]
    joined = ", ".join(labels)
    scope = "local target" if is_private else "assessed target"
    return (
        f"Remote access review completed. {joined} "
        f"{'was' if len(labels) == 1 else 'were'} observed on the {scope}. "
        "Review whether these services are expected and restricted to trusted devices."
    )


def _build_raw_output(target: str, services: list[dict[str, Any]], data_sources: list[str]) -> str:
    lines = [f"Remote Access Exposure Review — {target}", f"Data sources: {', '.join(data_sources) or 'none'}"]
    if not services:
        lines.append("No remote-access services identified from available observations.")
        return "\n".join(lines)
    lines.append("")
    for service in services:
        port = service.get("port")
        proto = service.get("protocol", "tcp")
        label = service.get("service_label") or "service"
        class_label = service.get("classification_label") or service.get("classification")
        product = service.get("product") or ""
        version = service.get("version") or ""
        detail = f"{label} on {port}/{proto} [{class_label}]"
        if product or version:
            detail += f" — {product} {version}".strip()
        lines.append(detail)
    return "\n".join(lines)


def run_remote_access_review(target: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """
    Review remote-access exposure from existing service observations.

    Does not authenticate, scan, or send payloads. Uses Nmap/entity/service data when provided.
    """
    options = options or {}
    target_type = get_target_type(target)
    if target_type not in {"ipv4", "domain", "url"}:
        return {
            "module_id": MODULE_ID,
            "success": False,
            "status": STATUS_BLOCKED,
            "summary": "Target type is not supported for remote access review.",
            "errors": ["target_incompatible"],
            "data": {"target": target, "target_type": target_type},
        }

    cleaned = normalize_target_value(target.strip(), target_type)
    host = cleaned
    if target_type == "url":
        from urllib.parse import urlparse

        parsed = urlparse(cleaned if "://" in cleaned else f"//{cleaned}")
        host = parsed.hostname or cleaned

    is_private = is_private_or_local_ip(host) if get_target_type(host) == "ipv4" else False
    data_sources: list[str] = []

    observed: list[dict[str, Any]] = []
    if options.get("parsed_ports"):
        observed.extend(nmap_ports_to_service_rows(list(options.get("parsed_ports") or [])))
        data_sources.append("nmap_result")
    if options.get("discovered_services"):
        for row in options.get("discovered_services") or []:
            observed.append(dict(row))
        if "discovered_services" not in data_sources:
            data_sources.append("case_services")
    if options.get("manual_services"):
        observed.extend(_normalize_manual_services(options.get("manual_services")))
        data_sources.append("manual_ports")

    remote_services = filter_remote_access_services(observed)
    no_service_data = not observed

    parsed_data: dict[str, Any] = {
        "target": cleaned,
        "host": host,
        "target_type": target_type,
        "is_private_target": is_private,
        "exposure_context": "local_private" if is_private else "public_or_unknown",
        "remote_services": remote_services,
        "observed_service_count": len(observed),
        "remote_service_count": len(remote_services),
        "data_sources": data_sources,
        "no_service_data": no_service_data,
        "lan_device_hint": options.get("lan_device_hint"),
        "limitations": [
            "Based on observed service data only — no authentication or intrusive testing performed.",
            "Absence of a service here does not prove it is not exposed elsewhere.",
        ],
    }

    warnings: list[str] = []
    if no_service_data:
        warnings.append("No service observations were available — run Network Service Check first.")
    elif not remote_services:
        warnings.append("No remote-access candidates were identified in the available service data.")

    status = STATUS_COMPLETED_WITH_WARNINGS if warnings else STATUS_COMPLETED
    return {
        "module_id": MODULE_ID,
        "success": True,
        "status": status,
        "summary": _build_summary(host, remote_services, is_private=is_private),
        "raw_output": _build_raw_output(host, remote_services, data_sources),
        "findings": [],
        "warnings": warnings,
        "errors": [],
        "data": parsed_data,
    }

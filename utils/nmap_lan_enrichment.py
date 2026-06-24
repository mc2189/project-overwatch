"""Merge Nmap scan hints into PCAP LAN device rows without overwriting higher-confidence PCAP data."""

from __future__ import annotations

from typing import Any


def _open_port_summary(parsed_ports: list[dict[str, Any]]) -> str:
    parts: list[str] = []
    for row in parsed_ports[:6]:
        port = row.get("port")
        service = row.get("service") or ""
        if port is None:
            continue
        label = f"{port}/tcp"
        if service:
            label += f" ({service})"
        parts.append(label)
    if len(parsed_ports) > 6:
        parts.append(f"+{len(parsed_ports) - 6} more")
    return ", ".join(parts)


def enrich_lan_devices_from_nmap(
    devices: list[dict[str, Any]],
    followup_results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Attach Nmap service hints to matching LAN device rows; preserve PCAP attribution."""
    if not followup_results:
        return devices

    by_ip: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for device in devices:
        ip = str(device.get("ip") or "").strip()
        if not ip:
            continue
        by_ip[ip] = dict(device)
        order.append(ip)

    for result in followup_results:
        if result.get("module_id") != "infra_nmap" or not result.get("success"):
            continue
        target = str(result.get("target") or "").strip()
        if not target:
            continue

        parsed = result.get("parsed_data") or {}
        primary_host = parsed.get("primary_host") or {}
        hostname = (
            parsed.get("hostname")
            or (parsed.get("hostnames") or [None])[0]
            or (primary_host.get("hostnames") or [None])[0]
        )
        mac = parsed.get("mac_address") or primary_host.get("mac_address")
        mac_vendor = parsed.get("mac_vendor") or primary_host.get("mac_vendor")
        parsed_ports = list(parsed.get("parsed_ports") or [])
        scan_profile = parsed.get("scan_profile") or {}

        row = by_ip.get(target)
        if row is None:
            row = {
                "ip": target,
                "mac": None,
                "hostname": None,
                "role_label": None,
                "sources": [],
                "confidence": "low",
                "observation_count": 0,
            }
            by_ip[target] = row
            order.append(target)

        sources = list(row.get("sources") or [])
        if "nmap" not in sources:
            sources.append("nmap")
        row["sources"] = sources

        if hostname and not row.get("hostname"):
            row["hostname"] = hostname
        if mac and not row.get("mac"):
            row["mac"] = mac
        if mac_vendor and not row.get("mac_vendor"):
            row["mac_vendor"] = mac_vendor

        row["nmap_open_ports"] = len(parsed_ports)
        if parsed_ports:
            row["nmap_services_summary"] = _open_port_summary(parsed_ports)
        if scan_profile.get("display_name"):
            row["nmap_profile"] = scan_profile["display_name"]
        row["nmap_host_status"] = parsed.get("host_status") or primary_host.get("host_status")

    if not by_ip:
        return devices
    return [by_ip[ip] for ip in order if ip in by_ip]

"""Lightweight parser for open ports in Nmap text output."""

from __future__ import annotations

import re
from typing import Any

# Matches lines such as:
# 88/tcp open kerberos-sec Heimdal Kerberos
# 5000/tcp open rtsp
# 5900/tcp open vnc Apple remote desktop vnc
NMAP_OPEN_PORT_LINE = re.compile(
    r"^\s*(\d+)/(tcp|udp)\s+(open)\s*(.*)$",
    re.IGNORECASE,
)


def parse_nmap_open_ports(raw_output: str) -> list[dict[str, Any]]:
    """Extract open TCP/UDP ports from Nmap raw output."""
    if not raw_output:
        return []

    ports: list[dict[str, Any]] = []
    for line in raw_output.splitlines():
        match = NMAP_OPEN_PORT_LINE.match(line)
        if not match:
            continue

        port, protocol, state, remainder = match.groups()
        remainder = remainder.strip()
        service = ""
        version = ""

        if remainder:
            parts = remainder.split(None, 1)
            service = parts[0]
            if len(parts) > 1:
                version = parts[1]

        ports.append(
            {
                "port": port,
                "protocol": protocol.lower(),
                "state": state.lower(),
                "service": service,
                "version": version,
            }
        )

    return ports


def build_service_entity_value(target: str, port_info: dict[str, Any]) -> str:
    """Build a stable service entity value such as 192.168.1.1:5900/tcp."""
    return f"{target.strip()}:{port_info['port']}/{port_info['protocol']}"


def build_service_entity_label(port_info: dict[str, Any]) -> str:
    """Build a readable service label such as 5900/tcp vnc Apple remote desktop vnc."""
    parts = [f"{port_info['port']}/{port_info['protocol']}"]
    if port_info.get("service"):
        parts.append(str(port_info["service"]))
    if port_info.get("version"):
        parts.append(str(port_info["version"]))
    return " ".join(parts)

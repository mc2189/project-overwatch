"""Stable keys for case memory, baselines, and expected-item matching."""

from __future__ import annotations

from typing import Any


def finding_fingerprint(finding: dict[str, Any]) -> str:
    """Return a stable key for a finding across runs."""
    module_id = (finding.get("module_id") or "").strip().lower()
    title = (finding.get("title") or "").strip().lower()
    if module_id and title:
        return f"{module_id}|{title}"
    return title or str(finding.get("finding_id") or finding.get("id") or "")


def service_item_key(host: str, port: Any, protocol: str = "tcp") -> str:
    host_value = str(host or "").strip().lower()
    try:
        port_num = int(port)
    except (TypeError, ValueError):
        return host_value
    return f"{host_value}:{port_num}/{str(protocol or 'tcp').lower()}"


def device_item_key(value: str) -> str:
    return str(value or "").strip().lower()


def technology_item_key(target: str, name: str) -> str:
    return f"{target}:{name}".strip(":").lower()


def finding_row_fingerprint(row: dict[str, Any]) -> str:
    if row.get("fingerprint"):
        return str(row["fingerprint"]).lower()
    return finding_fingerprint(row)

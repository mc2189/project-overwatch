"""Classify remote-access and administrative services from observed port/service data."""

from __future__ import annotations

import re
from typing import Any

CLASS_REMOTE_ADMIN = "remote_admin"
CLASS_FILE_SHARING = "file_sharing"
CLASS_LEGACY_CLEARTEXT = "legacy_cleartext"
CLASS_MEDIA_DEVICE = "media_device"
CLASS_MANAGEMENT_CONSOLE = "management_console"
CLASS_UNKNOWN_SERVICE = "unknown_service"

CLASSIFICATION_LABELS: dict[str, str] = {
    CLASS_REMOTE_ADMIN: "Remote administration",
    CLASS_FILE_SHARING: "File sharing",
    CLASS_LEGACY_CLEARTEXT: "Legacy cleartext management",
    CLASS_MEDIA_DEVICE: "Media / streaming device",
    CLASS_MANAGEMENT_CONSOLE: "Management console",
    CLASS_UNKNOWN_SERVICE: "Unknown remote service",
}

# signature token, known ports, classification
_REMOTE_SIGNATURES: tuple[tuple[str, frozenset[int], str], ...] = (
    ("ssh", frozenset({22}), CLASS_REMOTE_ADMIN),
    ("telnet", frozenset({23}), CLASS_LEGACY_CLEARTEXT),
    ("ftp", frozenset({21}), CLASS_LEGACY_CLEARTEXT),
    ("smb", frozenset({445}), CLASS_FILE_SHARING),
    ("microsoft-ds", frozenset({445}), CLASS_FILE_SHARING),
    ("netbios", frozenset({137, 138, 139}), CLASS_FILE_SHARING),
    ("netbios-ssn", frozenset({139}), CLASS_FILE_SHARING),
    ("rdp", frozenset({3389}), CLASS_REMOTE_ADMIN),
    ("ms-wbt-server", frozenset({3389}), CLASS_REMOTE_ADMIN),
    ("vnc", frozenset({5900, 5901, 5902, 5903, 5904, 5905}), CLASS_REMOTE_ADMIN),
    ("winrm", frozenset({5985, 5986}), CLASS_REMOTE_ADMIN),
    ("wsman", frozenset({5985, 5986}), CLASS_REMOTE_ADMIN),
    ("rtsp", frozenset({554, 8554, 5000, 7000}), CLASS_MEDIA_DEVICE),
    ("ipp", frozenset({631}), CLASS_MANAGEMENT_CONSOLE),
    ("printer", frozenset({631, 9100}), CLASS_MANAGEMENT_CONSOLE),
)

_VNC_PORT_RANGE = range(5900, 5910)
_ADMIN_WEB_TOKENS = frozenset(
    {
        "admin",
        "router",
        "management",
        "device",
        "nas",
        "synology",
        "qnap",
        "unifi",
        "mikrotik",
        "http-mgmt",
    }
)
_TOKEN_RE = re.compile(r"[a-z][a-z0-9+_.-]*")


def _tokens(*parts: str | None) -> set[str]:
    tokens: set[str] = set()
    for part in parts:
        if not part:
            continue
        for match in _TOKEN_RE.findall(str(part).lower()):
            tokens.add(match)
    return tokens


def _parse_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def classification_label(classification: str) -> str:
    return CLASSIFICATION_LABELS.get(classification, classification.replace("_", " ").title())


def service_display_name(service_name: str | None, port: int) -> str:
    name = (service_name or "").strip().lower()
    if "ssh" in name or port == 22:
        return "SSH"
    if "telnet" in name or port == 23:
        return "Telnet"
    if "ftp" in name or port == 21:
        return "FTP"
    if "smb" in name or "microsoft-ds" in name or port == 445:
        return "SMB"
    if "rdp" in name or "wbt" in name or port == 3389:
        return "RDP"
    if "vnc" in name or port in _VNC_PORT_RANGE:
        return "VNC"
    if "winrm" in name or "wsman" in name or port in {5985, 5986}:
        return "WinRM"
    if "rtsp" in name:
        return "RTSP"
    if name:
        return name.upper()
    return f"port {port}"


def classify_remote_access_service(
    *,
    port: int,
    protocol: str = "tcp",
    service_name: str | None = None,
    product: str | None = None,
    version: str | None = None,
    extra_info: str | None = None,
) -> str | None:
    """Return a remote-access classification or None if not a remote/admin candidate."""
    tokens = _tokens(service_name, product, version, extra_info)
    for signature, ports, classification in _REMOTE_SIGNATURES:
        if signature in tokens and (port in ports or signature in {"ssh", "telnet", "ftp", "vnc", "rdp", "smb", "microsoft-ds"}):
            return classification
        if port in ports and signature in tokens:
            return classification
    if port in _VNC_PORT_RANGE and ("vnc" in tokens or not tokens):
        return CLASS_REMOTE_ADMIN
    if port in {5985, 5986}:
        return CLASS_REMOTE_ADMIN
    if port in {137, 138, 139, 445} and not tokens:
        return CLASS_FILE_SHARING
    if port in {21, 23} and not tokens:
        return CLASS_LEGACY_CLEARTEXT
    if port == 22 and not tokens:
        return CLASS_REMOTE_ADMIN
    if port == 3389:
        return CLASS_REMOTE_ADMIN
    if "rtsp" in tokens or (port in {554, 8554} and protocol.lower() == "tcp"):
        return CLASS_MEDIA_DEVICE
    if tokens & _ADMIN_WEB_TOKENS and port not in {80, 443, 8080, 8443}:
        return CLASS_MANAGEMENT_CONSOLE
    return None


def enrich_service_row(row: dict[str, Any]) -> dict[str, Any] | None:
    """Return enriched remote-access service row or None."""
    port = _parse_port(row.get("port"))
    if port is None:
        return None
    classification = classify_remote_access_service(
        port=port,
        protocol=str(row.get("protocol") or "tcp"),
        service_name=row.get("service_name") or row.get("service"),
        product=row.get("product"),
        version=row.get("version"),
        extra_info=row.get("extra_info") or row.get("banner"),
    )
    if classification is None:
        return None
    enriched = dict(row)
    enriched["port"] = port
    enriched["protocol"] = str(enriched.get("protocol") or "tcp").lower()
    enriched["service_name"] = enriched.get("service_name") or enriched.get("service")
    enriched["classification"] = classification
    enriched["classification_label"] = classification_label(classification)
    enriched["service_label"] = service_display_name(enriched.get("service_name"), port)
    return enriched


def filter_remote_access_services(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter and enrich observed services to remote-access candidates."""
    rows: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for service in services:
        enriched = enrich_service_row(service)
        if enriched is None:
            continue
        key = (int(enriched["port"]), str(enriched.get("protocol") or "tcp"))
        if key in seen:
            continue
        seen.add(key)
        rows.append(enriched)
    rows.sort(key=lambda item: (int(item["port"]), item.get("service_label") or ""))
    return rows


def has_remote_access_services(services: list[dict[str, Any]]) -> bool:
    return bool(filter_remote_access_services(services))


def nmap_ports_to_service_rows(parsed_ports: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for port_info in parsed_ports:
        port = _parse_port(port_info.get("port"))
        if port is None:
            continue
        rows.append(
            {
                "port": port,
                "protocol": port_info.get("protocol") or "tcp",
                "service_name": port_info.get("service"),
                "product": port_info.get("product"),
                "version": port_info.get("version"),
                "extra_info": port_info.get("extra_info"),
                "source_module": "infra_nmap",
            }
        )
    return rows


def severity_for_service(
    *,
    classification: str,
    is_private: bool,
    service_label: str,
) -> str:
    """Conservative advisory severity."""
    if classification == CLASS_LEGACY_CLEARTEXT:
        return "medium"
    if not is_private:
        if classification in {CLASS_REMOTE_ADMIN, CLASS_FILE_SHARING}:
            return "high"
        return "medium"
    if classification == CLASS_REMOTE_ADMIN:
        if service_label in {"RDP", "VNC"}:
            return "medium"
        return "low"
    if classification == CLASS_FILE_SHARING:
        return "medium"
    if classification == CLASS_MEDIA_DEVICE:
        return "low"
    if classification == CLASS_MANAGEMENT_CONSOLE:
        return "low"
    return "low"

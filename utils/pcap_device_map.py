"""LAN device hints from DHCP, ARP, and mDNS observations in PCAP data."""

from __future__ import annotations

import re
from typing import Any

from utils.web_port_planner import is_private_ipv4_target

MAX_DEVICE_OBSERVATIONS = 400
_MAX_LAN_DEVICES = 40

_MAC_RE = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.I)
_LOCAL_NAME_RE = re.compile(r"\.local\.?$", re.I)
_SERVICE_NAME_RE = re.compile(r"^_[^.]+\._(?:tcp|udp)\.local\.?$", re.I)


def _normalise_mac(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = str(value).strip().lower().replace("-", ":")
    if not _MAC_RE.match(cleaned):
        return None
    return cleaned


def _normalise_hostname(value: str | None) -> str | None:
    if not value:
        return None
    name = str(value).strip().lower().rstrip(".")
    if not name or name in {"localhost", "unknown"}:
        return None
    return name


def _normalise_ip(value: str | None) -> str | None:
    if not value:
        return None
    ip = str(value).strip()
    if not ip or ip == "0.0.0.0":
        return None
    if is_private_ipv4_target(ip):
        return ip
    return None


def _safe_layer_get(packet: Any, layer: str, field: str) -> str | None:
    try:
        layer_obj = getattr(packet, layer, None)
        if layer_obj is None:
            return None
        value = getattr(layer_obj, field, None)
        if value is None:
            return None
        return str(value)
    except Exception:
        return None


def _first_layer_field(packet: Any, layer: str, *fields: str) -> str | None:
    for field in fields:
        value = _safe_layer_get(packet, layer, field)
        if value and value not in {"", "0.0.0.0", "00:00:00:00:00:00"}:
            return value
    return None


def _is_mdns_packet(packet: Any, sport: str | None, dport: str | None) -> bool:
    if sport == "5353" or dport == "5353":
        return True
    qname = _safe_layer_get(packet, "dns", "qry_name") or ""
    return bool(_LOCAL_NAME_RE.search(qname))


def extract_packet_device_hints(packet: Any) -> list[dict[str, Any]]:
    """Extract zero or more DHCP/ARP/mDNS observations from a single packet."""
    hints: list[dict[str, Any]] = []

    if hasattr(packet, "dhcp") or hasattr(packet, "bootp"):
        for layer in ("dhcp", "bootp"):
            if not hasattr(packet, layer):
                continue
            mac = _normalise_mac(
                _first_layer_field(
                    packet,
                    layer,
                    "hw.mac_addr",
                    "eth.src",
                    "chaddr",
                )
            )
            ip = _normalise_ip(
                _first_layer_field(
                    packet,
                    layer,
                    "ip.your",
                    "client_ip",
                    "yiaddr",
                    "ciaddr",
                )
            )
            hostname = _normalise_hostname(
                _first_layer_field(packet, layer, "option.hostname", "option.client_id")
            )
            vendor_class = _first_layer_field(packet, layer, "option.vendor_class_id")
            if mac or ip or hostname:
                hints.append(
                    {
                        "type": "dhcp",
                        "ip": ip,
                        "mac": mac,
                        "hostname": hostname,
                        "vendor_class": vendor_class,
                    }
                )
            break

    if hasattr(packet, "arp"):
        src_ip = _normalise_ip(_safe_layer_get(packet, "arp", "src.proto_ipv4"))
        dst_ip = _normalise_ip(_safe_layer_get(packet, "arp", "dst.proto_ipv4"))
        src_mac = _normalise_mac(_safe_layer_get(packet, "arp", "src.hw_mac"))
        dst_mac = _normalise_mac(_safe_layer_get(packet, "arp", "dst.hw_mac"))
        if src_ip or src_mac:
            hints.append({"type": "arp", "ip": src_ip, "mac": src_mac})
        if dst_ip or dst_mac:
            hints.append({"type": "arp", "ip": dst_ip, "mac": dst_mac})

    sport = _safe_layer_get(packet, "udp", "srcport") or _safe_layer_get(packet, "tcp", "srcport")
    dport = _safe_layer_get(packet, "udp", "dstport") or _safe_layer_get(packet, "tcp", "dstport")
    if hasattr(packet, "dns") and _is_mdns_packet(packet, sport, dport):
        qname = _normalise_hostname(_safe_layer_get(packet, "dns", "qry_name"))
        answer = _normalise_hostname(_safe_layer_get(packet, "dns", "resp_name"))
        ptr = _normalise_hostname(_safe_layer_get(packet, "dns", "ptr.domain.name"))
        a_record = _normalise_ip(_safe_layer_get(packet, "dns", "a"))
        names = [name for name in (qname, answer, ptr) if name]
        service_name = next((name for name in names if _SERVICE_NAME_RE.match(name)), None)
        host_name = next(
            (name for name in names if name and not _SERVICE_NAME_RE.match(name) and ".local" not in name),
            None,
        )
        if not host_name and qname and not _SERVICE_NAME_RE.match(qname):
            host_name = qname.replace(".local", "")
        if service_name or host_name or a_record:
            hints.append(
                {
                    "type": "mdns",
                    "ip": a_record,
                    "hostname": host_name,
                    "service": service_name,
                }
            )

    return hints


def _device_key(ip: str | None, mac: str | None) -> str:
    if mac:
        return f"mac:{mac}"
    if ip:
        return f"ip:{ip}"
    return ""


def merge_device_observations(observations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Merge DHCP/ARP/mDNS observations into a LAN device table."""
    merged: dict[str, dict[str, Any]] = {}
    mac_to_key: dict[str, str] = {}
    ip_to_key: dict[str, str] = {}

    def _get_or_create(key: str, *, ip: str | None = None, mac: str | None = None) -> dict[str, Any]:
        if key not in merged:
            merged[key] = {
                "ip": ip,
                "mac": mac,
                "hostname": None,
                "sources": [],
                "dhcp_vendor_class": None,
                "mdns_services": [],
                "observation_count": 0,
                "confidence": "low",
            }
        row = merged[key]
        if ip and not row.get("ip"):
            row["ip"] = ip
        if mac and not row.get("mac"):
            row["mac"] = mac
        return row

    def _resolve_key(ip: str | None, mac: str | None) -> str:
        if mac and mac in mac_to_key:
            return mac_to_key[mac]
        if ip and ip in ip_to_key:
            return ip_to_key[ip]
        key = _device_key(ip, mac)
        if not key:
            return ""
        if mac:
            mac_to_key[mac] = key
        if ip:
            ip_to_key[ip] = key
        return key

    for obs in observations:
        ip = obs.get("ip")
        mac = obs.get("mac")
        key = _resolve_key(ip, mac)
        if not key:
            continue
        row = _get_or_create(key, ip=ip, mac=mac)
        row["observation_count"] = int(row.get("observation_count") or 0) + 1
        source = str(obs.get("type") or "")
        if source and source not in row["sources"]:
            row["sources"].append(source)

        if obs.get("hostname"):
            existing = row.get("hostname")
            candidate = obs["hostname"]
            if not existing or len(candidate) > len(existing):
                row["hostname"] = candidate

        if obs.get("vendor_class"):
            row["dhcp_vendor_class"] = obs["vendor_class"]

        service = obs.get("service")
        if service and service not in row["mdns_services"]:
            row["mdns_services"].append(service)

        if mac:
            mac_to_key[mac] = key
            row["mac"] = mac
        if ip:
            ip_to_key[ip] = key
            row["ip"] = ip

    devices = list(merged.values())
    for row in devices:
        sources = set(row.get("sources") or [])
        if "dhcp" in sources and row.get("mac"):
            row["confidence"] = "high"
        elif len(sources) >= 2 or row.get("hostname"):
            row["confidence"] = "medium"
        else:
            row["confidence"] = "low"

    devices.sort(
        key=lambda item: (
            {"high": 0, "medium": 1, "low": 2}.get(str(item.get("confidence")), 9),
            -int(item.get("observation_count") or 0),
            str(item.get("ip") or ""),
        )
    )
    devices = [
        row
        for row in devices
        if not row.get("ip") or is_private_ipv4_target(str(row.get("ip")))
    ]
    return devices[:_MAX_LAN_DEVICES]


def device_map_for_ip(devices: list[dict[str, Any]], ip: str) -> dict[str, Any] | None:
    """Return the LAN device row for an IP, if present."""
    target = str(ip).strip()
    for row in devices:
        if row.get("ip") == target:
            return row
    return None


def lan_device_summary(devices: list[dict[str, Any]]) -> str:
    """One-line summary for triage narrative."""
    if not devices:
        return ""
    with_names = sum(1 for row in devices if row.get("hostname"))
    return f"{len(devices)} LAN device(s) inferred ({with_names} with hostname hints)."

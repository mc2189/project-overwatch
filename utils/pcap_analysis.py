"""PCAP file analysis helpers — bounded local review with privacy redaction."""

from __future__ import annotations

import hashlib
import importlib.util
import re
import shutil
import subprocess
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from utils.pcap_device_map import MAX_DEVICE_OBSERVATIONS, extract_packet_device_hints, merge_device_observations
from utils.pcap_iot_heuristics import enrich_devices_with_roles
from utils.security import redact_secrets_from_text

MAX_PACKETS = 25_000
MAX_DNS_ENTRIES = 100
MAX_HTTP_ENTRIES = 100
MAX_TLS_SNI_ENTRIES = 100
MAX_TOP_IPS = 25
MAX_CONVERSATIONS = 25
MAX_ENTITY_IPS = 50
MAX_ENTITY_DOMAINS = 40
MAX_ENTITY_SERVICES = 30

_SENSITIVE_FIELD_RE = re.compile(
    r"(?i)(password|passwd|authorization|cookie|set-cookie|bearer|token|session)=([^\s&;]+)"
)
_CLEARTEXT_PROTOCOLS = frozenset(
    {
        "http",
        "ftp",
        "telnet",
        "smtp",
        "pop",
        "imap",
        "ldap",
        "snmp",
        "dns",
    }
)
_ADMIN_MAIL_PROTOCOLS = frozenset({"ftp", "telnet", "smtp", "pop", "imap"})


def pcap_target_type(filename: str) -> str:
    lowered = filename.strip().lower()
    if lowered.endswith(".pcapng"):
        return "pcapng"
    if lowered.endswith(".pcap"):
        return "pcap"
    return "file"


def is_supported_pcap_filename(filename: str) -> bool:
    return pcap_target_type(filename) in {"pcap", "pcapng"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


def capinfos_available() -> bool:
    return shutil.which("capinfos") is not None


def pyshark_available() -> bool:
    return importlib.util.find_spec("pyshark") is not None


def parser_available() -> bool:
    return tshark_available() and pyshark_available()


def basic_metadata_available() -> bool:
    """True when capinfos or tshark can supply packet counts without pyshark."""
    return capinfos_available() or tshark_available()


_CAPINFOS_PACKETS_RE = re.compile(r"Number of packets:\s*(\d+)", re.I)
_CAPINFOS_DURATION_RE = re.compile(r"Capture duration:\s*([\d.]+)\s*seconds", re.I)
_CAPINFOS_EARLIEST_RE = re.compile(r"Earliest packet time:\s*(.+)", re.I)
_CAPINFOS_LATEST_RE = re.compile(r"Latest packet time:\s*(.+)", re.I)
_TSHARK_PHS_PROTO_RE = re.compile(r"^\s*(\S+)\s+frames:(\d+)", re.I)


def _extract_basic_pcap_metadata(file_path: Path) -> dict[str, Any]:
    """Bounded metadata via capinfos/tshark when pyshark deep parsing is unavailable."""
    metadata: dict[str, Any] = {
        "packet_count": 0,
        "packets_analysed": 0,
        "duration_seconds": None,
        "capture_start": None,
        "capture_end": None,
        "protocols": [],
        "basic_metadata_available": False,
    }
    if not file_path.is_file():
        return metadata

    if capinfos_available():
        try:
            completed = subprocess.run(
                ["capinfos", str(file_path)],
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            completed = None
        if completed and completed.returncode == 0 and completed.stdout:
            packet_match = _CAPINFOS_PACKETS_RE.search(completed.stdout)
            if packet_match:
                count = int(packet_match.group(1))
                metadata["packet_count"] = count
                metadata["packets_analysed"] = count
                metadata["basic_metadata_available"] = True
            duration_match = _CAPINFOS_DURATION_RE.search(completed.stdout)
            if duration_match:
                metadata["duration_seconds"] = round(float(duration_match.group(1)), 3)
            start_match = _CAPINFOS_EARLIEST_RE.search(completed.stdout)
            end_match = _CAPINFOS_LATEST_RE.search(completed.stdout)
            if start_match:
                metadata["capture_start"] = start_match.group(1).strip()
            if end_match:
                metadata["capture_end"] = end_match.group(1).strip()

    if metadata["packet_count"] == 0 and tshark_available():
        try:
            completed = subprocess.run(
                ["tshark", "-r", str(file_path), "-q", "-z", "io,phs"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            completed = None
        if completed and completed.returncode == 0 and completed.stdout:
            protocols: list[dict[str, int]] = []
            total_packets = 0
            for line in completed.stdout.splitlines():
                match = _TSHARK_PHS_PROTO_RE.match(line)
                if not match:
                    continue
                name = match.group(1).lower()
                count = int(match.group(2))
                if name == "frame" and count > total_packets:
                    total_packets = count
                elif name not in {"frame", "eth", "null"} and count > 0:
                    protocols.append({"protocol": name, "count": count})
            if total_packets > 0:
                metadata["packet_count"] = total_packets
                metadata["packets_analysed"] = total_packets
                metadata["basic_metadata_available"] = True
            if protocols:
                metadata["protocols"] = sorted(protocols, key=lambda item: item["count"], reverse=True)[:20]

    return metadata


def redact_sensitive_text(text: str) -> tuple[str, bool]:
    """Return redacted text and whether sensitive material was detected."""
    if not text:
        return text, False
    detected = False
    redacted = text

    def _replace(match: re.Match[str]) -> str:
        nonlocal detected
        detected = True
        return f"{match.group(1)}=[REDACTED]"

    redacted = _SENSITIVE_FIELD_RE.sub(_replace, redacted)
    redacted = redact_secrets_from_text(redacted)
    return redacted, detected or redacted != text


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


def _conversation_key(src: str, dst: str, sport: str | None, dport: str | None) -> str:
    return f"{src}:{sport or '*'} -> {dst}:{dport or '*'}"


def analyze_pcap_file(
    file_path: Path,
    *,
    filename: str,
    file_hash: str,
    file_size: int,
) -> dict[str, Any]:
    """Analyse a PCAP/PCAPNG file with bounded extraction."""
    warnings: list[str] = []
    errors: list[str] = []
    sensitive_detected = False

    parsed: dict[str, Any] = {
        "filename": filename,
        "file_size_bytes": file_size,
        "sha256": file_hash,
        "packet_count": 0,
        "packets_analysed": 0,
        "analysis_capped": False,
        "parser_available": parser_available(),
        "capture_start": None,
        "capture_end": None,
        "duration_seconds": None,
        "protocols": [],
        "top_source_ips": [],
        "top_destination_ips": [],
        "top_conversations": [],
        "ports_observed": [],
        "dns_queries": [],
        "http_entries": [],
        "tls_sni": [],
        "dhcp_activity": False,
        "arp_activity": False,
        "mdns_activity": False,
        "lan_devices": [],
        "icmp_activity": False,
        "broadcast_indicators": [],
        "cleartext_protocols": [],
        "high_volume_flows": [],
        "repeated_patterns": [],
        "entities_preview": {"ips": [], "domains": [], "services": []},
        "sensitive_values_redacted": False,
    }

    if not parser_available():
        if not tshark_available():
            warnings.append(
                "Deep packet parsing unavailable — install Wireshark/tshark command-line tools."
            )
        else:
            warnings.append(
                "Deep packet parsing unavailable — install pyshark (`pip install pyshark`) "
                "for DNS, HTTP, TLS, and entity extraction."
            )
        status = "partial"
        raw_lines = [
            f"PCAP file metadata: {filename}",
            f"Size: {file_size} bytes",
            f"SHA-256: {file_hash}",
        ]
        if file_path.exists() and basic_metadata_available():
            basic = _extract_basic_pcap_metadata(file_path)
            if basic.get("basic_metadata_available"):
                parsed["packet_count"] = basic["packet_count"]
                parsed["packets_analysed"] = basic["packets_analysed"]
                parsed["duration_seconds"] = basic["duration_seconds"]
                parsed["capture_start"] = basic["capture_start"]
                parsed["capture_end"] = basic["capture_end"]
                parsed["protocols"] = basic["protocols"]
                parsed["basic_metadata_available"] = True
                status = "completed_with_warnings"
                raw_lines.append(f"Packets: {basic['packet_count']}")
                if basic.get("duration_seconds") is not None:
                    raw_lines.append(f"Duration: {basic['duration_seconds']}s")
            else:
                raw_lines.append("Basic metadata extraction did not return packet counts.")
        else:
            raw_lines.append("Parser dependency unavailable.")
        return {
            "success": True,
            "status": status,
            "parsed_data": parsed,
            "warnings": warnings,
            "errors": errors,
            "raw_output": "\n".join(raw_lines),
            "sensitive_detected": sensitive_detected,
        }

    if not file_path.exists():
        errors.append("Capture file is not available for analysis.")
        return {
            "success": False,
            "status": "blocked",
            "parsed_data": parsed,
            "warnings": warnings,
            "errors": errors,
            "raw_output": "Capture file missing.",
            "sensitive_detected": False,
        }

    import pyshark  # type: ignore

    protocol_counter: Counter[str] = Counter()
    src_ip_counter: Counter[str] = Counter()
    dst_ip_counter: Counter[str] = Counter()
    conversation_counter: Counter[str] = Counter()
    port_counter: Counter[str] = Counter()
    dns_entries: list[dict[str, str]] = []
    http_entries: list[dict[str, str]] = []
    tls_entries: list[dict[str, str]] = []
    flow_counter: Counter[str] = Counter()
    domain_counter: Counter[str] = Counter()
    ip_entities: set[str] = set()
    service_entities: set[str] = set()
    device_observations: list[dict[str, Any]] = []

    timestamps: list[float] = []
    packets_seen = 0

    try:
        capture = pyshark.FileCapture(
            str(file_path),
            keep_packets=False,
            only_summaries=False,
        )
        for packet in capture:
            packets_seen += 1
            if packets_seen > MAX_PACKETS:
                parsed["analysis_capped"] = True
                warnings.append(f"Packet analysis capped at {MAX_PACKETS:,} packets.")
                break

            try:
                ts = float(packet.sniff_timestamp)
                timestamps.append(ts)
            except Exception:
                pass

            highest = getattr(packet, "highest_layer", None)
            transport = getattr(packet, "transport_layer", None)
            if highest:
                protocol_counter[str(highest).lower()] += 1
            if transport:
                protocol_counter[str(transport).lower()] += 1

            src = _safe_layer_get(packet, "ip", "src") or _safe_layer_get(packet, "ipv6", "src")
            dst = _safe_layer_get(packet, "ip", "dst") or _safe_layer_get(packet, "ipv6", "dst")
            sport = _safe_layer_get(packet, "tcp", "srcport") or _safe_layer_get(packet, "udp", "srcport")
            dport = _safe_layer_get(packet, "tcp", "dstport") or _safe_layer_get(packet, "udp", "dstport")

            if src:
                src_ip_counter[src] += 1
                if len(ip_entities) < MAX_ENTITY_IPS:
                    ip_entities.add(src)
            if dst:
                dst_ip_counter[dst] += 1
                if len(ip_entities) < MAX_ENTITY_IPS:
                    ip_entities.add(dst)
            if sport:
                port_counter[sport] += 1
            if dport:
                port_counter[dport] += 1
            if src and dst:
                conv = _conversation_key(src, dst, sport, dport)
                conversation_counter[conv] += 1
                flow_counter[conv] += 1
                if sport and src:
                    service_entities.add(f"{src}:{sport}/tcp")
                if dport and dst:
                    service_entities.add(f"{dst}:{dport}/tcp")

            if hasattr(packet, "dns"):
                qname = _safe_layer_get(packet, "dns", "qry_name")
                if qname and len(dns_entries) < MAX_DNS_ENTRIES:
                    dns_entries.append({"query": qname.lower().rstrip(".")})
                    if len(domain_counter) < MAX_ENTITY_DOMAINS:
                        domain_counter[qname.lower().rstrip(".")] += 1

            if hasattr(packet, "http"):
                host = _safe_layer_get(packet, "http", "host")
                method = _safe_layer_get(packet, "http", "request_method")
                code = _safe_layer_get(packet, "http", "response_code")
                entry = {
                    "host": (host or "").lower(),
                    "method": method or "",
                    "status_code": code or "",
                }
                if len(http_entries) < MAX_HTTP_ENTRIES:
                    http_entries.append(entry)
                if host and len(domain_counter) < MAX_ENTITY_DOMAINS:
                    domain_counter[host.lower()] += 1
                for field in ("cookie", "authorization", "auth"):
                    raw_val = _safe_layer_get(packet, "http", field)
                    if raw_val:
                        _, flagged = redact_sensitive_text(f"{field}={raw_val}")
                        sensitive_detected = sensitive_detected or flagged

            if hasattr(packet, "tls"):
                sni = _safe_layer_get(packet, "tls", "handshake_extensions_server_name")
                version = _safe_layer_get(packet, "tls", "handshake_version")
                if sni and len(tls_entries) < MAX_TLS_SNI_ENTRIES:
                    tls_entries.append({"server_name": sni.lower(), "version": version or ""})
                    if len(domain_counter) < MAX_ENTITY_DOMAINS:
                        domain_counter[sni.lower()] += 1

            if hasattr(packet, "dhcp"):
                parsed["dhcp_activity"] = True
            if hasattr(packet, "arp"):
                parsed["arp_activity"] = True
            if hasattr(packet, "icmp"):
                parsed["icmp_activity"] = True

            if len(device_observations) < MAX_DEVICE_OBSERVATIONS:
                for hint in extract_packet_device_hints(packet):
                    device_observations.append(hint)
                    if hint.get("type") == "mdns":
                        parsed["mdns_activity"] = True

            if dst and (dst.endswith(".255") or dst.startswith("224.") or dst.startswith("239.")):
                if dst not in parsed["broadcast_indicators"]:
                    parsed["broadcast_indicators"].append(dst)

        capture.close()
    except Exception as exc:
        errors.append(f"PCAP parsing error: {exc}")
        raw = redact_secrets_from_text(str(exc))
        return {
            "success": False,
            "status": "error",
            "parsed_data": parsed,
            "warnings": warnings,
            "errors": errors,
            "raw_output": raw,
            "sensitive_detected": sensitive_detected,
        }

    parsed["packet_count"] = packets_seen
    parsed["packets_analysed"] = min(packets_seen, MAX_PACKETS)
    if timestamps:
        start = datetime.fromtimestamp(min(timestamps), tz=timezone.utc)
        end = datetime.fromtimestamp(max(timestamps), tz=timezone.utc)
        parsed["capture_start"] = start.isoformat()
        parsed["capture_end"] = end.isoformat()
        parsed["duration_seconds"] = round(max(timestamps) - min(timestamps), 3)

    parsed["protocols"] = [
        {"protocol": name, "count": count}
        for name, count in protocol_counter.most_common(20)
    ]
    parsed["top_source_ips"] = [
        {"ip": ip, "packets": count} for ip, count in src_ip_counter.most_common(MAX_TOP_IPS)
    ]
    parsed["top_destination_ips"] = [
        {"ip": ip, "packets": count} for ip, count in dst_ip_counter.most_common(MAX_TOP_IPS)
    ]
    parsed["top_conversations"] = [
        {"conversation": conv, "packets": count}
        for conv, count in conversation_counter.most_common(MAX_CONVERSATIONS)
    ]
    parsed["ports_observed"] = [
        {"port": port, "count": count} for port, count in port_counter.most_common(20)
    ]
    parsed["dns_queries"] = dns_entries
    parsed["http_entries"] = http_entries
    parsed["tls_sni"] = tls_entries

    cleartext = sorted({p for p in protocol_counter if p in _CLEARTEXT_PROTOCOLS})
    parsed["cleartext_protocols"] = cleartext

    if flow_counter:
        threshold = max(flow_counter.values()) * 0.35
        parsed["high_volume_flows"] = [
            {"flow": flow, "packets": count}
            for flow, count in flow_counter.most_common(10)
            if count >= max(threshold, 25)
        ]
        repeats = [flow for flow, count in flow_counter.items() if count >= 50]
        parsed["repeated_patterns"] = repeats[:15]

    parsed["entities_preview"] = {
        "ips": sorted(ip_entities)[:MAX_ENTITY_IPS],
        "domains": [name for name, _ in domain_counter.most_common(MAX_ENTITY_DOMAINS)],
        "services": sorted(service_entities)[:MAX_ENTITY_SERVICES],
    }
    if device_observations:
        parsed["lan_devices"] = enrich_devices_with_roles(merge_device_observations(device_observations))
    parsed["sensitive_values_redacted"] = sensitive_detected

    status = "completed"
    if parsed["analysis_capped"] or warnings:
        status = "completed_with_warnings"
    if not packets_seen:
        status = "partial"
        warnings.append("No packets were parsed from the supplied capture.")

    raw_lines = [
        f"PCAP review: {filename}",
        f"SHA-256: {file_hash}",
        f"Packets analysed: {parsed['packets_analysed']}",
        f"Protocols: {', '.join(item['protocol'] for item in parsed['protocols'][:8]) or 'none'}",
    ]
    if parsed.get("duration_seconds") is not None:
        raw_lines.append(f"Duration: {parsed['duration_seconds']}s")

    return {
        "success": True,
        "status": status,
        "parsed_data": parsed,
        "warnings": warnings,
        "errors": errors,
        "raw_output": redact_secrets_from_text("\n".join(raw_lines)),
        "sensitive_detected": sensitive_detected,
    }

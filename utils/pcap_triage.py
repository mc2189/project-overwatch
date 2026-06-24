"""PCAP triage narrative, entity ranking, and target-focused slices."""

from __future__ import annotations

import re
from typing import Any

from utils.pcap_fingerprint import diff_fingerprints
from utils.pcap_device_map import device_map_for_ip, lan_device_summary
from utils.web_port_planner import is_private_ipv4_target

_CDN_OR_PLATFORM_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("Google", re.compile(r"google|gstatic|googleusercontent|1e100\.net|142\.250\.|172\.217\.|216\.58\.", re.I)),
    ("Apple", re.compile(r"apple|icloud|mzstatic|akamaiedge", re.I)),
    ("Cloudflare", re.compile(r"cloudflare|104\.1[68]\.|172\.6[47]\.", re.I)),
    ("AWS", re.compile(r"amazonaws|aws\.|52\.|54\.|34\.|35\.", re.I)),
    ("Microsoft", re.compile(r"microsoft|office|azure|msft", re.I)),
    ("Cursor", re.compile(r"cursor\.sh", re.I)),
]

_RISKY_CLEARTEXT = frozenset({"http", "ftp", "telnet", "smtp", "pop", "imap", "ldap", "snmp"})
_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def actionable_cleartext(protocols: list[str] | None) -> list[str]:
    """Cleartext protocols worth investigation (excludes routine DNS)."""
    if not protocols:
        return []
    return sorted(
        {
            str(p).lower()
            for p in protocols
            if str(p).lower() in _RISKY_CLEARTEXT
        }
    )


def resolve_org_bucket(value: str, *, kind: str = "ip") -> str:
    """Human-readable org/platform bucket for condensation."""
    text = str(value).strip()
    if kind == "ip" or _IPV4_RE.match(text):
        if is_private_ipv4_target(text):
            return "Local / LAN"
        for label, pattern in _CDN_OR_PLATFORM_PATTERNS:
            if pattern.search(text):
                return label
        return "Other external"
    lowered = text.lower()
    for label, pattern in _CDN_OR_PLATFORM_PATTERNS:
        if pattern.search(lowered):
            return label
    return "Other external"


def classify_endpoint(value: str, *, kind: str = "ip") -> str:
    """Classify IP or domain as local, cdn, or external."""
    text = str(value).strip()
    if kind == "ip" or _IPV4_RE.match(text):
        if is_private_ipv4_target(text):
            return "local"
        for label, pattern in _CDN_OR_PLATFORM_PATTERNS:
            if pattern.search(text):
                return "cdn"
        return "external"
    lowered = text.lower()
    for label, pattern in _CDN_OR_PLATFORM_PATTERNS:
        if pattern.search(lowered):
            return "cdn"
    return "external"


def bucket_ip_talkers(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Aggregate top IP talkers into org/platform buckets."""
    bucket_packets: dict[str, int] = {}
    bucket_ips: dict[str, set[str]] = {}

    def _add(ip: str, packets: int) -> None:
        if not ip:
            return
        label = resolve_org_bucket(ip)
        bucket_packets[label] = bucket_packets.get(label, 0) + packets
        bucket_ips.setdefault(label, set()).add(ip)

    for row in parsed_data.get("top_source_ips") or []:
        _add(str(row.get("ip") or ""), int(row.get("packets") or 0))
    for row in parsed_data.get("top_destination_ips") or []:
        _add(str(row.get("ip") or ""), int(row.get("packets") or 0))

    return [
        {
            "bucket": label,
            "packets": count,
            "ip_count": len(bucket_ips.get(label) or []),
            "sample_ips": sorted(bucket_ips.get(label) or [])[:4],
        }
        for label, count in sorted(bucket_packets.items(), key=lambda item: item[1], reverse=True)
    ]


def build_network_picture(
    parsed_data: dict[str, Any],
    *,
    ranked: list[dict[str, Any]] | None = None,
    risky_cleartext: list[str] | None = None,
    encrypted_ratio: float = 0.0,
) -> dict[str, Any]:
    """One-line condensed network summary for analysts."""
    ranked = ranked or rank_investigation_entities(parsed_data)
    risky = risky_cleartext if risky_cleartext is not None else actionable_cleartext(parsed_data.get("cleartext_protocols"))
    investigate = len([item for item in ranked if item.get("tier") == "investigate"])
    buckets = bucket_ip_talkers(parsed_data)
    enc_pct = int(round(encrypted_ratio * 100))
    risky_text = ", ".join(risky) if risky else "none"
    return {
        "encrypted_percent": enc_pct,
        "investigate_count": investigate,
        "risky_cleartext": risky,
        "talker_buckets": buckets,
        "one_liner": (
            f"{enc_pct}% encrypted traffic; {investigate} endpoint(s) worth probing; "
            f"risky cleartext: {risky_text}."
        ),
    }


def dedupe_table_rows(rows: list[dict[str, Any]], key: str) -> list[dict[str, Any]]:
    """Deduplicate PCAP sample tables (DNS/TLS) for cleaner UI."""
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for row in rows:
        value = str(row.get(key) or "").strip().lower().rstrip(".")
        if not value or value in seen:
            continue
        seen.add(value)
        unique.append(row)
    return unique


def _traffic_involving_target(parsed_data: dict[str, Any], workspace_target: str) -> dict[str, Any]:
    target = workspace_target.strip().lower()
    if not target:
        return {"involving_target": [], "external_to_target": []}

    involving: list[dict[str, Any]] = []
    for row in parsed_data.get("top_conversations") or []:
        conv = str(row.get("conversation") or "")
        if target in conv.lower():
            involving.append({"conversation": conv, "packets": row.get("packets", 0)})

    external_ips: list[dict[str, Any]] = []
    for row in parsed_data.get("top_source_ips") or []:
        ip = str(row.get("ip") or "")
        if not ip or ip.lower() == target:
            continue
        if _IPV4_RE.match(ip) and not is_private_ipv4_target(ip):
            external_ips.append(
                {
                    "ip": ip,
                    "packets": row.get("packets", 0),
                    "classification": classify_endpoint(ip),
                }
            )
    for row in parsed_data.get("top_destination_ips") or []:
        ip = str(row.get("ip") or "")
        if not ip or ip.lower() == target:
            continue
        if _IPV4_RE.match(ip) and not is_private_ipv4_target(ip):
            if not any(item["ip"] == ip for item in external_ips):
                external_ips.append(
                    {
                        "ip": ip,
                        "packets": row.get("packets", 0),
                        "classification": classify_endpoint(ip),
                    }
                )

    external_ips.sort(key=lambda item: int(item.get("packets") or 0), reverse=True)
    return {
        "involving_target": involving[:10],
        "external_to_target": external_ips[:12],
    }


def rank_investigation_entities(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Rank domains and IPs for follow-up intrusive / intel modules."""
    ranked: list[dict[str, Any]] = []
    preview = parsed_data.get("entities_preview") or {}

    ip_packets: dict[str, int] = {}
    for row in parsed_data.get("top_source_ips") or []:
        ip = str(row.get("ip") or "")
        if ip:
            ip_packets[ip] = ip_packets.get(ip, 0) + int(row.get("packets") or 0)
    for row in parsed_data.get("top_destination_ips") or []:
        ip = str(row.get("ip") or "")
        if ip:
            ip_packets[ip] = ip_packets.get(ip, 0) + int(row.get("packets") or 0)

    devices = list(parsed_data.get("lan_devices") or [])

    for ip, packets in sorted(ip_packets.items(), key=lambda item: item[1], reverse=True)[:20]:
        classification = classify_endpoint(ip)
        tier = "investigate" if classification == "external" and packets >= 15 else "review"
        if classification == "local" and packets >= 8:
            tier = "investigate"
        if classification == "cdn" and packets < 40:
            tier = "routine"
        ranked.append(
            {
                "entity_type": "ip",
                "value": ip,
                "packets": packets,
                "classification": classification,
                "org_bucket": resolve_org_bucket(ip),
                "tier": tier,
                "suggested_modules": _modules_for_ip(ip, classification),
                "device_hint": _device_hint_for_ip(devices, ip),
            }
        )

    domain_counts: dict[str, int] = {}
    for entry in parsed_data.get("tls_sni") or []:
        name = str(entry.get("server_name") or "").lower().rstrip(".")
        if name:
            domain_counts[name] = domain_counts.get(name, 0) + 1
    for entry in parsed_data.get("dns_queries") or []:
        name = str(entry.get("query") or "").lower().rstrip(".")
        if name:
            domain_counts[name] = domain_counts.get(name, 0) + 1
    for name in preview.get("domains") or []:
        key = str(name).lower().rstrip(".")
        domain_counts.setdefault(key, 1)

    for domain, hits in sorted(domain_counts.items(), key=lambda item: item[1], reverse=True)[:15]:
        classification = classify_endpoint(domain, kind="domain")
        tier = "investigate" if classification == "external" else "review"
        if classification == "cdn":
            tier = "routine"
        ranked.append(
            {
                "entity_type": "domain",
                "value": domain,
                "packets": hits,
                "classification": classification,
                "org_bucket": resolve_org_bucket(domain, kind="domain"),
                "tier": tier,
                "suggested_modules": ["infra_domain_intel", "intel_urlhaus", "infra_tls_review"],
            }
        )

    tier_order = {"investigate": 0, "review": 1, "routine": 2}
    ranked.sort(key=lambda item: (tier_order.get(item["tier"], 9), -int(item.get("packets") or 0)))
    return ranked[:25]


def _device_hint_for_ip(devices: list[dict[str, Any]], ip: str) -> dict[str, Any] | None:
    device = device_map_for_ip(devices, ip)
    if not device:
        return None
    return {
        "hostname": device.get("hostname"),
        "mac": device.get("mac"),
        "role": device.get("role"),
        "role_label": device.get("role_label"),
        "sources": device.get("sources") or [],
    }


def _modules_for_ip(ip: str, classification: str) -> list[str]:
    if is_private_ipv4_target(ip):
        return ["infra_nmap", "infra_tls_review", "infra_http_security"]
    if classification == "cdn":
        return ["intel_greynoise", "intel_abuseipdb"]
    return ["intel_abuseipdb", "intel_greynoise", "intel_shodan", "infra_whois_rdap"]


def build_triage_report(
    parsed_data: dict[str, Any],
    *,
    workspace_target: str = "",
    fingerprint: dict[str, Any] | None = None,
    fingerprint_diff: dict[str, Any] | None = None,
    capture_meta: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Produce analyst-facing triage narrative and ranked follow-ups."""
    packets = int(parsed_data.get("packets_analysed") or parsed_data.get("packet_count") or 0)
    duration = parsed_data.get("duration_seconds")
    protocols = [str(item.get("protocol", "")).upper() for item in (parsed_data.get("protocols") or [])[:6]]
    risky_cleartext = actionable_cleartext(parsed_data.get("cleartext_protocols"))
    ranked = rank_investigation_entities(parsed_data)
    focus = _traffic_involving_target(parsed_data, workspace_target)

    encrypted_ratio = 0.0
    proto_counts = {str(item.get("protocol", "")).lower(): int(item.get("count") or 0) for item in parsed_data.get("protocols") or []}
    encrypted = sum(proto_counts.get(key, 0) for key in ("tls", "quic", "ssl"))
    total_proto = sum(proto_counts.values()) or max(packets, 1)
    if total_proto:
        encrypted_ratio = round(encrypted / total_proto, 2)

    narrative: list[str] = []
    duration_text = f"{duration:.0f}s" if duration else "bounded window"
    narrative.append(
        f"Capture triage: **{packets:,}** packets over **{duration_text}**."
    )
    if encrypted_ratio >= 0.5:
        narrative.append(
            f"Traffic is predominantly encrypted (~{int(encrypted_ratio * 100)}% TLS/QUIC by protocol share)."
        )
    elif protocols:
        narrative.append(f"Top protocols: {', '.join(protocols)}.")

    investigate = [item for item in ranked if item["tier"] == "investigate"][:5]
    if investigate:
        bits = [f"`{item['value']}` ({item['entity_type']})" for item in investigate]
        narrative.append(f"**Investigate next:** {', '.join(bits)}.")
    else:
        routine = [item for item in ranked if item["tier"] != "routine"][:3]
        if routine:
            bits = [f"`{item['value']}`" for item in routine]
            narrative.append(f"**Review:** {', '.join(bits)}.")

    if risky_cleartext:
        narrative.append(
            f"**Cleartext exposure:** {', '.join(risky_cleartext)} observed — validate whether expected."
        )
    elif parsed_data.get("cleartext_protocols"):
        narrative.append("DNS observed in cleartext (routine); no risky cleartext admin/web protocols detected.")

    if workspace_target and focus.get("external_to_target"):
        top_external = focus["external_to_target"][0]
        narrative.append(
            f"Relative to workspace target `{workspace_target}`, top external talker: "
            f"`{top_external['ip']}` ({top_external.get('packets', 0)} packets)."
        )

    device_summary = lan_device_summary(list(parsed_data.get("lan_devices") or []))
    if device_summary:
        narrative.append(f"**LAN devices:** {device_summary}")

    if fingerprint_diff and fingerprint_diff.get("has_changes"):
        changes: list[str] = []
        if fingerprint_diff.get("new_domains"):
            changes.append(f"{len(fingerprint_diff['new_domains'])} new domain(s)")
        if fingerprint_diff.get("new_public_ips"):
            changes.append(f"{len(fingerprint_diff['new_public_ips'])} new public IP(s)")
        if fingerprint_diff.get("new_tls_sni"):
            changes.append(f"{len(fingerprint_diff['new_tls_sni'])} new TLS name(s)")
        if changes:
            narrative.append(f"**Delta vs last capture:** {', '.join(changes)}.")

    if capture_meta and capture_meta.get("stderr") and "dropped" in str(capture_meta["stderr"]).lower():
        narrative.append("Wi‑Fi/kernel reported dropped packets — consider shorter capture or wired interface.")

    network_picture = build_network_picture(
        parsed_data,
        ranked=ranked,
        risky_cleartext=risky_cleartext,
        encrypted_ratio=encrypted_ratio,
    )
    from utils.pcap_resilience import resilience_notes_for_triage

    resilience_notes = resilience_notes_for_triage(
        {
            "encrypted_ratio": encrypted_ratio,
            "risky_cleartext": risky_cleartext,
            "fingerprint_diff": fingerprint_diff,
            "ranked_entities": ranked,
            "focus": focus,
        }
    )

    return {
        "narrative": narrative,
        "narrative_text": " ".join(line.replace("**", "") for line in narrative),
        "ranked_entities": ranked,
        "focus": focus,
        "risky_cleartext": risky_cleartext,
        "encrypted_ratio": encrypted_ratio,
        "fingerprint": fingerprint,
        "fingerprint_diff": fingerprint_diff,
        "investigate_count": len([item for item in ranked if item["tier"] == "investigate"]),
        "network_picture": network_picture,
        "resilience_notes": resilience_notes,
        "talker_buckets": network_picture.get("talker_buckets") or [],
    }

"""SMB / continuity-oriented meaning notes for PCAP triage and findings."""

from __future__ import annotations

from typing import Any

# Plain-language resilience framing for learning and client reporting.
_RESILIENCE_BY_SIGNAL: dict[str, str] = {
    "encrypted_dominant": (
        "Most traffic is encrypted — good baseline for confidentiality. "
        "Focus resilience planning on certificate expiry, DNS trust, and endpoint compromise rather than wire tapping."
    ),
    "mixed_encryption": (
        "Encryption is partial — identify which apps or sites still use cleartext and whether they carry credentials or business data."
    ),
    "dns_only_cleartext": (
        "DNS in cleartext is normal on most networks. For SMBs, consider DNS filtering/logging for malware callbacks — not an emergency by itself."
    ),
    "http_cleartext": (
        "Cleartext HTTP can expose passwords and session cookies on the LAN or ISP path. "
        "Prioritise HTTPS everywhere and retire legacy HTTP services in continuity planning."
    ),
    "risky_admin_cleartext": (
        "Legacy admin protocols (FTP/telnet) are high-risk on any business network. "
        "Treat as urgent hygiene — replace with SSH/TLS and segment from production systems."
    ),
    "new_external_since_last": (
        "A new external endpoint appeared since your last capture — validate it against approved SaaS, updates, and user browsing."
    ),
    "high_external_volume": (
        "Sustained traffic to an unfamiliar external host may indicate sync, backup, or unwanted exfiltration — correlate with running applications."
    ),
    "local_service_exposure": (
        "Active traffic to a local IP often means a LAN server or printer. "
        "Map services (Nmap/TLS review) to understand attack surface for ransomware lateral movement."
    ),
    "intel_clean": (
        "Reputation checks are clean — low immediate threat signal, but still verify the host is an expected vendor or SaaS provider."
    ),
    "intel_suspicious": (
        "Negative reputation is a prioritisation signal — isolate if unexpected, then trace which device initiated the connection from the capture."
    ),
    "nmap_open_ports": (
        "Open ports on a LAN asset define what could be hit during an outage or intrusion. Document owners and disable unused services."
    ),
    "domain_unexpected": (
        "Unexpected domain names in TLS/DNS can be benign (ads, updates) or policy violations — confirm against acceptable-use and vendor lists."
    ),
}


def resilience_note(signal: str) -> str:
    return _RESILIENCE_BY_SIGNAL.get(signal, "")


def resilience_notes_for_triage(triage: dict[str, Any]) -> list[dict[str, str]]:
    """Return titled resilience implications for display after capture triage."""
    notes: list[dict[str, str]] = []
    ratio = float(triage.get("encrypted_ratio") or 0)
    if ratio >= 0.7:
        notes.append({"title": "Encryption posture", "note": resilience_note("encrypted_dominant")})
    elif ratio > 0:
        notes.append({"title": "Encryption posture", "note": resilience_note("mixed_encryption")})

    risky = triage.get("risky_cleartext") or []
    if any(p in {"ftp", "telnet"} for p in risky):
        notes.append({"title": "Legacy cleartext", "note": resilience_note("risky_admin_cleartext")})
    elif "http" in risky:
        notes.append({"title": "HTTP cleartext", "note": resilience_note("http_cleartext")})
    elif not risky:
        notes.append({"title": "DNS cleartext", "note": resilience_note("dns_only_cleartext")})

    diff = triage.get("fingerprint_diff") or {}
    if diff.get("new_public_ips") or diff.get("new_domains"):
        notes.append({"title": "Change detection", "note": resilience_note("new_external_since_last")})

    investigate = [item for item in (triage.get("ranked_entities") or []) if item.get("tier") == "investigate"]
    local = [item for item in investigate if item.get("classification") == "local"]
    external = [item for item in investigate if item.get("classification") == "external"]
    if local:
        notes.append({"title": "LAN assets", "note": resilience_note("local_service_exposure")})
    if external:
        notes.append({"title": "External talkers", "note": resilience_note("high_external_volume")})

    return notes[:6]


def resilience_note_for_finding_title(title: str) -> str:
    """Map common finding titles to resilience learning notes."""
    lowered = title.lower()
    if "http traffic" in lowered:
        return resilience_note("http_cleartext")
    if "risky cleartext" in lowered or "cleartext protocol" in lowered:
        return resilience_note("risky_admin_cleartext")
    if "dns in cleartext" in lowered or "dns queries" in lowered:
        return resilience_note("dns_only_cleartext")
    if lowered.startswith("investigate"):
        if "domain" in lowered:
            return resilience_note("domain_unexpected")
        return resilience_note("high_external_volume")
    return ""


def attach_resilience_to_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    enriched: list[dict[str, Any]] = []
    for finding in findings:
        item = dict(finding)
        note = resilience_note_for_finding_title(str(item.get("title") or ""))
        if note:
            item["resilience_note"] = note
        enriched.append(item)
    return enriched

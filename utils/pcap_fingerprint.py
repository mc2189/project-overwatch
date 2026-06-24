"""Capture fingerprints and temporal diff for PCAP / live-capture analysis."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from utils.live_capture import live_capture_dir
from utils.web_port_planner import is_private_ipv4_target

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def _normalise_domain(value: str) -> str:
    return str(value).strip().lower().rstrip(".")


def _normalise_ip(value: str) -> str:
    return str(value).strip()


def build_capture_fingerprint(parsed_data: dict[str, Any]) -> dict[str, Any]:
    """Build a comparable fingerprint from PCAP review parsed_data."""
    preview = parsed_data.get("entities_preview") or {}
    domains = sorted({_normalise_domain(d) for d in preview.get("domains") or [] if d})
    ips = sorted({_normalise_ip(ip) for ip in preview.get("ips") or [] if ip})
    public_ips = [ip for ip in ips if _IPV4_RE.match(ip) and not is_private_ipv4_target(ip)]
    private_ips = [ip for ip in ips if _IPV4_RE.match(ip) and is_private_ipv4_target(ip)]

    cleartext = [
        str(p).lower()
        for p in (parsed_data.get("cleartext_protocols") or [])
        if str(p).lower() != "dns"
    ]
    protocols = [
        str(item.get("protocol", "")).lower()
        for item in (parsed_data.get("protocols") or [])
        if item.get("protocol")
    ]
    top_flows = [
        str(item.get("conversation") or item.get("flow") or "")
        for item in (parsed_data.get("high_volume_flows") or parsed_data.get("top_conversations") or [])[:10]
        if item
    ]

    return {
        "filename": parsed_data.get("filename"),
        "sha256": parsed_data.get("sha256"),
        "packet_count": int(parsed_data.get("packets_analysed") or parsed_data.get("packet_count") or 0),
        "duration_seconds": parsed_data.get("duration_seconds"),
        "domains": domains,
        "ips": ips,
        "public_ips": public_ips,
        "private_ips": private_ips,
        "cleartext_protocols": cleartext,
        "protocols": protocols[:12],
        "top_flows": [flow for flow in top_flows if flow],
        "http_hosts": sorted(
            {
                str(entry.get("host", "")).lower()
                for entry in (parsed_data.get("http_entries") or [])
                if entry.get("host")
            }
        ),
        "tls_sni": sorted(
            {
                _normalise_domain(entry.get("server_name", ""))
                for entry in (parsed_data.get("tls_sni") or [])
                if entry.get("server_name")
            }
        ),
    }


def diff_fingerprints(
    current: dict[str, Any],
    previous: dict[str, Any],
) -> dict[str, Any]:
    """Return set differences between two capture fingerprints."""
    def _delta(key: str) -> list[str]:
        cur = set(current.get(key) or [])
        prev = set(previous.get(key) or [])
        return sorted(cur - prev)

    return {
        "previous_filename": previous.get("filename"),
        "previous_sha256": previous.get("sha256"),
        "new_domains": _delta("domains"),
        "new_ips": _delta("ips"),
        "new_public_ips": _delta("public_ips"),
        "new_tls_sni": _delta("tls_sni"),
        "new_http_hosts": _delta("http_hosts"),
        "new_cleartext_protocols": _delta("cleartext_protocols"),
        "packet_count_delta": int(current.get("packet_count") or 0) - int(previous.get("packet_count") or 0),
        "has_changes": any(
            _delta(key)
            for key in ("domains", "ips", "public_ips", "tls_sni", "http_hosts", "cleartext_protocols")
        ),
    }


def enrich_pcap_parsed_data(
    parsed_data: dict[str, Any],
    *,
    case_id: int = 0,
    workspace_target: str = "",
    capture_meta: dict[str, Any] | None = None,
    save_fingerprint: bool = True,
) -> dict[str, Any]:
    """Attach fingerprint, diff, and triage narrative to PCAP parsed_data."""
    from utils.pcap_triage import build_triage_report

    fingerprint = build_capture_fingerprint(parsed_data)
    prior = latest_prior_fingerprint(case_id, exclude_filename=parsed_data.get("filename")) if case_id else None
    fingerprint_diff = diff_fingerprints(fingerprint, prior) if prior else None
    if save_fingerprint and case_id:
        save_capture_fingerprint(case_id, fingerprint)
    triage = build_triage_report(
        parsed_data,
        workspace_target=workspace_target,
        fingerprint=fingerprint,
        fingerprint_diff=fingerprint_diff,
        capture_meta=capture_meta,
    )
    parsed_data["fingerprint"] = fingerprint
    if fingerprint_diff:
        parsed_data["fingerprint_diff"] = fingerprint_diff
    parsed_data["triage"] = triage
    return triage


def list_case_capture_fingerprints(
    case_id: int,
    *,
    exclude_filename: str | None = None,
) -> list[dict[str, Any]]:
    """Load stored fingerprints for prior captures in a case (newest first)."""
    index_path = live_capture_dir(case_id) / "_fingerprints.json"
    if not index_path.is_file():
        return []
    try:
        payload = json.loads(index_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    items = payload if isinstance(payload, list) else payload.get("captures") or []
    cleaned: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if exclude_filename and item.get("filename") == exclude_filename:
            continue
        cleaned.append(item)
    return cleaned


def save_capture_fingerprint(case_id: int, fingerprint: dict[str, Any]) -> None:
    """Append or update a capture fingerprint index for temporal diff."""
    index_path = live_capture_dir(case_id) / "_fingerprints.json"
    existing = list_case_capture_fingerprints(case_id)
    filename = fingerprint.get("filename")
    updated = [item for item in existing if item.get("filename") != filename]
    updated.insert(0, fingerprint)
    updated = updated[:30]
    index_path.parent.mkdir(parents=True, exist_ok=True)
    index_path.write_text(json.dumps(updated, indent=2), encoding="utf-8")


def latest_prior_fingerprint(
    case_id: int,
    *,
    exclude_filename: str | None = None,
) -> dict[str, Any] | None:
    items = list_case_capture_fingerprints(case_id, exclude_filename=exclude_filename)
    return items[0] if items else None

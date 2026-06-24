"""Concise module-specific report summary blocks."""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any

from modules.module_registry import get_module


def _module_label(module_id: str) -> str:
    module = get_module(module_id)
    return module.display_name if module else module_id


def _obs_payload(observation: dict[str, Any]) -> dict[str, Any]:
    data_json = observation.get("data_json")
    if not data_json:
        return {}
    try:
        return json.loads(data_json) if isinstance(data_json, str) else dict(data_json)
    except (TypeError, json.JSONDecodeError):
        return {}


def _concise_observation_block(
    observations: list[dict[str, Any]],
    *,
    title: str,
    intro: str,
    module_ids: set[str],
) -> list[str]:
    rows = [item for item in observations if item.get("module_id") in module_ids]
    if not rows:
        return []
    lines = [f"## {title}", "", intro, ""]
    for observation in rows[:8]:
        payload = _obs_payload(observation)
        lines.append(f"### {observation.get('title') or _module_label(observation.get('module_id', ''))}")
        lines.append("")
        lines.append(f"- **What was reviewed:** {_module_label(observation.get('module_id', ''))}")
        lines.append(f"- **What was observed:** {observation.get('summary') or '_No summary._'}")
        notable = payload.get("notable_count") or payload.get("paths_checked") or payload.get("indicators")
        if notable is not None:
            lines.append(f"- **Notable items:** {notable}")
        lines.append("- **Suggested action:** Review whether observed conditions are expected before sharing externally.")
        lines.append("- **Evidence reference:** See evidence summary and linked observation record.")
        lines.append(f"- **Point-in-time note:** Created {observation.get('created_at', '-')}")
        lines.append("")
    return lines


def build_web_posture_summary_lines(observations: list[dict[str, Any]]) -> list[str]:
    module_ids = {
        "infra_website_metadata",
        "infra_http_security",
        "infra_tls_review",
        "infra_web_stack_identifier",
        "infra_web_path_review",
        "infra_email_security",
        "infra_domain_intel",
    }
    rows = [item for item in observations if item.get("module_id") in module_ids]
    if not rows:
        return []
    lines = [
        "## Web Posture Summary",
        "",
        "_Point-in-time web, TLS, email, and domain posture observations based on available evidence. "
        "Observations indicate configuration visible at review time — not confirmed compromise._",
        "",
    ]
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in rows:
        grouped[row.get("module_id") or "unknown"].append(row)
    for module_id in sorted(grouped):
        lines.append(f"### {_module_label(module_id)}")
        lines.append("")
        for observation in grouped[module_id][:3]:
            payload = _obs_payload(observation)
            lines.append(f"- **Observed:** {observation.get('summary') or '_No summary._'}")
            if module_id == "infra_tls_review":
                cert = payload.get("certificate") or {}
                if cert.get("subject_cn"):
                    lines.append(f"- **Certificate subject:** {cert.get('subject_cn')}")
                if cert.get("days_until_expiry") is not None:
                    lines.append(f"- **Days until expiry:** {cert.get('days_until_expiry')}")
            if module_id == "infra_http_security":
                missing = payload.get("missing_headers") or []
                if missing:
                    lines.append(f"- **Missing headers (sample):** {', '.join(str(item) for item in missing[:6])}")
            if module_id == "infra_email_security":
                spf = payload.get("spf") or {}
                dmarc = payload.get("dmarc") or {}
                lines.append(
                    f"- **SPF/DMARC observed:** SPF={'present' if spf.get('present') else 'not observed'}, "
                    f"DMARC={'present' if dmarc.get('present') else 'not observed'}"
                )
            lines.append("- **Action:** Review whether observed posture matches intended exposure.")
        lines.append("")
    return lines


def build_threat_intel_summary_lines(observations: list[dict[str, Any]]) -> list[str]:
    module_ids = {
        "intel_virustotal",
        "intel_abuseipdb",
        "intel_greynoise",
        "intel_shodan",
        "intel_urlhaus",
    }
    return _concise_observation_block(
        observations,
        title="Threat Intelligence Summary",
        intro=(
            "_Third-party reputation and lookup signals only. These suggest further review — "
            "they do not confirm malicious activity._"
        ),
        module_ids=module_ids,
    )


def build_lan_recon_summary_lines(observations: list[dict[str, Any]]) -> list[str]:
    capture_rows = [
        item
        for item in observations
        if item.get("module_id") in {"net_live_capture", "net_pcap_review"}
    ]
    if not capture_rows:
        return []
    lines = [
        "## LAN / Capture Recon Summary",
        "",
        "_Based on supplied capture file(s) or bounded Personal Lab capture only — not continuous monitoring._",
        "",
    ]
    for observation in capture_rows[:6]:
        payload = _obs_payload(observation)
        lines.append(f"### {observation.get('title') or 'Capture review'}")
        lines.append("")
        lines.append(f"- **Observed:** {observation.get('summary') or '_No summary._'}")
        devices = payload.get("lan_devices") or payload.get("devices") or []
        if devices:
            lines.append(f"- **LAN devices inferred:** {len(devices)}")
        triage = payload.get("triage_narrative") or (payload.get("pcap_review") or {}).get("triage_narrative")
        if triage:
            lines.append(f"- **Triage note:** {str(triage)[:240]}")
        lines.append("- **Action:** Review priority follow-ups before external reporting.")
        lines.append("")
    return lines

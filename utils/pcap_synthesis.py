"""Synthesise capture observations with follow-up module runs."""

from __future__ import annotations

import re
from typing import Any

from utils.pcap_resilience import resilience_note

_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")

_INTEL_SUSPICIOUS_RE = re.compile(
    r"malicious|abuse|suspicious|high risk|confidence score.*?([6-9]\d|[1-9]\d{2})",
    re.I,
)
_INTEL_CLEAN_RE = re.compile(r"clean|low risk|0 malicious|no malicious|benign", re.I)
_NMAP_OPEN_RE = re.compile(r"open port|(\d+)/tcp\s+open|service", re.I)


def _capture_entity_set(parsed_data: dict[str, Any]) -> set[str]:
    entities: set[str] = set()
    preview = parsed_data.get("entities_preview") or {}
    for ip in preview.get("ips") or []:
        entities.add(str(ip).strip().lower())
    for domain in preview.get("domains") or []:
        entities.add(str(domain).strip().lower().rstrip("."))
    triage = parsed_data.get("triage") or {}
    for item in triage.get("ranked_entities") or []:
        value = str(item.get("value") or "").strip().lower()
        if value:
            entities.add(value.rstrip("."))
    return entities


def _capture_signal_for_target(target: str, parsed_data: dict[str, Any]) -> str:
    target_key = target.strip().lower().rstrip(".")
    triage = parsed_data.get("triage") or {}
    for item in triage.get("ranked_entities") or []:
        if str(item.get("value", "")).lower().rstrip(".") == target_key:
            tier = item.get("tier", "seen")
            packets = item.get("packets", 0)
            classification = item.get("classification", "")
            return f"Seen in capture ({packets} packets, {classification}, tier={tier})"
    if _IPV4_RE.match(target_key):
        return "IP appeared in capture talkers"
    return "Name appeared in DNS/TLS metadata"


def _module_outcome_line(module_id: str, summary: str, success: bool) -> tuple[str, str]:
    """Return (outcome_label, resilience_key) from an operation summary."""
    text = summary or ""
    if not success:
        return "Module did not complete successfully", ""

    if module_id == "intel_abuseipdb":
        if _INTEL_SUSPICIOUS_RE.search(text):
            return "Reputation: elevated risk or abuse signals reported", "intel_suspicious"
        if _INTEL_CLEAN_RE.search(text):
            return "Reputation: no strong malicious signals in this check", "intel_clean"
        return "Reputation lookup completed — review score in module output", "intel_clean"

    if module_id in {"intel_greynoise", "intel_virustotal", "intel_shodan"}:
        if _INTEL_SUSPICIOUS_RE.search(text):
            return "Threat intel: suspicious indicators returned", "intel_suspicious"
        return "Threat intel: no strong negative signals in summary", "intel_clean"

    if module_id == "infra_nmap":
        if _NMAP_OPEN_RE.search(text):
            return "Service discovery: responsive ports/services identified", "nmap_open_ports"
        return "Service discovery completed — confirm host was reachable", "local_service_exposure"

    if module_id == "infra_domain_intel":
        return "Domain intelligence gathered — review DNS and registration data", "domain_unexpected"

    if module_id in {"infra_tls_review", "infra_http_security"}:
        return "Web/TLS posture reviewed — check certificate and header gaps", "http_cleartext"

    return f"{module_id} completed", ""


def build_capture_followup_synthesis(
    capture_parsed: dict[str, Any],
    operations: list[dict[str, Any]],
    *,
    capture_sha256: str | None = None,
    limit: int = 8,
) -> list[dict[str, Any]]:
    """
    Link recent module operations to capture entities and produce learning-oriented synthesis lines.

    capture_parsed may be live-capture pcap_review parsed_data or standalone PCAP parsed_data.
    """
    entities = _capture_entity_set(capture_parsed)
    if not entities or not operations:
        return []

    synthesis: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()

    for op in operations:
        module_id = str(op.get("module_id") or "")
        target = str(op.get("target") or "").strip()
        if not module_id or not target:
            continue
        target_key = target.lower().rstrip(".")
        if target_key not in entities and not any(
            target_key in entity or entity in target_key for entity in entities
        ):
            continue
        key = (module_id, target_key)
        if key in seen:
            continue
        seen.add(key)

        success = str(op.get("status") or "").lower() in {"completed", "complete", "completed_with_warnings", "partial"}
        summary = str(op.get("summary") or "")
        outcome, resilience_key = _module_outcome_line(module_id, summary, success)
        capture_signal = _capture_signal_for_target(target, capture_parsed)

        line = f"Capture → {module_id} on `{target}`: {capture_signal}. Follow-up: {outcome}."
        synthesis.append(
            {
                "target": target,
                "module_id": module_id,
                "capture_signal": capture_signal,
                "module_outcome": outcome,
                "summary_line": line,
                "resilience_note": resilience_note(resilience_key) if resilience_key else "",
                "operation_summary": summary[:240],
                "capture_sha256": capture_sha256,
            }
        )
        if len(synthesis) >= limit:
            break

    return synthesis

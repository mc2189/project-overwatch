"""Rule-based executive summary generation for Report Builder v2."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from typing import Any

from modules.module_registry import get_module
from utils.operating_context import CLIENT_ENGAGEMENT, PERSONAL_LAB, PASSIVE_RESEARCH, operating_context_label


@dataclass
class ExecutiveSummaryContext:
    operating_context: str
    report_type_label: str | None
    findings: list[dict[str, Any]]
    open_findings: list[dict[str, Any]]
    observations: list[dict[str, Any]]
    evidence_items: list[dict[str, Any]]
    modules_used: list[str]
    highest_severity: str | None
    entity_count: int
    operation_count: int


def _severity_counts(findings: list[dict[str, Any]]) -> Counter[str]:
    counts: Counter[str] = Counter()
    for finding in findings:
        severity = (finding.get("severity") or "info").lower()
        counts[severity] += 1
    return counts


def _module_label(module_id: str) -> str:
    module = get_module(module_id)
    return module.display_name if module else module_id


def _theme_phrases(findings: list[dict[str, Any]], modules_used: list[str]) -> list[str]:
    themes: list[str] = []
    titles = " ".join((item.get("title") or "").lower() for item in findings)
    module_set = set(modules_used)

    if any(word in titles for word in ("remote", "ssh", "rdp", "smb", "vnc", "telnet")):
        themes.append("exposed remote-access services")
    if "infra_http_security" in module_set or "http header" in titles or "security header" in titles:
        themes.append("web security header observations")
    if "infra_tls_review" in module_set or "tls" in titles or "certificate" in titles:
        themes.append("TLS/certificate review items")
    if "net_pcap_review" in module_set or "net_live_capture" in module_set or "cleartext" in titles:
        themes.append("packet capture observations")
    if "evidence_file_metadata" in module_set or "metadata" in titles or "gps" in titles:
        themes.append("file metadata privacy considerations")
    if any(word in titles for word in ("web stack", "cms", "wordpress", "drupal")):
        themes.append("visible web technology indicators")
    if any(word in titles for word in ("reputation", "virustotal", "abuse", "shodan", "urlhaus")):
        themes.append("third-party reputation lookup signals")
    if any(word in titles for word in ("email", "dmarc", "spf")):
        themes.append("email security posture observations")
    if "infra_nmap" in module_set and not themes:
        themes.append("network service observations")
    return themes[:4]


def build_executive_summary_prose(context: ExecutiveSummaryContext) -> str:
    """Build a cautious plain-English executive summary without AI/API calls."""
    counts = _severity_counts(context.findings)
    notable = [severity for severity in ("critical", "high", "medium", "low") if counts.get(severity)]
    themes = _theme_phrases(context.findings, context.modules_used)

    if not context.findings and not context.observations:
        if context.operating_context == PERSONAL_LAB:
            return (
                "This Personal Lab review did not record findings or observations in the selected scope. "
                "Based on available evidence, no advisory items were captured for this case at generation time."
            )
        return (
            "This review did not record findings or observations in the selected scope. "
            "Based on available evidence, no advisory items were captured for this case at generation time."
        )

    opening = "This review identified "
    if context.open_findings:
        opening += f"{len(context.open_findings)} open advisory item(s)"
    elif context.findings:
        opening += f"{len(context.findings)} recorded advisory item(s)"
    else:
        opening += "observations but no selected findings"

    if context.report_type_label:
        opening += f" for the **{context.report_type_label}** pack"
    opening += ". "

    if themes:
        theme_text = ", ".join(themes[:-1]) + (" and " + themes[-1] if len(themes) > 1 else themes[0])
        opening += f"The most notable themes relate to {theme_text}. "
    elif context.modules_used:
        module_names = ", ".join(_module_label(item) for item in context.modules_used[:4])
        opening += f"Observations were drawn from modules including {module_names}. "

    if context.highest_severity in {"critical", "high"}:
        opening += (
            f"The highest recorded severity is **{context.highest_severity}**. "
            "These items should be reviewed promptly to confirm whether they reflect expected configuration."
        )
    elif context.highest_severity == "medium":
        opening += (
            "Several medium-severity advisory items were recorded. "
            "Review whether the observed conditions are expected for the assessed target and audience."
        )
    elif notable:
        opening += (
            "No critical issue was recorded in the selected findings, "
            "but lower-severity items should still be reviewed to confirm expected exposure."
        )
    else:
        opening += (
            "Most recorded items are informational context only. "
            "Review whether they are useful before sharing externally."
        )

    context_bits: list[str] = []
    if context.operating_context == PERSONAL_LAB:
        context_bits.append(
            "This summary reflects Personal Lab / self-owned testing and should not be presented as formal client work."
        )
    elif context.operating_context == CLIENT_ENGAGEMENT:
        context_bits.append(
            "Where client engagement context is linked, scope and authorisation limitations still apply."
        )
    else:
        context_bits.append(
            "Results are based on passive/public or direct observations as recorded — not confirmed live compromise."
        )

    context_bits.append(
        f"Based on available evidence ({len(context.evidence_items)} evidence item(s), "
        f"{len(context.observations)} observation(s)), this is a point-in-time review."
    )
    return opening + " ".join(context_bits)


def build_executive_summary_stats_lines(context: ExecutiveSummaryContext) -> list[str]:
    """Optional bullet stats beneath the prose summary."""
    counts = _severity_counts(context.findings)
    lines = [
        f"- Open findings: {len(context.open_findings)}",
        f"- Selected findings: {len(context.findings)}",
        f"- Highest severity: {context.highest_severity or 'None recorded'}",
        f"- Severity breakdown: critical={counts.get('critical', 0)}, high={counts.get('high', 0)}, "
        f"medium={counts.get('medium', 0)}, low={counts.get('low', 0)}, info={counts.get('info', 0)}",
        f"- Observations: {len(context.observations)}",
        f"- Evidence items: {len(context.evidence_items)}",
        f"- Entities reviewed: {context.entity_count}",
        f"- Operations recorded: {context.operation_count}",
        f"- Operating context: {operating_context_label(context.operating_context)}",
    ]
    if context.modules_used:
        lines.append(
            "- Modules represented: "
            + ", ".join(_module_label(module_id) for module_id in context.modules_used[:8])
        )
    return lines

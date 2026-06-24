"""Build and save Markdown case reports for Project Overwatch."""

from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from database.db_setup import (
    PROJECT_ROOT,
    REPORT_EXCLUDED_STATUSES,
    effective_finding_severity,
    finding_status_counts,
    get_case,
    get_db_conn,
    list_entities,
    list_evidence_finding_links,
    list_evidence_items,
    list_findings,
    list_observations,
    list_operations,
    list_batch_queue_runs,
    list_batch_queue_items,
    list_relationships,
    normalize_finding_status,
)
from modules.module_registry import get_module
from utils.finding_interpreter import is_source_notice
from utils.evidence_storage import read_spilled_content
from utils.evidence_model import (
    CONFIDENCE_GUIDANCE,
    EVIDENCE_TYPES,
    RELIABILITY_LEVELS,
    evidence_type_label,
    evidence_wording,
    reliability_label,
)
from utils.report_redaction import (
    RedactionOption,
    apply_redactions,
    parse_custom_regex_patterns,
)
from utils.security import redact_secrets_from_text
from utils.report_settings import ReportBranding, branding_footer_lines, branding_header_lines, load_report_branding
from utils.report_types import FindingSelectionMode, get_report_type

SEVERITY_SECTION_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: index for index, name in enumerate(reversed(SEVERITY_SECTION_ORDER))}
ReportTemplate = Literal["full", "executive"]


@dataclass
class ReportOptions:
    include_closed_findings: bool = False
    include_raw_appendix: bool = False
    include_graph_appendix: bool = False
    template: ReportTemplate = "full"
    redactions: set[RedactionOption] = field(default_factory=set)
    branding: ReportBranding | None = None
    custom_redaction_terms: list[str] = field(default_factory=list)
    custom_redaction_regex: str = ""
    include_engagement_context: bool = False
    operating_context: str | None = None
    report_type_id: str | None = None
    sections: frozenset[str] | None = None
    finding_selection_mode: FindingSelectionMode = "active"
    selected_finding_ids: frozenset[int] = field(default_factory=frozenset)
    finding_module_filter: frozenset[str] = field(default_factory=frozenset)
    finding_severity_filter: frozenset[str] = field(default_factory=frozenset)
    analyst_notes: str = ""
    include_evidence_summary: bool = True


def _lookup_notices_from_observations(observations: list[dict[str, Any]]) -> list[str]:
    notices: list[str] = []
    seen: set[str] = set()
    for observation in observations:
        try:
            payload = json.loads(observation.get("data_json") or "{}")
        except json.JSONDecodeError:
            continue
        for warning in payload.get("warnings") or []:
            cleaned = str(warning).strip()
            if cleaned and cleaned not in seen:
                seen.add(cleaned)
                notices.append(cleaned)
        for finding in payload.get("interpreter_findings") or []:
            if not is_source_notice(finding):
                continue
            text = (finding.get("explanation") or finding.get("title") or "").strip()
            if text and text not in seen:
                seen.add(text)
                notices.append(text)
    return notices


def _parse_suggested_actions(finding: dict[str, Any]) -> list[str]:
    try:
        actions = json.loads(finding.get("suggested_actions_json") or "[]")
    except (json.JSONDecodeError, TypeError):
        return []
    return [action for action in actions if action]


def _entity_display(entity: dict[str, Any] | None, entity_id: int | None) -> str:
    if entity is None:
        return str(entity_id) if entity_id is not None else "-"
    return entity.get("label") or entity.get("value") or str(entity["id"])


def _module_display(module_id: str | None) -> str:
    if not module_id:
        return "unknown"
    module = get_module(module_id)
    return module.display_name if module else module_id


def _format_operation_run_modes(operations: list[dict[str, Any]]) -> str:
    if not operations:
        return "None recorded"
    counts: dict[str, int] = defaultdict(int)
    for operation in operations:
        label = operation.get("run_mode_label") or "Unknown"
        counts[str(label)] += 1
    return ", ".join(f"{label}: {count}" for label, count in sorted(counts.items())) or "None recorded"


def _highest_severity(findings: list[dict[str, Any]]) -> str | None:
    if not findings:
        return None
    return max(
        findings,
        key=lambda item: SEVERITY_RANK.get((item.get("severity") or "info").lower(), 0),
    ).get("severity", "info")


def _safe_filename_part(value: str) -> str:
    cleaned = re.sub(r"[^\w\-]+", "_", value.strip().lower())
    cleaned = re.sub(r"_+", "_", cleaned).strip("_")
    return cleaned or "case"


def _load_case_data(case_id: int, conn) -> dict[str, Any]:
    return {
        "case": get_case(case_id, conn=conn),
        "entities": list_entities(case_id=case_id, conn=conn),
        "relationships": list_relationships(case_id=case_id, conn=conn),
        "observations": list_observations(case_id=case_id, conn=conn),
        "operations": list_operations(case_id=case_id, conn=conn),
        "findings": list_findings(case_id=case_id, conn=conn),
        "batch_queue_runs": list_batch_queue_runs(case_id, limit=10, conn=conn),
        "batch_queue_items": list_batch_queue_items(case_id, conn=conn),
        "evidence_items": list_evidence_items(case_id=case_id, conn=conn),
        "evidence_finding_links": list_evidence_finding_links(case_id=case_id, conn=conn),
    }


def _linked_evidence_for_finding(
    finding: dict[str, Any],
    evidence_items: list[dict[str, Any]],
    evidence_links: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    finding_id = finding.get("id")
    observation_id = finding.get("observation_id")
    linked_ids = {
        link["evidence_id"]
        for link in evidence_links
        if link.get("finding_id") == finding_id
    }
    linked: list[dict[str, Any]] = []
    seen: set[int] = set()
    for item in evidence_items:
        if item["id"] in linked_ids or item.get("finding_id") == finding_id:
            linked.append(item)
            seen.add(item["id"])
    if observation_id is not None:
        for item in evidence_items:
            if item.get("observation_id") == observation_id and item["id"] not in seen:
                linked.append(item)
                seen.add(item["id"])
    return linked


def _evidence_summary_lines(evidence_items: list[dict[str, Any]]) -> list[str]:
    lines = ["## Evidence Summary", ""]
    if not evidence_items:
        lines.append("_No evidence locker items recorded for this case._")
        lines.append("")
        return lines

    lines.append(f"- Total evidence items: {len(evidence_items)}")
    lines.append("")

    by_module: dict[str, int] = defaultdict(int)
    by_type: dict[str, int] = defaultdict(int)
    by_reliability: dict[str, int] = defaultdict(int)
    for item in evidence_items:
        by_module[item.get("module_id") or "unknown"] += 1
        by_type[item.get("evidence_type") or "unknown"] += 1
        by_reliability[item.get("reliability") or "unknown"] += 1

    lines.append("**By module:**")
    for module_id in sorted(by_module):
        lines.append(f"- `{module_id}`: {by_module[module_id]}")
    lines.append("")
    lines.append("**By evidence type:**")
    for evidence_type in sorted(by_type):
        lines.append(f"- {evidence_type_label(evidence_type)}: {by_type[evidence_type]}")
    lines.append("")
    lines.append("**By reliability:**")
    for reliability in sorted(by_reliability):
        lines.append(f"- {reliability_label(reliability)}: {by_reliability[reliability]}")
    lines.append("")
    return lines


def _graph_appendix_lines(
    entities: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    reports_dir: Path,
    basename: str,
) -> list[str]:
    from utils.report_export import export_graph_snapshot

    lines = ["### Entity relationship graph", ""]
    if not entities:
        lines.append("_No graph data available._")
        return lines

    png_path = reports_dir / f"{basename}_graph.png"
    saved = export_graph_snapshot(entities, relationships, findings, png_path)
    if saved and saved.exists():
        lines.append(f"![Entity relationship graph]({saved.name})")
        lines.append("")
        lines.append(
            f"_Graph snapshot: {len(entities)} entities, {len(relationships)} relationships. "
            "Node colour reflects highest open/reviewed finding severity._"
        )
    else:
        lines.append(
            f"_Graph snapshot unavailable. Data present: {len(entities)} entities, "
            f"{len(relationships)} relationships. "
            "Install `kaleido` for PNG export, or view the graph in the application._"
        )
    lines.append("")
    return lines


def build_case_report(
    case_id: int,
    include_closed_findings: bool = False,
    include_raw_appendix: bool = False,
    *,
    options: ReportOptions | None = None,
    include_graph_appendix: bool | None = None,
    template: ReportTemplate | None = None,
    redact_ips: bool = False,
    redact_emails: bool = False,
    redact_domains: bool = False,
) -> str:
    """Build a Markdown case report for the given case ID."""
    if options is None:
        options = ReportOptions(
            include_closed_findings=include_closed_findings,
            include_raw_appendix=include_raw_appendix,
        )
    if include_graph_appendix is not None:
        options.include_graph_appendix = include_graph_appendix
    if template is not None:
        options.template = template
    if redact_ips:
        options.redactions.add("ipv4")
    if redact_emails:
        options.redactions.add("email")
    if redact_domains:
        options.redactions.add("domain")

    if options.branding is None:
        options.branding = load_report_branding()

    from utils.report_finding_selection import filter_findings_for_report
    from utils.report_sections import section_enabled
    from utils.report_executive_summary import ExecutiveSummaryContext, build_executive_summary_prose, build_executive_summary_stats_lines
    from utils.report_recommended_actions import build_recommended_actions, recommended_actions_markdown
    from utils.report_module_summaries import (
        build_lan_recon_summary_lines,
        build_threat_intel_summary_lines,
        build_web_posture_summary_lines,
    )

    report_type = get_report_type(options.report_type_id)
    if report_type and options.sections is None:
        options.sections = report_type.default_sections
    if report_type and options.operating_context is None:
        options.operating_context = report_type.default_operating_context

    def enabled(section_id: str) -> bool:
        return section_enabled(options.sections, section_id, legacy_template=options.template)

    conn = get_db_conn()
    try:
        data = _load_case_data(case_id, conn)
    finally:
        conn.close()

    case = data["case"]
    branding = options.branding or ReportBranding()
    custom_regex_patterns = (
        parse_custom_regex_patterns(options.custom_redaction_regex)
        if options.custom_redaction_regex
        else []
    )

    def finalize_report(body: str) -> str:
        body = redact_secrets_from_text(body)
        footer = branding_footer_lines(branding)
        if footer:
            body = body.rstrip() + "\n\n" + "\n".join(footer)
        return apply_redactions(
            body,
            options.redactions,
            custom_terms=options.custom_redaction_terms,
            custom_regex_patterns=custom_regex_patterns,
        )

    if case is None:
        return finalize_report(
            "\n".join(
                [
                    "# Project Overwatch Case Report",
                    "",
                    *branding_header_lines(branding),
                    f"_No case found with ID {case_id}._",
                ]
            )
        )

    entities = data["entities"]
    relationships = data["relationships"]
    observations = data["observations"]
    operations = data["operations"]
    all_findings = data["findings"]
    batch_queue_runs = data.get("batch_queue_runs") or []
    evidence_items = data.get("evidence_items") or []
    evidence_links = data.get("evidence_finding_links") or []

    entity_by_id = {entity["id"]: entity for entity in entities}
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    template_label = "Executive" if options.template == "executive" else "Full technical"
    report_type_label = report_type.label if report_type else None

    all_findings_filtered = filter_findings_for_report(
        all_findings,
        mode=options.finding_selection_mode,
        include_closed=options.include_closed_findings,
        selected_ids=options.selected_finding_ids,
        module_filter=options.finding_module_filter,
        severity_filter=options.finding_severity_filter,
    )
    if options.include_closed_findings and options.finding_selection_mode == "active":
        report_findings = list(all_findings_filtered) or [
            finding
            for finding in all_findings
            if normalize_finding_status(finding.get("status")) not in REPORT_EXCLUDED_STATUSES
        ]
    else:
        report_findings = list(all_findings_filtered)

    open_findings = [
        finding for finding in all_findings if normalize_finding_status(finding.get("status")) == "open"
    ]
    status_counts = finding_status_counts(case["id"])
    status_summary = ", ".join(
        f"{status}: {status_counts.get(status, 0)}"
        for status in ("open", "in_review", "action_required", "accepted", "false_positive", "closed")
        if status_counts.get(status, 0)
    ) or "None recorded"
    highest = _highest_severity(
        [
            {**finding, "severity": effective_finding_severity(finding)}
            for finding in (report_findings if report_findings else open_findings)
        ]
    )

    modules_used = sorted(
        {
            module_id
            for module_id in (
                *(observation.get("module_id") for observation in observations),
                *(operation.get("module_id") for operation in operations),
                *(finding.get("module_id") for finding in all_findings),
            )
            if module_id
        }
    )
    modules_summary = ", ".join(_module_display(module_id) for module_id in modules_used) or "None recorded"

    lines: list[str] = [
        "# Project Overwatch Case Report",
        "",
        *branding_header_lines(branding),
        f"_Generated: {generated_at} · Template: {template_label}"
        + (f" · Report type: {report_type_label}" if report_type_label else "")
        + "_",
        "",
    ]

    if enabled("cover_case_summary"):
        lines.extend(
            [
                "## Case Summary",
                "",
                f"- **Case name:** {case.get('name', 'Unnamed')}",
                f"- **Case ID:** {case.get('id')}",
                f"- **Status:** {case.get('status', 'open')}",
                f"- **Created:** {case.get('created_at', 'unknown')}",
                f"- **Updated:** {case.get('updated_at', 'unknown')}",
                f"- **Description:** {case.get('description') or '_No description provided._'}",
                "",
            ]
        )

    from utils.operating_context import (
        CLIENT_ENGAGEMENT,
        PASSIVE_RESEARCH,
        PERSONAL_LAB,
        operating_context_label,
    )

    exec_context = ExecutiveSummaryContext(
        operating_context=options.operating_context or PASSIVE_RESEARCH,
        report_type_label=report_type_label,
        findings=report_findings,
        open_findings=open_findings,
        observations=observations,
        evidence_items=evidence_items,
        modules_used=modules_used,
        highest_severity=highest,
        entity_count=len(entities),
        operation_count=len(operations),
    )

    if enabled("change_summary"):
        report_conn = get_db_conn()
        try:
            from utils.baseline_compare import compare_case_to_latest_baseline

            comparison = compare_case_to_latest_baseline(case_id, conn=report_conn)
            if comparison.get("has_baseline"):
                exec_context = ExecutiveSummaryContext(
                    **{
                        **exec_context.__dict__,
                        "baseline_change_summary": (
                            f"Since baseline '{comparison.get('baseline_name') or 'Baseline'}', "
                            f"{comparison.get('summary_text')}"
                        ),
                    }
                )
        finally:
            report_conn.close()

    if enabled("executive_summary"):
        lines.extend(["## Executive Summary", ""])
        lines.append(build_executive_summary_prose(exec_context))
        lines.append("")
        lines.extend(build_executive_summary_stats_lines(exec_context))
        lines.append("")

    if enabled("scope_limitations"):
        lines.extend(
            [
                "## Scope and Limitations",
                "",
                "This report was generated from locally stored Project Overwatch case data. "
                "Findings are analyst aids based on available evidence at generation time — "
                "not final proof of risk or compromise. Review all content before sharing externally.",
                "",
            ]
        )

    context_key = options.operating_context or PASSIVE_RESEARCH
    if enabled("operating_context"):
        lines.extend(
            [
                "## Operating Context",
                "",
                f"- **Mode:** {operating_context_label(context_key)}",
            ]
        )
        if context_key == PERSONAL_LAB:
            lines.append(
                "- **Note:** Output includes results from self-authorised Personal Lab / self-owned testing. "
                "This is not a formal client engagement and must not be presented as client-authorised work."
            )
        elif context_key == CLIENT_ENGAGEMENT:
            lines.append(
                "- **Note:** Active testing results, where present, were produced under client engagement "
                "controls when applicable."
            )
        else:
            lines.append(
                "- **Note:** Passive research context — results are based on passive/public or direct "
                "observations as recorded — not confirmed compromise."
            )
        lines.append("")

    if options.analyst_notes.strip():
        lines.extend(["## Analyst Notes", "", options.analyst_notes.strip(), ""])

    if options.include_engagement_context:
        from database.engagements import engagement_summary_for_report, get_engagement_for_case

        engagement_id = (case or {}).get("engagement_id")
        summary = engagement_summary_for_report(int(engagement_id), conn=conn) if engagement_id else {}
        engagement = summary.get("engagement") or get_engagement_for_case(case_id, conn=conn)
        roe = summary.get("roe") or {}
        lines.extend(["## Engagement and Authorisation Context", ""])
        if not engagement:
            lines.append(
                "_No client engagement linked to this case. Passive collection may still be present; "
                "active testing should only occur under documented authorisation or Personal Lab self-owned testing._"
            )
            lines.append("")
        else:
            lines.append(f"- **Engagement:** {engagement.get('name')}")
            if options.include_engagement_context:
                lines.append(f"- **Client:** {engagement.get('client_name') or '—'}")
            lines.append(f"- **Assessment type:** {engagement.get('engagement_type') or '—'}")
            lines.append(f"- **Status:** {engagement.get('status')}")
            lines.append(f"- **Authorisation reference:** {engagement.get('authorisation_reference') or '—'}")
            lines.append(f"- **In-scope assets recorded:** {summary.get('in_scope_count', 0)}")
            if summary.get("scope_summary"):
                lines.append(f"- **Scope summary:** {summary['scope_summary']}")
            lines.append(
                "- **Testing limitations:** "
                f"Active scanning {'permitted' if roe.get('active_scanning_allowed') else 'not permitted'}; "
                f"intrusive testing {'permitted' if roe.get('intrusive_testing_allowed') else 'not permitted'}; "
                f"DoS {'permitted' if roe.get('denial_of_service_allowed') else 'not permitted (default)'}."
            )
            if roe.get("prohibited_actions"):
                lines.append(f"- **Prohibited actions (ROE):** {roe['prohibited_actions']}")
            if roe.get("evidence_handling_notes"):
                lines.append(f"- **Evidence handling:** {roe['evidence_handling_notes']}")
            lines.append(
                "- **Authorised testing statement:** Testing was performed using Project Overwatch under the "
                "linked engagement rules where applicable. Findings are advisory and require human review."
            )
            lines.append("")

    show_technical_detail = options.template == "full" or options.sections is not None
    if show_technical_detail and enabled("assets_entities"):
        lines.extend(["## Entities", ""])
        if not entities:
            lines.append("_No entities recorded for this case._")
            lines.append("")
        else:
            grouped_entities: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for entity in entities:
                grouped_entities[entity.get("entity_type", "unknown")].append(entity)

            for entity_type in sorted(grouped_entities):
                lines.append(f"### {entity_type}")
                lines.append("")
                for entity in sorted(
                    grouped_entities[entity_type],
                    key=lambda item: (item.get("value") or "", item.get("id", 0)),
                ):
                    lines.append(f"- **{entity.get('value', '-') }**")
                    if entity.get("label"):
                        lines.append(f"  - Label: {entity['label']}")
                    if entity.get("source"):
                        lines.append(f"  - Source: {entity['source']}")
                    lines.append(f"  - Confidence: {entity.get('confidence', 50)}")
                    if entity.get("notes"):
                        lines.append(f"  - Notes: {entity['notes']}")
                lines.append("")

        lines.extend(["## Relationships", ""])
        if not relationships:
            lines.append("_No relationships recorded for this case._")
            lines.append("")
        else:
            for relationship in relationships:
                source = _entity_display(
                    entity_by_id.get(relationship.get("source_entity_id")),
                    relationship.get("source_entity_id"),
                )
                target = _entity_display(
                    entity_by_id.get(relationship.get("target_entity_id")),
                    relationship.get("target_entity_id"),
                )
                rel_type = relationship.get("relationship_type", "related")
                module = relationship.get("source_module") or "unknown"
                confidence = relationship.get("confidence", 50)
                evidence_bits = []
                if relationship.get("evidence_type"):
                    evidence_bits.append(f"evidence: {evidence_type_label(relationship.get('evidence_type'))}")
                if relationship.get("reliability"):
                    evidence_bits.append(f"reliability: {reliability_label(relationship.get('reliability'))}")
                evidence_suffix = f", {', '.join(evidence_bits)}" if evidence_bits else ""
                lines.append(
                    f"- {source} → `{rel_type}` → {target} "
                    f"(module: {module}, confidence: {confidence}{evidence_suffix})"
                )
            lines.append("")

    if show_technical_detail:
        pcap_observations = [
            observation
            for observation in observations
            if observation.get("module_id") in {"net_pcap_review", "net_live_capture"}
        ]
        if pcap_observations and enabled("packet_capture_summary"):
            lines.extend(["## PCAP Evidence Summary", ""])
            lines.append(
                "_Analysis based only on the supplied packet capture file(s). "
                "Not live network capture. Sensitive payloads and credentials are not included._"
            )
            lines.append("")
            for observation in pcap_observations:
                entity = _entity_display(
                    entity_by_id.get(observation.get("entity_id")),
                    observation.get("entity_id"),
                )
                lines.append(f"### {observation.get('title', 'PCAP review')}")
                lines.append("")
                lines.append(f"- Entity: {entity}")
                lines.append(f"- Summary: {observation.get('summary') or '_No summary._'}")
                triage_text = None
                data_json = observation.get("data_json")
                if data_json:
                    try:
                        payload = json.loads(data_json) if isinstance(data_json, str) else data_json
                        triage_text = payload.get("triage_narrative")
                        investigate = payload.get("investigate_entities") or []
                        if investigate:
                            lines.append(f"- Priority follow-ups: {', '.join(investigate)}")
                    except (TypeError, json.JSONDecodeError):
                        triage_text = None
                if triage_text:
                    lines.append(f"- Triage: {triage_text}")
                network_picture = payload.get("network_picture")
                if network_picture:
                    lines.append(f"- Network picture: {network_picture}")
                lines.append(f"- Created: {observation.get('created_at', '-')}")
                lines.append("")

        metadata_observations = [
            observation
            for observation in observations
            if observation.get("module_id") == "evidence_file_metadata"
        ]
        if metadata_observations and enabled("file_metadata_summary"):
            lines.extend(["## File Metadata Review Summary", ""])
            lines.append(
                "_Local metadata review of uploaded files only. Files are not sent externally. "
                "GPS coordinates are omitted from this report summary._"
            )
            lines.append("")
            for observation in metadata_observations:
                entity = _entity_display(
                    entity_by_id.get(observation.get("entity_id")),
                    observation.get("entity_id"),
                )
                payload: dict[str, Any] = {}
                data_json = observation.get("data_json")
                if data_json:
                    try:
                        payload = json.loads(data_json) if isinstance(data_json, str) else data_json
                    except (TypeError, json.JSONDecodeError):
                        payload = {}
                files = list(payload.get("files") or [])
                lines.append(f"### {observation.get('title', 'File metadata review')}")
                lines.append("")
                lines.append(f"- Entity: {entity}")
                lines.append(f"- Summary: {observation.get('summary') or '_No summary._'}")
                lines.append(f"- Files reviewed: {payload.get('file_count', len(files))}")
                lines.append(f"- Notable metadata: {payload.get('notable_count', 0)}")
                privacy_notes = payload.get("privacy_notes") or []
                if privacy_notes:
                    lines.append(f"- Privacy notes: {'; '.join(privacy_notes)}")
                if files:
                    lines.append("- File hashes:")
                    for row in files[:12]:
                        sha = row.get("sha256") or "—"
                        lines.append(
                            f"  - {row.get('filename', 'file')}: `{sha}` "
                            f"({row.get('size_bytes', 0):,} bytes, status={row.get('extraction_status')})"
                        )
                partial = payload.get("partial_count") or 0
                unsupported = payload.get("unsupported_count") or 0
                if partial or unsupported:
                    lines.append(
                        f"- Limitations: partial={partial}, unsupported={unsupported} "
                        "(optional libraries or unsupported types may apply)"
                    )
                lines.append(f"- Created: {observation.get('created_at', '-')}")
                lines.append("")

        nmap_observations = [
            observation
            for observation in observations
            if observation.get("module_id") == "infra_nmap"
        ]
        if nmap_observations and enabled("network_service_summary"):
            lines.extend(["## Network Service Check Summary", ""])
            lines.append(
                "_Controlled Nmap profile runs against authorised targets. "
                "Service detection is point-in-time and requires validation._"
            )
            lines.append("")
            for observation in nmap_observations:
                entity = _entity_display(
                    entity_by_id.get(observation.get("entity_id")),
                    observation.get("entity_id"),
                )
                payload: dict[str, Any] = {}
                data_json = observation.get("data_json")
                if data_json:
                    try:
                        payload = json.loads(data_json) if isinstance(data_json, str) else data_json
                    except (TypeError, json.JSONDecodeError):
                        payload = {}
                profile_label = payload.get("nmap_profile") or "Network Service Check"
                parsed_ports = payload.get("parsed_ports") or []
                warnings = payload.get("warnings") or []
                lines.append(f"### {profile_label}")
                lines.append("")
                lines.append(f"- Entity: {entity}")
                lines.append(f"- Summary: {observation.get('summary') or '_No summary._'}")
                lines.append(f"- Open ports observed: {len(parsed_ports)}")
                if parsed_ports:
                    preview = ", ".join(
                        f"{row.get('port')}/{row.get('protocol', 'tcp')}"
                        + (f" ({row.get('service')})" if row.get("service") else "")
                        for row in parsed_ports[:10]
                    )
                    lines.append(f"- Key services: {preview}")
                if warnings:
                    lines.append(f"- Scan limitations: {'; '.join(warnings)}")
                lines.append(f"- Created: {observation.get('created_at', '-')}")
                lines.append("")
            lines.append(
                "_Point-in-time caveat: port state and service banners may change; "
                "confirm exposure context before acting on findings._"
            )
            lines.append("")

        remote_observations = [
            observation
            for observation in observations
            if observation.get("module_id") == "infra_remote_access_review"
        ]
        if remote_observations and enabled("remote_access_summary"):
            lines.extend(["## Remote Access Exposure Summary", ""])
            lines.append(
                "_Based on observed Nmap/service data only. No authentication or intrusive testing was performed._"
            )
            lines.append("")
            for observation in remote_observations:
                entity = _entity_display(
                    entity_by_id.get(observation.get("entity_id")),
                    observation.get("entity_id"),
                )
                payload: dict[str, Any] = {}
                data_json = observation.get("data_json")
                if data_json:
                    try:
                        payload = json.loads(data_json) if isinstance(data_json, str) else data_json
                    except (TypeError, json.JSONDecodeError):
                        payload = {}
                services = payload.get("remote_services") or []
                exposure = "local/private" if payload.get("is_private_target") else "public or non-local"
                lines.append(f"### {observation.get('title', 'Remote access review')}")
                lines.append("")
                lines.append(f"- Entity: {entity}")
                lines.append(f"- Summary: {observation.get('summary') or '_No summary._'}")
                lines.append(f"- Exposure context: {exposure}")
                lines.append(f"- Remote/admin services observed: {len(services)}")
                if services:
                    for service in services[:8]:
                        lines.append(
                            f"  - {service.get('service_label', 'service')} "
                            f"{service.get('port')}/{service.get('protocol', 'tcp')} "
                            f"({service.get('classification_label', service.get('classification', 'unknown'))})"
                        )
                lines.append("- Recommendation: review whether services are expected and restricted to trusted networks.")
                lines.append(f"- Created: {observation.get('created_at', '-')}")
                lines.append("")
            lines.append(
                "_Limitation: findings reflect observed service data at review time and require validation._"
            )
            lines.append("")

        ssh_observations = [
            observation
            for observation in observations
            if observation.get("module_id") == "infra_ssh_review"
        ]
        if ssh_observations and enabled("ssh_configuration_summary"):
            lines.extend(["## SSH Configuration Review Summary", ""])
            lines.append(
                "_This is a visible service review and does not include authenticated server configuration inspection._"
            )
            lines.append("")
            for observation in ssh_observations:
                entity = _entity_display(
                    entity_by_id.get(observation.get("entity_id")),
                    observation.get("entity_id"),
                )
                payload: dict[str, Any] = {}
                data_json = observation.get("data_json")
                if data_json:
                    try:
                        payload = json.loads(data_json) if isinstance(data_json, str) else data_json
                    except (TypeError, json.JSONDecodeError):
                        payload = {}
                host = payload.get("host") or "target"
                port = payload.get("port") or 22
                banner = payload.get("banner") or {}
                connection = payload.get("connection") or {}
                exposure = "local/private" if payload.get("is_private_target") else "public or non-local"
                lines.append(f"### {observation.get('title', 'SSH configuration review')}")
                lines.append("")
                lines.append(f"- Entity: {entity}")
                lines.append(f"- Summary: {observation.get('summary') or '_No summary._'}")
                lines.append(f"- Target / port: {host}:{port}")
                lines.append(f"- Exposure context: {exposure}")
                lines.append(
                    f"- Connection: {'success' if connection.get('success') else 'failed'}"
                    + (f" ({connection.get('error')})" if connection.get("error") else "")
                )
                if banner.get("raw_banner"):
                    lines.append(f"- SSH banner: {banner['raw_banner'][:160]}")
                elif banner.get("software_family"):
                    lines.append(f"- Software family: {banner['software_family']}")
                if banner.get("version"):
                    lines.append(f"- Version string: {banner['version']}")
                nmap_ssh = payload.get("nmap_ssh_service") or {}
                if nmap_ssh:
                    lines.append(
                        f"- Nmap service: {nmap_ssh.get('service_name') or nmap_ssh.get('service') or 'ssh'} "
                        f"{nmap_ssh.get('product') or ''} {nmap_ssh.get('version') or ''}".strip()
                    )
                lines.append(
                    "- Recommendation: review whether SSH is expected and restricted to trusted networks."
                )
                lines.append(f"- Created: {observation.get('created_at', '-')}")
                lines.append("")
            lines.append(
                "_Limitation: banner and handshake metadata reflect point-in-time visible service information only._"
            )
            lines.append("")

        batch_items = data.get("batch_queue_items") or []
        autopilot_ops = [
            op
            for op in operations
            if "autopilot" in str(op.get("run_mode_label") or "").lower()
        ]
        autopilot_queue_rows = []
        for item in batch_items:
            summary = item.get("summary") or ""
            if "playbook/autopilot" in summary or item.get("autopilot_metadata"):
                autopilot_queue_rows.append(item)
            elif summary.strip().startswith("{"):
                try:
                    meta = json.loads(summary)
                    if meta.get("source") == "playbook/autopilot":
                        autopilot_queue_rows.append(item)
                except (TypeError, json.JSONDecodeError):
                    pass
        if enabled("playbook_summary") and (autopilot_queue_rows or autopilot_ops):
            lines.extend(["## Assessment Playbook Summary", ""])
            lines.append(
                "_Automated follow-up path using assessment playbooks. Active checks require explicit "
                "Personal Lab or Client Engagement confirmation — autopilot does not bypass guardrails._"
            )
            lines.append("")
            if autopilot_ops:
                lines.append("### Modules run via autopilot")
                lines.append("")
                for op in autopilot_ops[:12]:
                    lines.append(
                        f"- {op.get('module_id')} on {op.get('target')} "
                        f"({op.get('run_mode_label') or 'autopilot'}) — {op.get('status', 'completed')}"
                    )
                lines.append("")
            if autopilot_queue_rows:
                lines.append("### Queued / completed follow-up checks")
                lines.append("")
                for item in autopilot_queue_rows[:15]:
                    reason = item.get("summary") or ""
                    if reason.startswith("{"):
                        try:
                            meta = json.loads(reason)
                            reason = meta.get("why_detail") or meta.get("reason") or reason
                        except (TypeError, json.JSONDecodeError):
                            pass
                    lines.append(
                        f"- {item.get('module_display_name') or item.get('module_id')} "
                        f"→ {item.get('execution_target') or item.get('entity_value')} "
                        f"({item.get('status')})"
                    )
                    if reason and not reason.startswith("{"):
                        lines.append(f"  - Reason: {str(reason)[:200]}")
                lines.append("")
            blocked = [item for item in autopilot_queue_rows if item.get("status") == "blocked"]
            if blocked:
                lines.append("### Skipped / blocked checks")
                lines.append("")
                for item in blocked[:8]:
                    lines.append(
                        f"- {item.get('module_id')} on {item.get('execution_target')}: "
                        f"{item.get('compatibility_status') or item.get('summary') or 'blocked'}"
                    )
                lines.append("")
            lines.append(
                "_Limitation: playbook follow-ups are suggestions based on observed results — "
                "validate scope and ROE before external reporting._"
            )
            lines.append("")

        if enabled("change_summary"):
            from utils.baseline_compare import compare_case_to_latest_baseline
            from utils.settings_manager import show_expected_in_reports
            from utils.operating_context import PERSONAL_LAB

            report_conn = get_db_conn()
            try:
                comparison = compare_case_to_latest_baseline(case_id, conn=report_conn)
            finally:
                report_conn.close()
            if comparison.get("has_baseline"):
                grouped = comparison.get("grouped") or {}
                section_title = (
                    "Changes since previous lab baseline"
                    if context_key == PERSONAL_LAB
                    else "Changes since previous assessment baseline"
                )
                lines.extend([f"## {section_title}", ""])
                baseline_name = comparison.get("baseline_name") or "Baseline"
                baseline_updated = comparison.get("baseline_updated_at") or "—"
                lines.append(f"- **Baseline used:** {baseline_name} (updated {baseline_updated})")
                lines.append(f"- **Summary:** {comparison.get('summary_text')}")
                lines.append("")
                for bucket, label in (
                    ("new", "New items"),
                    ("changed", "Changed items"),
                    ("resolved", "Resolved items"),
                ):
                    rows = grouped.get(bucket) or []
                    if not rows:
                        continue
                    lines.append(f"### {label}")
                    lines.append("")
                    for change in rows[:12]:
                        lines.append(f"- **{change.get('title')}** — {change.get('summary')}")
                        if change.get("suggested_action"):
                            lines.append(f"  - Suggested action: {change['suggested_action']}")
                    lines.append("")
                expected_rows = grouped.get("expected") or []
                if show_expected_in_reports() and expected_rows:
                    lines.append("### Expected / accepted items")
                    lines.append("")
                    for change in expected_rows[:10]:
                        lines.append(f"- {change.get('title')}")
                    lines.append("")
                review_rows = [
                    change
                    for change in comparison.get("changes") or []
                    if not change.get("expected")
                    and change.get("category") == "new"
                    and (change.get("importance") or "info") in {"high", "critical", "medium"}
                ]
                if review_rows:
                    lines.append("### Notable changes requiring review")
                    lines.append("")
                    for change in review_rows[:8]:
                        lines.append(f"- {change.get('title')}: {change.get('summary')}")
                    lines.append("")
                lines.append(
                    "_Change detection compares the latest baseline snapshot to current case memory — "
                    "mark expected items in Assessment Workspace to reduce repeated noise._"
                )
                lines.append("")

        web_stack_observations = [
            observation
            for observation in observations
            if observation.get("module_id") == "infra_web_stack_identifier"
        ]
        if web_stack_observations and enabled("web_posture_summary"):
            lines.extend(["## Web Stack Summary", ""])
            lines.append(
                "_Based on a normal HTTP GET with capped preview only. Indicators suggest possible technologies — validate before acting._"
            )
            lines.append("")
            for observation in web_stack_observations:
                entity = _entity_display(
                    entity_by_id.get(observation.get("entity_id")),
                    observation.get("entity_id"),
                )
                payload: dict[str, Any] = {}
                data_json = observation.get("data_json")
                if data_json:
                    try:
                        payload = json.loads(data_json) if isinstance(data_json, str) else data_json
                    except (TypeError, json.JSONDecodeError):
                        payload = {}
                indicators = payload.get("indicators") or []
                categories = payload.get("categories") or []
                response = payload.get("response") or {}
                lines.append(f"### {observation.get('title', 'Web stack identification')}")
                lines.append("")
                lines.append(f"- Entity: {entity}")
                lines.append(f"- Summary: {observation.get('summary') or '_No summary._'}")
                lines.append(f"- Final URL: {response.get('final_url') or payload.get('requested_url') or '—'}")
                lines.append(f"- Indicators observed: {len(indicators)}")
                if categories:
                    lines.append(f"- Categories: {', '.join(categories[:8])}")
                for row in indicators[:10]:
                    version = f" {row['version']}" if row.get("version") else ""
                    lines.append(
                        f"  - {row.get('name')}{version} "
                        f"({row.get('category_label', row.get('category'))}, "
                        f"{row.get('confidence', 'unknown')} confidence, source: {row.get('source')})"
                    )
                lines.append("- Recommendation: review whether observed stack indicators are expected.")
                lines.append(f"- Created: {observation.get('created_at', '-')}")
                lines.append("")
            lines.append("_No full page bodies are stored in observations or evidence._")
            lines.append("")

        web_path_observations = [
            observation
            for observation in observations
            if observation.get("module_id") == "infra_web_path_review"
        ]
        if web_path_observations and enabled("web_posture_summary"):
            lines.extend(["## Web Path Review Summary", ""])
            lines.append(
                "_Small curated sequential path review only — not a site map or discovery scan._"
            )
            lines.append("")
            for observation in web_path_observations:
                entity = _entity_display(
                    entity_by_id.get(observation.get("entity_id")),
                    observation.get("entity_id"),
                )
                payload: dict[str, Any] = {}
                data_json = observation.get("data_json")
                if data_json:
                    try:
                        payload = json.loads(data_json) if isinstance(data_json, str) else data_json
                    except (TypeError, json.JSONDecodeError):
                        payload = {}
                path_results = payload.get("path_results") or []
                notable = [row for row in path_results if row.get("notable")]
                lines.append(f"### {observation.get('title', 'Web path review')}")
                lines.append("")
                lines.append(f"- Entity: {entity}")
                lines.append(f"- Target: {payload.get('base_url') or payload.get('requested_url') or '—'}")
                lines.append(f"- Summary: {observation.get('summary') or '_No summary._'}")
                lines.append(f"- Paths checked: {payload.get('paths_checked', len(path_results))}")
                lines.append(f"- Notable responses: {payload.get('notable_count', len(notable))}")
                if notable:
                    lines.append("- Notable paths:")
                    for row in notable[:12]:
                        lines.append(
                            f"  - {row.get('path')} — status {row.get('status_code')} "
                            f"({row.get('category_label', row.get('category'))})"
                        )
                lines.append("- Limitation: responses are review prompts; validate before claiming exposure.")
                lines.append(f"- Created: {observation.get('created_at', '-')}")
                lines.append("")
            lines.append("_Sensitive-name paths store metadata only — no response bodies retained._")
            lines.append("")

        if enabled("web_posture_summary"):
            lines.extend(build_web_posture_summary_lines(observations))
        if enabled("technical_observations"):
            lines.extend(build_threat_intel_summary_lines(observations))

        if enabled("technical_observations"):
            lines.extend(["## Observations", ""])
        if not observations:
            lines.append("_No observations recorded for this case._")
            lines.append("")
        else:
            grouped_observations: dict[str, list[dict[str, Any]]] = defaultdict(list)
            for observation in observations:
                grouped_observations[observation.get("module_id") or "unknown"].append(observation)

            for module_id in sorted(grouped_observations):
                lines.append(f"### {_module_display(module_id)} (`{module_id}`)")
                lines.append("")
                for observation in grouped_observations[module_id]:
                    entity = _entity_display(
                        entity_by_id.get(observation.get("entity_id")),
                        observation.get("entity_id"),
                    )
                    lines.append(f"#### {observation.get('title', 'Observation')}")
                    lines.append("")
                    lines.append(f"- Entity: {entity}")
                    lines.append(f"- Type: {observation.get('observation_type', '-')}")
                    lines.append(f"- Created: {observation.get('created_at', '-')}")
                    if observation.get("evidence_type"):
                        lines.append(
                            f"- Evidence: {evidence_type_label(observation.get('evidence_type'))} "
                            f"({reliability_label(observation.get('reliability'))})"
                        )
                        if observation.get("source_name"):
                            lines.append(f"- Source: `{observation.get('source_name')}`")
                        if observation.get("collection_method"):
                            lines.append(f"- Collection method: {observation.get('collection_method')}")
                        if observation.get("collected_at"):
                            lines.append(f"- Collected at: {observation.get('collected_at')}")
                        lines.append(f"- Note: {evidence_wording(observation.get('evidence_type'))}")
                    lines.append(f"- Summary: {observation.get('summary') or '_No summary._'}")
                    lines.append("")
            lines.append("")

    if batch_queue_runs:
        lines.extend(["## Batch queue runs", ""])
        lines.append(
            "_Controlled batch pivot runs executed from the Batch Queue page. "
            "Individual module results are also stored as operations and observations._"
        )
        lines.append("")
        for run in batch_queue_runs:
            lines.append(
                f"### Run #{run.get('id')} · {run.get('completed_at') or run.get('started_at') or '-'}"
            )
            lines.append("")
            lines.append(
                f"- Processed: {run.get('items_processed', 0)} · "
                f"Completed: {run.get('items_completed', 0)} · "
                f"Warnings: {run.get('items_warnings', 0)} · "
                f"Failed: {run.get('items_failed', 0)}"
            )
            if run.get("run_summary"):
                lines.append("")
                lines.append(run["run_summary"])
            lines.append("")

    lookup_notices = _lookup_notices_from_observations(observations)
    if lookup_notices:
        lines.extend(["## Lookup and source notices", ""])
        lines.append(
            "_External lookup limits and collection warnings. Informational only — "
            "they do not by themselves indicate target risk._"
        )
        lines.append("")
        for notice in lookup_notices:
            lines.append(f"- {notice}")
        lines.append("")

    if options.include_evidence_summary and enabled("evidence_summary"):
        lines.extend(_evidence_summary_lines(evidence_items))

    lines.extend(["## Evidence and Reliability Notes", ""])
    lines.append(
        "_Project Overwatch distinguishes how information was collected. "
        "Evidence type describes the origin of a record; reliability describes how much weight "
        "to give it before analyst review. Confidence scores on findings are separate — they reflect "
        "interpreter strength, not automatic proof._"
    )
    lines.append("")
    lines.append("**Evidence types:** " + ", ".join(sorted(EVIDENCE_TYPES)))
    lines.append("")
    lines.append("**Reliability levels:** " + ", ".join(RELIABILITY_LEVELS))
    lines.append("")
    for low, high, guidance in CONFIDENCE_GUIDANCE:
        lines.append(f"- Confidence {low}–{high}: {guidance}")
    lines.append("")
    lines.append(
        "- Third-party sources (for example crt.sh or public DNS) provide leads, not confirmed live state."
    )
    lines.append(
        "- Unavailable sources during a run are **not** evidence that data does not exist — "
        "only that Overwatch could not retrieve it at that time."
    )
    lines.append(
        "- Parser-inferred relationships are derived from module output and should be validated "
        "before treating them as confirmed links."
    )
    lines.append("")

    if enabled("key_findings") and report_findings:
        lines.extend(["## Key Findings", ""])
        lines.append(
            "_Highest-priority selected findings. Review whether each item reflects expected configuration._"
        )
        lines.append("")
        key_sorted = sorted(
            report_findings,
            key=lambda item: SEVERITY_RANK.get(effective_finding_severity(item).lower(), 0),
            reverse=True,
        )
        for finding in key_sorted[:8]:
            severity = effective_finding_severity(finding)
            lines.append(
                f"- **[{severity.upper()}] {finding.get('title', 'Finding')}** — "
                f"{(finding.get('explanation') or '_No explanation._').split('.')[0].strip()}."
            )
        lines.append("")

    if enabled("findings_table"):
        lines.extend(["## Findings", ""])
    if not report_findings:
        if not options.include_closed_findings:
            lines.append("_No active findings recorded for this case._")
        else:
            lines.append("_No findings recorded for this case._")
        lines.append("")
    else:
        findings_by_severity: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for finding in report_findings:
            severity = effective_finding_severity(finding).lower()
            if severity not in SEVERITY_SECTION_ORDER:
                severity = "info"
            findings_by_severity[severity].append(finding)

        for severity in SEVERITY_SECTION_ORDER:
            severity_findings = findings_by_severity.get(severity, [])
            if not severity_findings:
                continue
            lines.append(f"### {severity}")
            lines.append("")
            for finding in severity_findings:
                entity = _entity_display(
                    entity_by_id.get(finding.get("entity_id")),
                    finding.get("entity_id"),
                )
                display_severity = effective_finding_severity(finding)
                lines.append(f"#### {finding.get('title', 'Finding')}")
                lines.append("")
                lines.append(f"- Status: {normalize_finding_status(finding.get('status', 'open'))}")
                lines.append(f"- Module severity: {finding.get('severity', 'info')}")
                if finding.get("user_severity"):
                    lines.append(f"- Analyst severity override: {finding.get('user_severity')}")
                else:
                    lines.append(f"- Effective severity: {display_severity}")
                lines.append(f"- Confidence: {finding.get('confidence', 50)}")
                if finding.get("evidence_type") or finding.get("reliability"):
                    lines.append(
                        f"- Evidence: {evidence_type_label(finding.get('evidence_type'))} "
                        f"({reliability_label(finding.get('reliability'))})"
                    )
                    if finding.get("source_name"):
                        lines.append(f"- Source: `{finding.get('source_name')}`")
                    lines.append(f"- Evidence note: {evidence_wording(finding.get('evidence_type'))}")
                linked_evidence = _linked_evidence_for_finding(finding, evidence_items, evidence_links)
                if linked_evidence:
                    lines.append("- Linked evidence:")
                    for item in linked_evidence:
                        hash_note = f", hash `{item['content_hash']}`" if item.get("content_hash") else ""
                        lines.append(
                            f"  - {item.get('title', 'Evidence item')} "
                            f"({item.get('source_name') or 'unknown source'}, "
                            f"{reliability_label(item.get('reliability'))}{hash_note})"
                        )
                lines.append(f"- Affected entity: {entity}")
                lines.append(f"- Module: `{finding.get('module_id', '-')}`")
                if finding.get("reviewed_at"):
                    lines.append(f"- Reviewed at: {finding.get('reviewed_at')}")
                if finding.get("closed_at"):
                    lines.append(f"- Closed at: {finding.get('closed_at')}")
                lines.append("")
                explanation = finding.get("explanation") or "_No explanation provided._"
                if options.template == "executive":
                    explanation = explanation.split(".")[0].strip()
                    if explanation and not explanation.endswith("."):
                        explanation += "."
                lines.append(explanation)
                lines.append("")
                if finding.get("analyst_notes"):
                    lines.append("**Analyst notes:**")
                    lines.append(finding.get("analyst_notes"))
                    lines.append("")
                if options.template == "full":
                    actions = _parse_suggested_actions(finding)
                    if actions:
                        lines.append("**Suggested actions:**")
                        for action in actions:
                            lines.append(f"- {action}")
                        lines.append("")
        lines.append("")

    recommended = build_recommended_actions(
        findings=report_findings or open_findings,
        evidence_items=evidence_items,
        evidence_links=evidence_links,
        operating_context=context_key,
    )
    if enabled("recommended_actions"):
        lines.extend(recommended_actions_markdown(recommended))
    elif enabled("open_actions"):
        lines.extend(["## Open Actions", ""])
        if not recommended:
            lines.append("_No open actions generated._")
        else:
            for action in recommended[:8]:
                lines.append(f"- **{action.title}** — {action.reason}")
        lines.append("")

    appendix_enabled = enabled("appendix_raw") or options.include_raw_appendix or options.include_graph_appendix
    if appendix_enabled and (options.template == "full" or options.include_raw_appendix or options.include_graph_appendix):
        lines.extend(["## Appendix", ""])
        appendix_parts: list[str] = []

        if options.include_graph_appendix:
            reports_dir = PROJECT_ROOT / "reports"
            reports_dir.mkdir(parents=True, exist_ok=True)
            basename = f"{_safe_filename_part(case.get('name', f'case_{case_id}'))}_{case_id}"
            appendix_parts.extend(
                _graph_appendix_lines(entities, relationships, all_findings, reports_dir, basename)
            )

        if options.include_raw_appendix and options.template == "full":
            if evidence_items:
                appendix_parts.append("### Evidence locker content")
                appendix_parts.append("")
                for item in evidence_items:
                    appendix_parts.append(f"#### {item.get('title', 'Evidence item')}")
                    appendix_parts.append("")
                    appendix_parts.append(f"- Module: `{item.get('module_id', '-')}`")
                    appendix_parts.append(f"- Source: `{item.get('source_name') or '-'}`")
                    if item.get("content_hash"):
                        appendix_parts.append(f"- Hash: `{item['content_hash']}`")
                    if item.get("storage_path"):
                        appendix_parts.append(f"- Storage: `{item['storage_path']}`")
                    appendix_parts.append("")
                    content = item.get("content_text") or read_spilled_content(item.get("storage_path"))
                    content = content or "_No content stored._"
                    appendix_parts.append("```text")
                    appendix_parts.append(content)
                    appendix_parts.append("```")
                    appendix_parts.append("")
            if not observations and not evidence_items:
                appendix_parts.append("_No observation raw output or evidence locker content available._")
            elif observations:
                appendix_parts.append("### Observation raw output")
                appendix_parts.append("")
                for observation in observations:
                    appendix_parts.append(f"#### {observation.get('title', 'Observation')}")
                    appendix_parts.append("")
                    raw_output = observation.get("raw_output") or "_No raw output stored._"
                    appendix_parts.append("```text")
                    appendix_parts.append(raw_output)
                    appendix_parts.append("```")
                    appendix_parts.append("")
        elif options.template == "full" and not options.include_raw_appendix and not options.include_graph_appendix:
            appendix_parts.append(
                "Raw module outputs are stored in the application database and were excluded from this report. "
                "Enable the raw output appendix option to include them."
            )

        if not appendix_parts and options.template == "executive":
            appendix_parts.append("_Executive template: detailed appendix sections omitted._")

        lines.extend(appendix_parts)
        lines.append("")

    return finalize_report("\n".join(lines))


def save_report_markdown(
    case_id: int,
    markdown_text: str | None = None,
    output_dir: str = "reports",
    *,
    options: ReportOptions | None = None,
) -> Path:
    """
    Save a Markdown report to disk.

    Creates the output directory if needed and returns the saved file path.
    """
    if markdown_text is None:
        markdown_text = build_case_report(case_id)

    conn = get_db_conn()
    try:
        case = get_case(case_id, conn=conn)
    finally:
        conn.close()

    case_name = case.get("name", f"case_{case_id}") if case else f"case_{case_id}"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    filename = f"{_safe_filename_part(case_name)}_{case_id}_{timestamp}.md"

    reports_dir = Path(output_dir)
    if not reports_dir.is_absolute():
        reports_dir = PROJECT_ROOT / reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)

    output_path = reports_dir / filename
    output_path.write_text(markdown_text, encoding="utf-8")

    if options is not None:
        from utils.report_metadata import build_report_metadata, save_report_metadata_sidecar

        metadata = build_report_metadata(
            case_id=case_id,
            report_type_id=options.report_type_id,
            operating_context=options.operating_context,
            sections=sorted(options.sections) if options.sections else None,
            finding_selection_mode=options.finding_selection_mode,
            template=options.template,
            output_path=output_path,
        )
        save_report_metadata_sidecar(output_path, metadata)

    return output_path

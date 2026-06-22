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
    list_findings,
    list_observations,
    list_operations,
    list_relationships,
    normalize_finding_status,
)
from modules.module_registry import get_module
from utils.finding_interpreter import is_source_notice
from utils.report_redaction import (
    RedactionOption,
    apply_redactions,
    parse_custom_regex_patterns,
)
from utils.report_settings import ReportBranding, branding_footer_lines, branding_header_lines, load_report_branding

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
    }


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

    entity_by_id = {entity["id"]: entity for entity in entities}
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    template_label = "Executive" if options.template == "executive" else "Full technical"

    if options.include_closed_findings:
        report_findings = list(all_findings)
    else:
        report_findings = [
            finding
            for finding in all_findings
            if normalize_finding_status(finding.get("status")) not in REPORT_EXCLUDED_STATUSES
        ]

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
        f"_Generated: {generated_at} · Template: {template_label}_",
        "",
        "## Case Summary",
        "",
        f"- **Case name:** {case.get('name', 'Unnamed')}",
        f"- **Case ID:** {case.get('id')}",
        f"- **Status:** {case.get('status', 'open')}",
        f"- **Created:** {case.get('created_at', 'unknown')}",
        f"- **Updated:** {case.get('updated_at', 'unknown')}",
        f"- **Description:** {case.get('description') or '_No description provided._'}",
        "",
        "## Executive Summary",
        "",
        f"- Total entities: {len(entities)}",
        f"- Total relationships: {len(relationships)}",
        f"- Total observations: {len(observations)}",
        f"- Total operations: {len(operations)}",
        f"- Operations by run mode: {_format_operation_run_modes(operations)}",
        f"- Total findings: {len(all_findings)}",
        f"- Open findings: {len(open_findings)}",
        f"- Finding status summary: {status_summary}",
        f"- Highest severity finding: {highest or 'None recorded'}",
        f"- Main modules used: {modules_summary}",
        "",
        "## Scope and Notes",
        "",
        "This report was generated from locally stored Project Overwatch case data. "
        "Findings are analyst aids, not final proof of risk. Review all content before sharing externally.",
        "",
    ]

    if options.template == "full":
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
                lines.append(
                    f"- {source} → `{rel_type}` → {target} "
                    f"(module: {module}, confidence: {confidence})"
                )
            lines.append("")

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
                    lines.append(f"- Summary: {observation.get('summary') or '_No summary._'}")
                    lines.append("")
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

    lines.extend(["## Suggested Next Actions", ""])
    combined_actions: list[str] = []
    seen_actions: set[str] = set()
    for finding in open_findings:
        if normalize_finding_status(finding.get("status")) != "open":
            continue
        for action in _parse_suggested_actions(finding):
            normalized = action.strip()
            if not normalized or normalized in seen_actions:
                continue
            seen_actions.add(normalized)
            combined_actions.append(normalized)

    if not combined_actions:
        lines.append("_No suggested actions from open findings._")
    else:
        for action in combined_actions:
            lines.append(f"- {action}")
    lines.append("")

    if options.template == "full" or options.include_raw_appendix or options.include_graph_appendix:
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
            if not observations:
                appendix_parts.append("_No observation raw output available._")
            else:
                for observation in observations:
                    appendix_parts.append(f"### {observation.get('title', 'Observation')}")
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
    return output_path

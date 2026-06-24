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
        f"- Batch queue runs recorded: {len(batch_queue_runs)}",
        "",
        "## Scope and Notes",
        "",
        "This report was generated from locally stored Project Overwatch case data. "
        "Findings are analyst aids, not final proof of risk. Review all content before sharing externally.",
        "",
    ]

    from utils.operating_context import (
        CLIENT_ENGAGEMENT,
        PASSIVE_RESEARCH,
        PERSONAL_LAB,
        operating_context_label,
    )

    context_key = options.operating_context or PASSIVE_RESEARCH
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
            "- **Note:** Passive research context — active testing artefacts should not be included unless "
            "explicitly generated under Personal Lab or Client Engagement mode."
        )
    lines.append("")

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

        pcap_observations = [
            observation
            for observation in observations
            if observation.get("module_id") in {"net_pcap_review", "net_live_capture"}
        ]
        if pcap_observations:
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

        nmap_observations = [
            observation
            for observation in observations
            if observation.get("module_id") == "infra_nmap"
        ]
        if nmap_observations:
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
        if remote_observations:
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

        web_stack_observations = [
            observation
            for observation in observations
            if observation.get("module_id") == "infra_web_stack_identifier"
        ]
        if web_stack_observations:
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

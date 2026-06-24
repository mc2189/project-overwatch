"""Report Builder v2 UI — guided assessment pack workflow."""

from __future__ import annotations

import re
from typing import Any

import streamlit as st

from database.db_setup import effective_finding_severity, get_case, get_db_conn, list_evidence_items, list_findings, normalize_finding_status
from ui.styles import section_heading
from utils.report_builder import ReportOptions, build_case_report, save_report_markdown
from utils.report_executive_summary import ExecutiveSummaryContext, build_executive_summary_prose
from utils.report_export import (
    build_case_report_json,
    markdown_to_html,
    save_report_html,
    save_report_pdf,
)
from utils.report_finding_selection import filter_findings_for_report
from utils.report_recommended_actions import build_recommended_actions
from utils.report_sections import ALL_SECTIONS, SECTION_LABELS, section_label
from utils.report_settings import ReportBranding, load_report_branding
from utils.report_types import REPORT_TYPES, get_report_type
from utils.report_presets import build_report_options_from_state


def _init_report_v2_state() -> None:
    defaults = {
        "report_v2_type_id": "client_executive_pack",
        "report_v2_sections": sorted(REPORT_TYPES["client_executive_pack"].default_sections),
        "report_finding_mode": "active",
        "report_analyst_notes": "",
        "report_include_all_findings": False,
        "report_exclude_info_findings": False,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


def _apply_report_type(type_id: str) -> None:
    report_type = get_report_type(type_id)
    if report_type is None:
        return
    st.session_state.report_v2_type_id = type_id
    st.session_state.report_v2_sections = sorted(report_type.default_sections)
    st.session_state.report_template = report_type.default_template
    st.session_state.report_operating_context = report_type.default_operating_context
    st.session_state.report_finding_mode = report_type.default_finding_mode
    st.session_state.include_engagement_context = report_type.include_engagement_by_default
    st.session_state.include_raw_appendix = report_type.include_raw_appendix_by_default
    if report_type.default_template == "executive":
        st.session_state.include_graph_appendix = False


def _selected_finding_ids(case_id: int) -> frozenset[int]:
    conn = get_db_conn()
    try:
        findings = list_findings(case_id=case_id, conn=conn)
    finally:
        conn.close()
    key_prefix = f"report_finding_{case_id}_"
    selected: set[int] = set()
    for finding in findings:
        if st.session_state.get(f"{key_prefix}{finding['id']}", False):
            selected.add(int(finding["id"]))
    return frozenset(selected)


def build_report_v2_options(
    branding: ReportBranding,
    *,
    custom_terms_text: str = "",
    custom_regex_text: str = "",
) -> ReportOptions:
    base = build_report_options_from_state(
        branding,
        custom_terms_text=custom_terms_text,
        custom_regex_text=custom_regex_text,
    )
    type_id = st.session_state.get("report_v2_type_id")
    sections = frozenset(st.session_state.get("report_v2_sections") or [])
    finding_mode = st.session_state.get("report_finding_mode", "active")
    if st.session_state.get("report_include_all_findings"):
        finding_mode = "all"
        base.include_closed_findings = True
    if st.session_state.get("report_exclude_info_findings"):
        finding_mode = "exclude_info"

    return ReportOptions(
        include_closed_findings=base.include_closed_findings,
        include_raw_appendix=base.include_raw_appendix,
        include_graph_appendix=base.include_graph_appendix,
        template=base.template,
        redactions=base.redactions,
        branding=base.branding,
        custom_redaction_terms=base.custom_redaction_terms,
        custom_redaction_regex=base.custom_redaction_regex,
        include_engagement_context=base.include_engagement_context,
        operating_context=base.operating_context,
        report_type_id=type_id,
        sections=sections,
        finding_selection_mode=finding_mode,
        selected_finding_ids=_selected_finding_ids(st.session_state.get("active_case_id") or 0)
        if finding_mode == "selected"
        else frozenset(),
        analyst_notes=st.session_state.get("report_analyst_notes", ""),
        include_evidence_summary=True,
    )


def _preview_context(case_id: int, options: ReportOptions) -> dict[str, Any]:
    conn = get_db_conn()
    try:
        findings = list_findings(case_id=case_id, conn=conn)
        evidence = list_evidence_items(case_id=case_id, conn=conn)
    finally:
        conn.close()
    filtered = filter_findings_for_report(
        findings,
        mode=options.finding_selection_mode,
        include_closed=options.include_closed_findings,
        selected_ids=options.selected_finding_ids,
    )
    return {
        "findings": filtered,
        "evidence_count": len(evidence),
        "open_count": sum(1 for item in findings if normalize_finding_status(item.get("status")) == "open"),
    }


def render_report_builder_v2(case_id: int) -> ReportOptions | None:
    """Render Report Builder v2 controls. Returns options when preview/export is requested."""
    _init_report_v2_state()
    st.session_state.active_case_id = case_id

    section_heading("1. Case")
    case = get_case(case_id)
    if case:
        st.markdown(f"**{case.get('name', 'Unnamed')}** · Case #{case_id} · {case.get('status', 'open')}")
    else:
        st.warning(f"Case #{case_id} not found.")

    section_heading("2. Report type")
    type_ids = list(REPORT_TYPES.keys())
    current_type = st.session_state.get("report_v2_type_id", type_ids[0])
    type_index = type_ids.index(current_type) if current_type in type_ids else 0
    selected_type = st.selectbox(
        "Assessment pack type",
        options=type_ids,
        index=type_index,
        format_func=lambda value: REPORT_TYPES[value].label,
        key="report_v2_type_select",
    )
    st.caption(REPORT_TYPES[selected_type].description)
    if st.button("Apply report type defaults", key="apply_report_v2_type"):
        _apply_report_type(selected_type)
        st.rerun()

    section_heading("3. Included sections")
    with st.expander("Section selection", expanded=False):
        selected_sections = st.multiselect(
            "Sections to include",
            options=list(ALL_SECTIONS),
            default=st.session_state.get("report_v2_sections", []),
            format_func=section_label,
            key="report_v2_sections_select",
        )
        st.session_state.report_v2_sections = selected_sections
        c1, c2 = st.columns(2)
        with c1:
            if st.button("Use concise defaults", key="report_sections_concise"):
                st.session_state.report_v2_sections = sorted(
                    REPORT_TYPES[selected_type].default_sections
                )
                st.rerun()
        with c2:
            if st.button("Include technical appendix sections", key="report_sections_full"):
                st.session_state.report_v2_sections = sorted(ALL_SECTIONS)
                st.rerun()

    section_heading("4. Findings review")
    conn = get_db_conn()
    try:
        all_findings = list_findings(case_id=case_id, conn=conn)
    finally:
        conn.close()
    st.checkbox(
        "Include closed / accepted / false positive findings",
        key="include_closed_findings",
    )
    st.checkbox("Include all findings", key="report_include_all_findings")
    st.checkbox("Exclude info-only findings", key="report_exclude_info_findings")
    finding_mode = st.selectbox(
        "Finding selection mode",
        options=["active", "all", "exclude_info", "selected"],
        format_func=lambda value: {
            "active": "Open / active findings (default)",
            "all": "All findings",
            "exclude_info": "Exclude info-only",
            "selected": "Selected findings only",
        }[value],
        key="report_finding_mode",
    )
    if finding_mode == "selected" or st.checkbox("Choose individual findings", key="report_show_finding_picker"):
        for finding in all_findings[:40]:
            severity = effective_finding_severity(finding)
            st.checkbox(
                f"[{severity}] {finding.get('title', 'Finding')} ({normalize_finding_status(finding.get('status'))})",
                key=f"report_finding_{case_id}_{finding['id']}",
            )

    section_heading("5. Evidence summary")
    st.caption(
        "Evidence summary, hashes, source, and reliability are included by default. "
        "Raw evidence remains optional via the technical appendix section."
    )
    st.checkbox("Include raw output appendix", key="include_raw_appendix")
    st.checkbox("Include entity graph snapshot", key="include_graph_appendix")

    section_heading("6. Analyst notes")
    st.text_area(
        "Notes to include in the report",
        key="report_analyst_notes",
        height=120,
        placeholder="Optional analyst commentary for this report pack.",
    )

    section_heading("7. Generate and export")
    branding = load_report_branding()
    custom_terms_text = ""
    custom_regex_text = ""
    with st.expander("Advanced export settings", expanded=False):
        st.selectbox(
            "Report template depth",
            options=["full", "executive"],
            format_func=lambda value: "Full technical" if value == "full" else "Executive summary",
            key="report_template",
        )
        from utils.operating_context import list_operating_contexts, operating_context_label

        st.selectbox(
            "Operating context for report wording",
            options=[mode_id for mode_id, _ in list_operating_contexts()],
            format_func=operating_context_label,
            key="report_operating_context",
        )
        st.checkbox("Include engagement / authorisation context", key="include_engagement_context")
        st.checkbox("Redact IP addresses", key="redact_ips")
        st.checkbox("Redact email addresses", key="redact_emails")
        st.checkbox("Redact domain names", key="redact_domains")
        custom_terms_text = st.text_area("Additional redaction strings (one per line)", height=80)
        custom_regex_text = st.text_area("Custom regex redaction patterns", height=80)

    options = build_report_v2_options(
        branding,
        custom_terms_text=custom_terms_text,
        custom_regex_text=custom_regex_text,
    )

    preview = _preview_context(case_id, options)
    st.caption(
        f"Preview scope: {len(preview['findings'])} finding(s) selected · "
        f"{preview['open_count']} open in case · {preview['evidence_count']} evidence item(s)"
    )

    exec_preview = build_executive_summary_prose(
        ExecutiveSummaryContext(
            operating_context=options.operating_context or "passive_research",
            report_type_label=get_report_type(options.report_type_id).label if options.report_type_id else None,
            findings=preview["findings"],
            open_findings=[item for item in preview["findings"] if normalize_finding_status(item.get("status")) == "open"],
            observations=[],
            evidence_items=[{}] * preview["evidence_count"],
            modules_used=[],
            highest_severity=None,
            entity_count=0,
            operation_count=0,
        )
    )
    with st.expander("Executive summary preview", expanded=False):
        st.write(exec_preview)

    conn = get_db_conn()
    try:
        evidence_items = list_evidence_items(case_id=case_id, conn=conn)
    finally:
        conn.close()
    actions = build_recommended_actions(
        findings=preview["findings"],
        evidence_items=evidence_items,
        evidence_links=[],
        operating_context=options.operating_context or "passive_research",
    )
    with st.expander("Recommended actions preview", expanded=False):
        for action in actions[:6]:
            st.markdown(f"- **{action.title}** ({action.priority}) — {action.reason}")

    with st.expander("Evidence summary preview", expanded=False):
        st.caption(f"{len(evidence_items)} evidence item(s) will be summarised with source and reliability.")

    return options

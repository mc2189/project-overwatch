"""Findings triage page for Project Overwatch."""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from database.db_setup import (
    FINDING_STATUSES,
    TERMINAL_FINDING_STATUSES,
    effective_finding_severity,
    get_db_conn,
    list_entities,
    list_evidence_for_finding,
    list_findings,
    normalize_finding_status,
    reopen_finding,
    update_finding,
)
from ui.constants import FINDING_SEVERITY_OPTIONS, FINDING_SEVERITY_ORDER, FINDING_STATUS_LABELS
from ui.metrics import render_compact_metrics
from utils.evidence_model import EVIDENCE_TYPES, RELIABILITY_LEVELS, evidence_type_label, evidence_wording, reliability_label


def finding_status_label(status: str | None) -> str:
    return FINDING_STATUS_LABELS.get(normalize_finding_status(status), "Open")


def save_finding_update(
    finding_id: int,
    *,
    status: str | None = None,
    analyst_notes: str | None = None,
    user_severity: str | None = None,
) -> None:
    conn = get_db_conn()
    try:
        update_finding(
            finding_id,
            status=status,
            analyst_notes=analyst_notes,
            user_severity=user_severity,
            conn=conn,
        )
    finally:
        conn.close()


def render_finding_review_controls(finding: dict) -> None:
    finding_id = finding["id"]
    current_status = normalize_finding_status(finding.get("status"))
    is_terminal = current_status in TERMINAL_FINDING_STATUSES

    st.markdown(f"**Status:** {finding_status_label(current_status)}")

    with st.form(key=f"finding_review_{finding_id}"):
        status_index = FINDING_STATUSES.index(current_status) if current_status in FINDING_STATUSES else 0
        new_status = st.selectbox(
            "Update status",
            FINDING_STATUSES,
            index=status_index,
            format_func=lambda value: FINDING_STATUS_LABELS.get(value, value),
        )
        analyst_notes = st.text_area(
            "Analyst notes",
            value=finding.get("analyst_notes") or "",
            help="Document review decisions, context, or follow-up.",
        )
        current_override = finding.get("user_severity") or ""
        override_index = (
            FINDING_SEVERITY_OPTIONS.index(current_override)
            if current_override in FINDING_SEVERITY_OPTIONS
            else 0
        )
        user_severity = st.selectbox(
            "Severity override",
            FINDING_SEVERITY_OPTIONS,
            index=override_index,
            format_func=lambda value: "(module default)" if not value else value,
        )
        button_col1, button_col2 = st.columns(2)
        with button_col1:
            save_clicked = st.form_submit_button("Save update", width="stretch")
        with button_col2:
            close_clicked = (
                st.form_submit_button("Close finding", width="stretch") if not is_terminal else False
            )

    if save_clicked:
        save_finding_update(
            finding_id,
            status=new_status,
            analyst_notes=analyst_notes,
            user_severity=user_severity or None,
        )
        st.rerun()
    if close_clicked:
        save_finding_update(
            finding_id,
            status="closed",
            analyst_notes=analyst_notes,
            user_severity=user_severity or None,
        )
        st.rerun()

    if is_terminal:
        if st.button("Reopen finding", key=f"finding_reopen_{finding_id}", width="stretch"):
            conn = get_db_conn()
            try:
                reopen_finding(finding_id, conn=conn)
            finally:
                conn.close()
            st.rerun()


def render_finding_detail(
    finding: dict,
    entity_lookup: dict,
    evidence_items: list[dict] | None = None,
) -> None:
    entity_label = entity_lookup.get(finding.get("entity_id"), finding.get("entity_id") or "-")
    st.markdown(f"**Title:** {finding.get('title', 'Finding')}")
    st.markdown(f"**Module:** `{finding.get('module_id', '-')}`")
    st.markdown(f"**Entity:** {entity_label}")
    st.markdown(f"**Module severity:** {finding.get('severity', 'info')}")
    if finding.get("user_severity"):
        st.markdown(f"**Analyst severity override:** {finding.get('user_severity')}")
    st.markdown(f"**Effective severity:** {effective_finding_severity(finding)}")
    st.markdown(f"**Confidence:** {finding.get('confidence', 50)}")
    if finding.get("evidence_type") or finding.get("reliability"):
        st.markdown(
            f"**Evidence:** {evidence_type_label(finding.get('evidence_type'))} · "
            f"Reliability: {reliability_label(finding.get('reliability'))}"
        )
        if finding.get("source_name"):
            st.markdown(f"**Source:** `{finding.get('source_name')}`")
        st.caption(evidence_wording(finding.get("evidence_type")))
    linked = evidence_items or []
    if linked:
        st.markdown(f"**Linked evidence items:** {len(linked)}")
        for item in linked[:5]:
            hash_note = f" · hash `{item['content_hash']}`" if item.get("content_hash") else ""
            st.markdown(
                f"- {item.get('title', 'Evidence')} · `{item.get('source_name') or '-'}` · "
                f"{reliability_label(item.get('reliability'))}{hash_note}"
            )
        if len(linked) > 5:
            st.caption(f"_Plus {len(linked) - 5} more — see Evidence Locker._")
    st.markdown(f"**Status:** {finding_status_label(finding.get('status'))}")
    st.markdown("**Explanation**")
    st.write(finding.get("explanation") or "_No explanation provided._")
    try:
        suggested_actions = json.loads(finding.get("suggested_actions_json") or "[]")
    except json.JSONDecodeError:
        suggested_actions = []
    if suggested_actions:
        st.markdown("**Suggested actions**")
        for action in suggested_actions:
            st.markdown(f"- {action}")
    if finding.get("analyst_notes"):
        st.markdown("**Analyst notes**")
        st.write(finding.get("analyst_notes"))
    render_finding_review_controls(finding)


def render_findings_page(case_id: int, metrics: dict) -> None:
    st.title("Findings")
    render_compact_metrics(metrics)
    st.divider()

    conn = get_db_conn()
    entities = list_entities(case_id=case_id, conn=conn)
    entity_lookup = {
        entity["id"]: entity.get("label") or entity.get("value", entity["id"])
        for entity in entities
    }
    findings = list_findings(case_id=case_id, conn=conn)
    linked_evidence_map = {
        int(finding["id"]): list_evidence_for_finding(finding, conn=conn) for finding in findings
    }
    conn.close()

    def linked_evidence_for_finding(finding: dict) -> list[dict]:
        return linked_evidence_map.get(int(finding["id"]), [])

    st.caption(
        f"Showing findings for case #{case_id}. "
        "Findings are analyst aids, not final proof of risk."
    )

    module_options = sorted({finding.get("module_id") for finding in findings if finding.get("module_id")})
    filter_col1, filter_col2, filter_col3 = st.columns(3)
    with filter_col1:
        severity_filter = st.selectbox(
            "Filter by severity",
            ["All", *FINDING_SEVERITY_ORDER],
            key="findings_severity_filter",
        )
    with filter_col2:
        status_filter = st.selectbox(
            "Filter by status",
            ["All", *FINDING_STATUSES],
            format_func=lambda value: "All" if value == "All" else FINDING_STATUS_LABELS.get(value, value),
            key="findings_status_filter",
        )
    with filter_col3:
        module_filter = st.selectbox(
            "Filter by module",
            ["All", *module_options],
            key="findings_module_filter",
        )

    filter_col4, filter_col5, filter_col6 = st.columns(3)
    with filter_col4:
        evidence_type_filter = st.selectbox(
            "Filter by evidence type",
            ["All", *EVIDENCE_TYPES],
            format_func=lambda value: "All" if value == "All" else evidence_type_label(value),
            key="findings_evidence_type_filter",
        )
    with filter_col5:
        reliability_filter = st.selectbox(
            "Filter by reliability",
            ["All", *RELIABILITY_LEVELS],
            format_func=lambda value: "All" if value == "All" else reliability_label(value),
            key="findings_reliability_filter",
        )
    with filter_col6:
        evidence_link_filter = st.selectbox(
            "Linked evidence",
            ["All", "With linked evidence", "Without linked evidence"],
            key="findings_evidence_link_filter",
        )

    filtered_findings = findings
    if severity_filter != "All":
        filtered_findings = [
            finding
            for finding in filtered_findings
            if effective_finding_severity(finding) == severity_filter
        ]
    if status_filter != "All":
        filtered_findings = [
            finding
            for finding in filtered_findings
            if normalize_finding_status(finding.get("status")) == status_filter
        ]
    if module_filter != "All":
        filtered_findings = [
            finding for finding in filtered_findings if finding.get("module_id") == module_filter
        ]
    if evidence_type_filter != "All":
        filtered_findings = [
            finding
            for finding in filtered_findings
            if finding.get("evidence_type") == evidence_type_filter
        ]
    if reliability_filter != "All":
        filtered_findings = [
            finding
            for finding in filtered_findings
            if finding.get("reliability") == reliability_filter
        ]
    if evidence_link_filter == "With linked evidence":
        filtered_findings = [
            finding for finding in filtered_findings if linked_evidence_for_finding(finding)
        ]
    elif evidence_link_filter == "Without linked evidence":
        filtered_findings = [
            finding for finding in filtered_findings if not linked_evidence_for_finding(finding)
        ]

    if not filtered_findings:
        st.info("No findings match the current filters.")
        return

    summary_rows = []
    for finding in filtered_findings:
        summary_rows.append(
            {
                "id": finding["id"],
                "severity": effective_finding_severity(finding),
                "confidence": finding.get("confidence"),
                "module": finding.get("module_id"),
                "entity": entity_lookup.get(finding.get("entity_id"), finding.get("entity_id") or "-"),
                "title": finding.get("title"),
                "status": finding_status_label(finding.get("status")),
                "created_at": finding.get("created_at"),
            }
        )
    st.dataframe(pd.DataFrame(summary_rows), width="stretch")

    findings_by_severity: dict[str, list[dict]] = {severity: [] for severity in FINDING_SEVERITY_ORDER}
    for finding in filtered_findings:
        severity = effective_finding_severity(finding).lower()
        if severity not in findings_by_severity:
            severity = "info"
        findings_by_severity[severity].append(finding)

    for severity in FINDING_SEVERITY_ORDER:
        severity_findings = findings_by_severity.get(severity, [])
        if not severity_findings:
            continue
        st.subheader(f"{severity.upper()} ({len(severity_findings)})")
        for finding in severity_findings:
            entity_label = entity_lookup.get(finding.get("entity_id"), finding.get("entity_id") or "-")
            status_text = finding_status_label(finding.get("status"))
            expander_label = (
                f"[{effective_finding_severity(finding).upper()}] {finding.get('title', 'Finding')} · "
                f"{finding.get('module_id')} · {entity_label} · {status_text}"
            )
            with st.expander(expander_label, expanded=False):
                render_finding_detail(finding, entity_lookup, linked_evidence_for_finding(finding))

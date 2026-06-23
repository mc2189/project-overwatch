"""Concise result cards for the assessment workspace."""

from __future__ import annotations

from typing import Any

import streamlit as st

from modules.module_registry import get_module
from ui.constants import SEVERITY_RANK
from ui.results import render_result_detail_tabs
from utils.finding_interpreter import risk_findings
from utils.pivot_discovery import discover_pivots_from_results
from utils.result_status import status_label
from utils.result_summary import summarize_run_results


def _highest_severity(findings: list[dict]) -> str | None:
    best = None
    best_rank = -1
    for finding in findings:
        severity = (finding.get("severity") or "info").lower()
        rank = SEVERITY_RANK.get(severity, 0)
        if rank > best_rank:
            best_rank = rank
            best = severity
    return best


def _suggested_action_for_result(result: dict[str, Any]) -> str:
    risk = risk_findings(result.get("interpreter_findings") or [])
    if not risk:
        if result.get("warnings"):
            return "Review warnings and decide whether follow-up checks are needed."
        return "No immediate action — review details if this target is in scope."
    top = risk[0]
    actions = top.get("suggested_actions") or []
    if actions:
        return str(actions[0])
    return f"Review {top.get('title', 'finding')} ({top.get('severity', 'info')})."


def render_concise_result_card(result: dict[str, Any], *, expanded: bool = False) -> None:
    """Render a single concise result card with collapsed details."""
    module = get_module(result.get("module_id"))
    display_name = module.display_name if module else result.get("module_id", "Module")
    risk = risk_findings(result.get("interpreter_findings") or [])
    highest = _highest_severity(risk)
    warning_count = len(result.get("warnings") or [])
    run_status = result.get("status", "unknown")

    with st.container(border=True):
        cols = st.columns([3, 1])
        with cols[0]:
            st.markdown(f"**{display_name}**")
            st.caption(
                f"{status_label(run_status)} · "
                f"{len(risk)} key finding(s) · {warning_count} warning(s)"
                + (f" · highest: {highest}" if highest else "")
            )
        with cols[1]:
            if run_status == "blocked":
                st.error("Blocked")
            elif run_status == "error" or not result.get("success"):
                st.error("Failed")
            elif warning_count:
                st.warning("Warnings")
            else:
                st.success("OK")

        summary = (result.get("summary") or "").strip()
        if summary:
            st.write(summary[:280] + ("…" if len(summary) > 280 else ""))

        st.caption(f"Suggested action: {_suggested_action_for_result(result)}")

        with st.expander("Details", expanded=expanded):
            render_result_detail_tabs(result)


def render_workspace_results(
    results: list[dict[str, Any]],
    *,
    target: str,
    case_id: int,
) -> list[dict[str, Any]]:
    """Render concise results section and return discovered pivots."""
    if not results:
        return []

    st.markdown("### Results")
    st.caption(f"Target: `{target}`")
    summary = summarize_run_results(results)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Checks", summary["modules_run"])
    c2.metric("Completed", summary["completed"])
    c3.metric("Findings", summary["total_findings"])
    c4.metric("Highest", summary["highest_severity"] or "—")

    for index, result in enumerate(results):
        render_concise_result_card(result, expanded=index == 0 and len(results) == 1)

    pivots = discover_pivots_from_results(results)
    if pivots:
        st.markdown("**New pivots discovered**")
        for pivot in pivots[:8]:
            cols = st.columns([3, 1, 1])
            with cols[0]:
                st.markdown(f"**{pivot['pivot_type']}** — `{pivot['value']}`")
                st.caption(f"From {pivot.get('source_module', 'run')}")
            with cols[1]:
                if st.button("Add to queue", key=f"pivot_queue_{pivot['pivot_type']}_{pivot['value']}"):
                    st.session_state.workspace_queue_pivot = pivot
            with cols[2]:
                if st.button("Open entity", key=f"pivot_entity_{pivot['pivot_type']}_{pivot['value']}"):
                    st.session_state.operation_target = pivot["value"]
                    st.session_state.nav_page = "Entity Workspace"
                    st.rerun()

    st.markdown("**Report journey**")
    r1, r2, r3 = st.columns(3)
    with r1:
        if st.button("Generate report", key="workspace_generate_report"):
            st.session_state.nav_page = "Report"
            st.rerun()
    with r2:
        if st.button("Review findings", key="workspace_review_findings"):
            st.session_state.nav_page = "Findings"
            st.rerun()
    with r3:
        if st.button("Review evidence", key="workspace_review_evidence"):
            st.session_state.nav_page = "Evidence Locker"
            st.rerun()

    return pivots

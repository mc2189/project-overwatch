"""Concise result cards for the assessment workspace."""

from __future__ import annotations

from typing import Any

import streamlit as st

from modules.module_registry import get_module
from ui.action_cards import render_pivot_cards
from ui.constants import SEVERITY_RANK
from ui.results import (
    render_result_interpretation_tab,
    render_result_module_output_tab,
    render_result_raw_tab,
    render_result_structured_tab,
    render_result_summary_tab,
)
from ui.styles import render_empty_state, render_status_chip, section_heading
from ui.workspace_actions import apply_workspace_action
from ui.workspace_cards import render_report_journey_cards
from utils.finding_interpreter import risk_findings
from utils.next_actions import finalize_actions, make_action
from utils.pivot_discovery import discover_pivots_from_results
from utils.result_next_actions import _http_tls_unreachable, suggest_result_action
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


def _result_status_key(result: dict[str, Any]) -> str:
    run_status = result.get("status", "unknown")
    if run_status == "blocked":
        return "blocked"
    if run_status in {"error"} or not result.get("success"):
        return "failed"
    if _http_tls_unreachable(result) or run_status == "partial":
        return "no_response"
    if result.get("warnings"):
        return "warning"
    return "complete"


def render_result_detail_expanders(result: dict[str, Any]) -> None:
    """Collapsed detail expanders for a result card."""
    with st.expander("Summary", expanded=False):
        render_result_summary_tab(result)
    with st.expander("Analyst interpretation", expanded=False):
        render_result_interpretation_tab(result)
    with st.expander("Findings", expanded=False):
        findings = risk_findings(result.get("interpreter_findings") or [])
        if not findings:
            render_empty_state("No findings yet for this check.")
        else:
            for finding in findings[:12]:
                st.markdown(f"- **{finding.get('title', 'Finding')}** ({finding.get('severity', 'info')})")
                if finding.get("explanation"):
                    st.caption(str(finding["explanation"])[:200])
    with st.expander("Evidence / module output", expanded=False):
        render_result_module_output_tab(result)
    with st.expander("Raw output", expanded=False):
        render_result_raw_tab(result)
    with st.expander("Structured data", expanded=False):
        render_result_structured_tab(result)


def render_concise_result_card(
    result: dict[str, Any],
    *,
    target: str,
    case_id: int,
    card_index: int = 0,
) -> None:
    """Render a single concise result card with collapsed details."""
    module = get_module(result.get("module_id"))
    display_name = module.display_name if module else result.get("module_id", "Module")
    risk = risk_findings(result.get("interpreter_findings") or [])
    highest = _highest_severity(risk)
    warning_count = len(result.get("warnings") or [])
    status_key = _result_status_key(result)
    next_action = finalize_actions(
        [suggest_result_action(result, target=target)],
        case_id=case_id,
        operating_context=st.session_state.get("operating_context", "passive_research"),
        personal_lab_confirmed=bool(st.session_state.get("personal_lab_confirmed")),
        authorisation_confirmed=bool(st.session_state.get("authorisation_confirmed")),
    )[0]

    with st.container(border=True):
        head = st.columns([4, 1])
        with head[0]:
            st.markdown(f"**{display_name}**")
        with head[1]:
            render_status_chip(status_key)

        summary = (result.get("summary") or "").strip()
        if summary:
            st.write(summary[:220] + ("…" if len(summary) > 220 else ""))
        elif _http_tls_unreachable(result):
            parsed = result.get("parsed_data") or {}
            host = parsed.get("host") or target
            port = parsed.get("port") or 443
            st.caption(
                f"No response from {host}:{port}. The selected service was not reachable."
            )

        st.caption(
            f"{len(risk)} finding(s) · {warning_count} warning(s)"
            + (f" · highest: {highest}" if highest else "")
        )

        if _http_tls_unreachable(result):
            st.caption(
                "This does not prove missing headers or weak TLS. "
                "It means no usable response was received."
            )

        if next_action.get("title"):
            st.caption(f"Next: **{next_action.get('title')}**")
        if next_action.get("action_type") != "no_action" and next_action.get("enabled"):
            if st.button(
                next_action.get("button_label", "Go"),
                key=f"result_action_{card_index}_{result.get('module_id')}",
                width="stretch",
            ):
                st.session_state.workspace_action_message = apply_workspace_action(
                    next_action, case_id
                )
                st.rerun()
        elif next_action.get("blocked_reason"):
            st.caption(next_action["blocked_reason"])

        with st.expander("Details", expanded=False):
            render_result_detail_expanders(result)


def render_workspace_results(
    results: list[dict[str, Any]],
    *,
    target: str,
    case_id: int,
) -> list[dict[str, Any]]:
    """Render concise results section and return discovered pivots."""
    if not results:
        return []

    section_heading("Results")
    if st.session_state.get("workspace_action_message"):
        st.success(st.session_state.workspace_action_message)
        if st.button("Dismiss action message", key="result_dismiss_action_msg"):
            del st.session_state["workspace_action_message"]
            st.rerun()

    summary = summarize_run_results(results)
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Checks", summary["modules_run"])
    c2.metric("Completed", summary["completed"])
    c3.metric("Findings", summary["total_findings"])
    c4.metric("Highest", summary["highest_severity"] or "—")

    for index, result in enumerate(results):
        render_concise_result_card(
            result,
            target=target,
            case_id=case_id,
            card_index=index,
        )

    pivots = discover_pivots_from_results(results)
    render_pivot_cards(pivots, case_id=case_id, key_prefix="result_pivot")

    report_actions = finalize_actions(
        [
            make_action(
                title="Review findings",
                reason="Triage open findings from this run.",
                action_type="open_finding",
                priority="high",
                button_label="Review findings",
                action_id="result_journey_findings",
            ),
            make_action(
                title="Review evidence",
                reason="Check evidence locker before reporting.",
                action_type="review_evidence",
                priority="medium",
                button_label="Review evidence",
                action_id="result_journey_evidence",
            ),
            make_action(
                title="Generate report",
                reason="Summarise this run in a case report.",
                action_type="create_report",
                priority="medium",
                button_label="Generate report",
                action_id="result_journey_report",
            ),
            make_action(
                title="Add analyst note",
                reason="Capture observations before reporting.",
                action_type="add_note",
                priority="low",
                button_label="Add note",
                action_id="result_journey_note",
            ),
        ],
        case_id=case_id,
        operating_context=st.session_state.get("operating_context", "passive_research"),
        personal_lab_confirmed=bool(st.session_state.get("personal_lab_confirmed")),
        authorisation_confirmed=bool(st.session_state.get("authorisation_confirmed")),
    )
    render_report_journey_cards(
        report_actions,
        case_id=case_id,
        apply_action=apply_workspace_action,
    )

    return pivots

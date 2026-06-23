"""Concise result cards for the assessment workspace."""

from __future__ import annotations

from typing import Any

import streamlit as st

from modules.module_registry import get_module
from ui.action_cards import render_pivot_cards
from ui.constants import SEVERITY_RANK
from ui.results import render_result_detail_tabs
from ui.workspace_actions import apply_workspace_action
from utils.finding_interpreter import risk_findings
from utils.next_actions import finalize_actions, make_action
from utils.pivot_discovery import discover_pivots_from_results
from utils.result_next_actions import suggest_result_action, _http_tls_unreachable
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


def render_concise_result_card(
    result: dict[str, Any],
    *,
    target: str,
    case_id: int,
    expanded: bool = False,
    card_index: int = 0,
) -> None:
    """Render a single concise result card with collapsed details."""
    module = get_module(result.get("module_id"))
    display_name = module.display_name if module else result.get("module_id", "Module")
    risk = risk_findings(result.get("interpreter_findings") or [])
    highest = _highest_severity(risk)
    warning_count = len(result.get("warnings") or [])
    run_status = result.get("status", "unknown")
    next_action = finalize_actions(
        [suggest_result_action(result, target=target)],
        case_id=case_id,
        operating_context=st.session_state.get("operating_context", "passive_research"),
        personal_lab_confirmed=bool(st.session_state.get("personal_lab_confirmed")),
        authorisation_confirmed=bool(st.session_state.get("authorisation_confirmed")),
    )[0]

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

        parsed = result.get("parsed_data") or {}
        if parsed.get("target_selection_note"):
            st.caption(parsed["target_selection_note"])
        if _http_tls_unreachable(result):
            st.caption(
                "This does not prove missing headers or weak TLS. "
                "It means no usable response was received."
            )

        st.caption(f"Next step: {next_action.get('title')}")
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
    if st.session_state.get("workspace_action_message"):
        st.success(st.session_state.workspace_action_message)
        if st.button("Dismiss action message", key="result_dismiss_action_msg"):
            del st.session_state["workspace_action_message"]
            st.rerun()
    st.caption(f"Target: `{target}`")
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
            expanded=index == 0 and len(results) == 1,
            card_index=index,
        )

    pivots = discover_pivots_from_results(results)
    render_pivot_cards(pivots, case_id=case_id, key_prefix="result_pivot")

    report_actions = finalize_actions(
        [
            make_action(
                title="Generate report",
                reason="Summarise this run in a case report.",
                action_type="create_report",
                priority="medium",
                button_label="Generate report",
                action_id="result_journey_report",
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
                title="Review findings",
                reason="Triage open findings from this run.",
                action_type="open_finding",
                priority="medium",
                button_label="Open findings",
                action_id="result_journey_findings",
            ),
        ],
        case_id=case_id,
        operating_context=st.session_state.get("operating_context", "passive_research"),
        personal_lab_confirmed=bool(st.session_state.get("personal_lab_confirmed")),
        authorisation_confirmed=bool(st.session_state.get("authorisation_confirmed")),
    )
    st.markdown("**Report journey**")
    cols = st.columns(len(report_actions))
    for col, action in zip(cols, report_actions):
        with col:
            if action.get("enabled") and st.button(
                action.get("button_label", "Go"),
                key=f"rj_{action['id']}",
                width="stretch",
            ):
                st.session_state.workspace_action_message = apply_workspace_action(action, case_id)
                st.rerun()

    return pivots

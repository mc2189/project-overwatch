"""Inline Batch Queue panel for Assessment Workspace sidebars."""

from __future__ import annotations

from typing import Any

import streamlit as st

from database.db_setup import get_db_conn
from ui.batch_queue_page import navigate_to_batch_queue
from utils.batch_queue import sort_queue_items
from utils.batch_queue_runner import run_batch_queue_for_case
from utils.batch_queue_store import load_batch_queue
from utils.batch_queue_summary import summarize_batch_queue
from utils.case_memory_refresh import store_case_memory_refresh
from utils.operating_context import CLIENT_ENGAGEMENT, PERSONAL_LAB, PASSIVE_RESEARCH


def _active_queue_allowed(
    operating_context: str,
    *,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
) -> bool:
    if operating_context == PASSIVE_RESEARCH:
        return False
    if operating_context == PERSONAL_LAB:
        return personal_lab_confirmed
    if operating_context == CLIENT_ENGAGEMENT:
        return authorisation_confirmed
    return False


def _complete_inline_queue_run(
    case_id: int,
    outcome: dict[str, Any],
    *,
    scroll_after: bool = True,
) -> None:
    if outcome.get("messages"):
        st.session_state.workspace_action_message = outcome["messages"][-1]
    if outcome.get("processed", 0) > 0:
        conn = get_db_conn()
        try:
            store_case_memory_refresh(
                st.session_state,
                case_id,
                conn=conn,
                scroll_after=scroll_after,
            )
        finally:
            conn.close()
    st.rerun()


def render_inline_batch_queue(
    case_id: int,
    *,
    operating_context: str,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
    emergency_stop_active: bool = False,
    key_prefix: str = "inline_batch_queue",
) -> dict[str, Any]:
    """Show persisted queue status and quick actions beside autopilot controls."""
    items = sort_queue_items(load_batch_queue(case_id))
    summary = summarize_batch_queue(items)
    active_allowed = _active_queue_allowed(
        operating_context,
        personal_lab_confirmed=personal_lab_confirmed,
        authorisation_confirmed=authorisation_confirmed,
    )

    st.markdown("**Persisted Batch Queue**")
    if summary["total"] == 0:
        st.caption("Empty — **Run queue** or **Run lab assessment** adds follow-up checks here.")
        return summary

    st.caption(
        f"{summary['queued']} queued · {summary['passive_queued']} passive · "
        f"{summary['active_queued']} active · {summary['completed']} done · "
        f"{summary['failed']} blocked/error"
    )

    if summary["preview_queued"]:
        with st.expander("Queued items", expanded=summary["queued"] <= 4):
            for item in summary["preview_queued"]:
                mode_label = item.get("mode") or "passive"
                compat = item.get("compatibility_status") or "compatible"
                st.markdown(
                    f"- **{item.get('entity_value')}** · {item.get('module_display_name')} "
                    f"({mode_label}, {compat})"
                )
                if item.get("summary"):
                    st.caption(str(item["summary"])[:160])

    col_open, col_passive, col_active = st.columns(3)
    with col_open:
        if st.button("Open Batch Queue", key=f"{key_prefix}_open", width="stretch"):
            navigate_to_batch_queue()
            st.rerun()
    with col_passive:
        passive_disabled = emergency_stop_active or summary["passive_queued"] == 0
        if st.button(
            "Run passive queued",
            key=f"{key_prefix}_run_passive",
            disabled=passive_disabled,
            width="stretch",
            help="Execute compatible passive items without leaving the workspace.",
        ):
            outcome = run_batch_queue_for_case(
                case_id,
                mode="passive",
                operating_context=operating_context,
                authorisation_confirmed=authorisation_confirmed,
                personal_lab_confirmed=personal_lab_confirmed,
            )
            _complete_inline_queue_run(case_id, outcome)
    with col_active:
        active_disabled = (
            emergency_stop_active
            or summary["active_queued"] == 0
            or not active_allowed
        )
        active_help = "Execute queued active items (requires Personal Lab or client authorisation)."
        if operating_context == PASSIVE_RESEARCH:
            active_help = "Switch to Personal Lab or Client Engagement to run active queue items."
        elif not active_allowed:
            active_help = "Confirm authorisation before running active queue items."
        if st.button(
            "Run active queued",
            key=f"{key_prefix}_run_active",
            disabled=active_disabled,
            width="stretch",
            help=active_help,
        ):
            outcome = run_batch_queue_for_case(
                case_id,
                mode="active",
                operating_context=operating_context,
                authorisation_confirmed=authorisation_confirmed,
                personal_lab_confirmed=personal_lab_confirmed,
            )
            _complete_inline_queue_run(case_id, outcome)

    st.code(
        f"python scripts/run_queue_worker.py --case-id {case_id} --once --personal-lab-confirmed",
        language="bash",
    )

    return summary

"""Express Lab UI — simplified Personal Lab workspace for solo operators."""

from __future__ import annotations

from typing import Any

import streamlit as st

from ui.batch_queue_page import navigate_to_batch_queue
from ui.styles import section_heading
from utils.assessment_goals import (
    GOAL_CUSTOM,
    GOAL_QUICK_SAFETY,
    goal_description,
    goal_label,
    list_assessment_goals,
)
from utils.run_modes import LOCAL_IP_CHECK, QUICK_CHECK
from utils.autopilot_engine import update_autopilot_from_results
from utils.batch_queue import sort_queue_items
from utils.batch_queue_runner import run_batch_queue_for_case
from utils.batch_queue_store import load_batch_queue
from utils.batch_queue_summary import summarize_batch_queue
from utils.case_memory_refresh import store_case_memory_refresh
from utils.express_lab import EXPRESS_GOAL_LOCKED_KEY
from database.db_setup import get_db_conn


def render_express_run_panel(
    *,
    goal_id: str,
    selected_count: int,
    passive_count: int,
    active_count: int,
    launch_blocked: str | None,
    emergency_stop_active: bool,
) -> bool:
    """Render the primary Assess target control. Returns True when clicked."""
    st.markdown(
        f"**{goal_label(goal_id)}** — {selected_count} check(s) "
        f"({passive_count} passive · {active_count} active)"
    )
    st.caption(goal_description(goal_id))
    if launch_blocked:
        st.warning(launch_blocked)
    elif emergency_stop_active:
        st.warning("Emergency stop is active for this engagement — assessment is paused.")

    return st.button(
        "Assess target",
        type="primary",
        disabled=launch_blocked is not None or emergency_stop_active,
        width="stretch",
        help="Run recommended checks, autopilot follow-ups, and baseline update when clean.",
    )


def render_express_advanced_controls(
    *,
    goal_session_key: str,
    current_goal: str,
    target: str,
    target_type: str,
    selected_ids: list[str],
    run_mode_id: str,
    journey: dict,
    render_journey_details,
    render_custom_module_picker,
    render_advanced_module_settings,
    render_module_check_card,
    quick_check_supports_port_scan_option,
    is_private_ipv4_target,
    parse_custom_web_port_list,
    render_readiness_summary,
    operating_context: str,
    passive_count: int,
    active_count: int,
    preflight_result: str,
    launch_blocked: str | None,
    show_run_selected: bool,
    on_run_selected,
) -> None:
    """Power-user controls hidden under Advanced."""
    with st.expander("Advanced", expanded=False):
        st.caption("Override auto-goal, run primary checks only, or tune module settings.")

        goal_ids = [goal_id for goal_id, _ in list_assessment_goals()]
        picked = st.selectbox(
            "Assessment goal",
            options=goal_ids,
            index=goal_ids.index(current_goal) if current_goal in goal_ids else 0,
            format_func=goal_label,
            key="express_advanced_goal_select",
        )
        if picked != current_goal:
            st.session_state[EXPRESS_GOAL_LOCKED_KEY] = True
            st.session_state[goal_session_key] = picked
            st.rerun()
        if st.button("Use auto-goal from target", key="express_unlock_auto_goal"):
            st.session_state[EXPRESS_GOAL_LOCKED_KEY] = False
            st.rerun()
        if st.session_state.get(EXPRESS_GOAL_LOCKED_KEY):
            st.caption("Auto-goal is off — pick a goal above or re-enable auto-goal.")

        if current_goal == GOAL_QUICK_SAFETY and quick_check_supports_port_scan_option(target_type):
            st.checkbox(
                "Include light port scan (active)",
                value=st.session_state.get("quick_check_include_port_scan", False),
                key="quick_check_include_port_scan",
            )

        render_readiness_summary(
            selected_count=len(selected_ids),
            passive_count=passive_count,
            active_count=active_count,
            preflight_result=preflight_result,
            operating_context=operating_context,
            one_line_warning=launch_blocked,
        )

        if show_run_selected and st.button(
            "Run selected checks only",
            key="express_run_selected_only",
            disabled=launch_blocked is not None,
            help="Skip autopilot follow-ups and auto-snapshot.",
        ):
            on_run_selected()

        check_rows = (journey.get("recommended") or []) + (journey.get("active_needs_confirmation") or [])
        if check_rows:
            st.markdown("**Recommended checks**")
            for row in check_rows[:6]:
                render_module_check_card(row, target=target)

        with st.expander("Journey details", expanded=False):
            render_journey_details(journey, target)

        if current_goal == GOAL_CUSTOM:
            render_custom_module_picker(target)

        if is_private_ipv4_target(target.strip()):
            with st.expander("Local IP web port options", expanded=False):
                custom_ports_text = st.text_input(
                    "Custom web port list (max 10)",
                    value=st.session_state.get("custom_web_ports_text", ""),
                    placeholder="e.g. 8080, 8443",
                    key="express_custom_web_ports_input",
                )
                ports, port_error = parse_custom_web_port_list(custom_ports_text)
                if port_error and custom_ports_text.strip():
                    st.caption(port_error)
                if st.checkbox(
                    "Confirm ports for HTTP/TLS checking",
                    key="express_custom_web_ports_confirmed",
                ) and ports:
                    st.session_state.pending_custom_web_ports = ports

        conservative_nmap = run_mode_id in {QUICK_CHECK, LOCAL_IP_CHECK}
        render_advanced_module_settings(
            selected_ids,
            target,
            conservative_nmap=conservative_nmap,
            goal_id=current_goal,
            run_mode_id=run_mode_id,
        )


def render_express_followups_panel(
    *,
    case_id: int,
    target: str,
    goal_id: str | None,
    latest_results: list[dict[str, Any]],
    operating_context: str,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
    emergency_stop_active: bool,
    conn: Any | None,
    quiet: bool = False,
) -> dict[str, Any]:
    """Compact follow-up queue status instead of full autopilot + batch panels."""
    update = update_autopilot_from_results(
        case_id=case_id,
        target=target.strip(),
        latest_results=latest_results,
        session_state=st.session_state,
        operating_context=operating_context,
        personal_lab_confirmed=personal_lab_confirmed,
        authorisation_confirmed=authorisation_confirmed,
        goal_id=goal_id,
        emergency_stop_active=emergency_stop_active,
        conn=conn,
    )
    batch_summary = summarize_batch_queue(sort_queue_items(load_batch_queue(case_id)))
    pending_autopilot = [
        row
        for row in update.get("queue") or []
        if row.get("status") in {"proposed", "queued"} and not row.get("blocked_reason")
    ]
    has_work = bool(batch_summary["queued"] or pending_autopilot or latest_results)
    if quiet and not has_work:
        return {"update": update, "batch_summary": batch_summary, "hidden": True}

    section_heading("Follow-ups")
    st.caption(
        f"Batch queue: **{batch_summary['queued']}** queued · "
        f"**{batch_summary['completed']}** done · "
        f"Autopilot: **{len(pending_autopilot)}** pending"
    )
    if update.get("stop") and update.get("stop_reason"):
        st.caption(update["stop_reason"])

    col_run, col_open = st.columns(2)
    with col_run:
        run_disabled = emergency_stop_active or batch_summary["queued"] == 0
        if st.button(
            "Run remaining queued",
            key=f"express_run_remaining_{case_id}",
            disabled=run_disabled,
            width="stretch",
        ):
            outcome = run_batch_queue_for_case(
                case_id,
                mode="all",
                operating_context=operating_context,
                authorisation_confirmed=authorisation_confirmed,
                personal_lab_confirmed=personal_lab_confirmed,
            )
            if outcome.get("messages"):
                st.session_state.workspace_action_message = outcome["messages"][-1]
            if outcome.get("processed", 0) > 0:
                db_conn = get_db_conn()
                try:
                    store_case_memory_refresh(
                        st.session_state,
                        case_id,
                        conn=db_conn,
                        scroll_after=True,
                    )
                finally:
                    db_conn.close()
            st.rerun()
    with col_open:
        if st.button("Open Batch Queue", key=f"express_open_batch_{case_id}", width="stretch"):
            navigate_to_batch_queue()
            st.rerun()

    summary = update.get("summary") or {}
    if summary.get("next_manual_action"):
        st.caption(f"Next: {summary['next_manual_action']}")
    return {"update": update, "batch_summary": batch_summary, "hidden": False}

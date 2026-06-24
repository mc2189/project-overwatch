"""Assessment playbooks and autopilot queue UI for the Assessment Workspace."""

from __future__ import annotations

from typing import Any

import streamlit as st

from ui.styles import section_heading
from utils.assessment_playbooks import (
    MODE_ASSISTED,
    MODE_MANUAL,
    MODE_PASSIVE_AUTOPILOT,
    MODE_PERSONAL_LAB_AUTOPILOT,
    assessment_mode_labels,
    default_assessment_mode,
    get_playbook,
    list_playbooks,
    playbook_for_goal,
    playbook_suitable_for_target,
)
from utils.autopilot_engine import (
    SESSION_ASSESSMENT_MODE_KEY,
    SESSION_AUTOPILOT_CONFIRMED_KEY,
    SESSION_AUTOPILOT_STOP_KEY,
    SESSION_PLAYBOOK_KEY,
    queue_autopilot_to_batch,
    resume_autopilot,
    run_autopilot_confirmed_queue,
    stop_autopilot,
    update_autopilot_from_results,
)
from utils.settings_manager import autopilot_settings, passive_autopilot_enabled, personal_lab_autopilot_enabled
from utils.target_detection import get_target_type


def _init_autopilot_state() -> None:
    settings = autopilot_settings()
    st.session_state.setdefault(SESSION_ASSESSMENT_MODE_KEY, settings["default_mode"])
    st.session_state.setdefault(SESSION_AUTOPILOT_STOP_KEY, False)
    st.session_state.setdefault(SESSION_AUTOPILOT_CONFIRMED_KEY, False)


def render_autopilot_panel(
    *,
    case_id: int,
    target: str,
    goal_id: str | None,
    latest_results: list[dict[str, Any]],
    operating_context: str,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
    emergency_stop_active: bool = False,
    conn: Any | None = None,
) -> dict[str, Any]:
    """Render playbook selector, queue preview, and autopilot controls."""
    _init_autopilot_state()
    section_heading("Assessment mode & playbooks")

    mode_labels = assessment_mode_labels()
    mode_options = list(mode_labels.keys())
    if not passive_autopilot_enabled():
        mode_options = [mode for mode in mode_options if mode != MODE_PASSIVE_AUTOPILOT]
    if not personal_lab_autopilot_enabled():
        mode_options = [mode for mode in mode_options if mode != MODE_PERSONAL_LAB_AUTOPILOT]

    current_mode = st.session_state.get(SESSION_ASSESSMENT_MODE_KEY, default_assessment_mode())
    if current_mode not in mode_options:
        current_mode = MODE_ASSISTED if MODE_ASSISTED in mode_options else mode_options[0]

    selected_mode = st.radio(
        "Assessment mode",
        options=mode_options,
        index=mode_options.index(current_mode),
        format_func=lambda value: mode_labels[value],
        key="assessment_mode_radio",
        help="Manual shows suggestions only. Assisted builds a queue for your confirmation. Autopilot modes never run active checks silently.",
    )
    st.session_state[SESSION_ASSESSMENT_MODE_KEY] = selected_mode

    playbooks = list_playbooks()
    playbook_ids = [row.playbook_id for row in playbooks]
    suggested = playbook_for_goal(goal_id)
    default_playbook = suggested.playbook_id if suggested else playbook_ids[0]
    st.session_state.setdefault(SESSION_PLAYBOOK_KEY, default_playbook)

    current_playbook_id = st.session_state.get(SESSION_PLAYBOOK_KEY, default_playbook)
    if current_playbook_id not in playbook_ids:
        current_playbook_id = default_playbook

    selected_playbook_id = st.selectbox(
        "Playbook",
        options=playbook_ids,
        index=playbook_ids.index(current_playbook_id),
        format_func=lambda value: get_playbook(value).display_name if get_playbook(value) else value,
        key="autopilot_playbook_select",
    )
    st.session_state[SESSION_PLAYBOOK_KEY] = selected_playbook_id
    playbook = get_playbook(selected_playbook_id)
    if playbook:
        st.caption(playbook.description)
        target_type = get_target_type(target.strip()) if target.strip() else "unknown"
        if target.strip() and not playbook_suitable_for_target(playbook, target_type):
            st.warning(
                f"This playbook is intended for {', '.join(playbook.suitable_target_types)} targets — "
                f"current target type is {target_type}."
            )

    if selected_mode == MODE_PERSONAL_LAB_AUTOPILOT:
        st.checkbox(
            "I confirm Personal Lab autopilot may run safe active follow-ups on in-scope lab targets",
            key=SESSION_AUTOPILOT_CONFIRMED_KEY,
        )

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

    summary = update.get("summary") or {}
    if update.get("stop") and update.get("stop_reason"):
        st.warning(update["stop_reason"])

    queue = update.get("queue") or []
    proposed = update.get("proposed") or []

    if selected_mode == MODE_MANUAL and proposed:
        st.markdown("**Overwatch suggests these next checks**")
        for action in proposed[:8]:
            passive_label = "passive" if action.get("is_passive") else "active" if action.get("is_active") else "advisory"
            confirm = "needs confirmation" if action.get("requires_confirmation") else "ready"
            st.markdown(f"- **{action.get('title')}** ({passive_label}, {confirm})")
            st.caption(action.get("why_detail") or action.get("reason"))
            if action.get("blocked_reason"):
                st.caption(f"Blocked: {action['blocked_reason']}")

    if selected_mode != MODE_MANUAL and queue:
        active_rows = [row for row in queue if row.get("is_active")]
        passive_rows = [row for row in queue if row.get("is_passive")]
        st.markdown(
            f"**Queue preview:** {len(queue)} item(s) · "
            f"{len(passive_rows)} passive · {len(active_rows)} active"
        )
        with st.expander("Proposed next checks", expanded=selected_mode == MODE_ASSISTED):
            for item in queue[:12]:
                status = item.get("status", "proposed")
                label = "passive" if item.get("is_passive") else "active" if item.get("is_active") else "advisory"
                st.markdown(f"- **{item.get('title')}** · {status} · {label}")
                st.caption(item.get("why_detail") or item.get("reason"))
                if item.get("blocked_reason"):
                    st.caption(f"Blocked: {item['blocked_reason']}")

    col_run, col_stop, col_resume = st.columns(3)
    with col_run:
        if selected_mode in {MODE_ASSISTED, MODE_PASSIVE_AUTOPILOT, MODE_PERSONAL_LAB_AUTOPILOT}:
            if st.button("Run queue", key="autopilot_run_queue", disabled=emergency_stop_active):
                _, messages, _ = queue_autopilot_to_batch(
                    case_id,
                    st.session_state,
                    operating_context=operating_context,
                    personal_lab_confirmed=personal_lab_confirmed,
                    authorisation_confirmed=authorisation_confirmed,
                )
                if selected_mode == MODE_PERSONAL_LAB_AUTOPILOT and st.session_state.get(
                    SESSION_AUTOPILOT_CONFIRMED_KEY
                ):
                    run_autopilot_confirmed_queue(
                        case_id=case_id,
                        session_state=st.session_state,
                        operating_context=operating_context,
                        personal_lab_confirmed=personal_lab_confirmed,
                        authorisation_confirmed=authorisation_confirmed,
                        include_active=True,
                    )
                for message in messages[:6]:
                    st.caption(message)
                st.rerun()
    with col_stop:
        if st.button("Stop autopilot", key="autopilot_stop"):
            stop_autopilot(st.session_state)
            st.rerun()
    with col_resume:
        if st.button("Resume", key="autopilot_resume"):
            resume_autopilot(st.session_state)
            st.rerun()

    if summary:
        with st.expander("Autopilot summary", expanded=False):
            st.markdown(f"**Playbook:** {summary.get('playbook_name', '—')}")
            if summary.get("targets_assessed"):
                st.markdown(f"**Targets:** {', '.join(summary['targets_assessed'][:6])}")
            if summary.get("modules_run"):
                st.markdown(f"**Modules run:** {', '.join(summary['modules_run'][:8])}")
            st.markdown(
                f"**Completed / blocked / skipped / proposed:** "
                f"{summary.get('completed', 0)} / {summary.get('blocked', 0)} / "
                f"{summary.get('skipped', 0)} / {summary.get('proposed', 0)}"
            )
            if summary.get("highest_severity"):
                st.markdown(f"**Highest severity:** {summary['highest_severity']}")
            st.markdown(f"**Next manual action:** {summary.get('next_manual_action', '—')}")
            if summary.get("stop_reason"):
                st.caption(summary["stop_reason"])

    return update

"""Guided assessment workspace — main Run Operation experience."""

from __future__ import annotations

import streamlit as st

from database.db_setup import create_or_get_entity, get_db_conn, infer_entity_type
from database.engagements import get_engagement_for_case
from database.personal_lab import add_personal_lab_scope_item
from modules.executor import execute_module
from modules.module_registry import get_module, is_executable
from ui.compact_preflight import render_compact_preflight
from ui.concise_results import render_workspace_results
from ui.constants import IMPLEMENTED_MODULE_IDS, MODULE_CARD_TITLES
from ui.metrics import render_compact_metrics
from ui.module_config_compact import render_advanced_module_settings, render_module_info_expanders
from ui.module_runtime import module_disable_reason, module_enabled_for_ui
from ui.run_status_panel import record_workspace_run, render_run_status_panel
from utils.assessment_goals import (
    GOAL_CUSTOM,
    GOAL_EVIDENCE_REVIEW,
    GOAL_QUICK_SAFETY,
    get_modules_for_goal,
    goal_description,
    goal_label,
    goal_to_run_mode_id,
    list_assessment_goals,
    suggested_goals_for_target,
)
from utils.journey_planner import build_assessment_journey
from utils.module_compatibility import build_operation_plan
from utils.next_actions import suggest_next_actions
from utils.operating_context import (
    CLIENT_ENGAGEMENT,
    OPERATING_CONTEXT_DESCRIPTIONS,
    PASSIVE_RESEARCH,
    PERSONAL_LAB,
    PERSONAL_LAB_CONFIRMATION_TEXT,
    enrich_operation_plan_with_preflight,
    list_operating_contexts,
    operating_context_label,
)
from utils.run_modes import (
    LOCAL_IP_CHECK,
    QUICK_CHECK,
    apply_recommended_selection,
    get_run_mode_label,
    persist_run_mode_for_case,
    quick_check_supports_port_scan_option,
    sync_run_mode_from_case,
)
from utils.security import is_private_or_local_ip
from utils.target_detection import get_target_type, normalize_target_value, target_type_label
from utils.target_profile import build_target_profile

from utils.engagement_guardrails import assess_target_scope

PREV_GOAL_KEY = "workspace_prev_goal"
RUN_GOAL_SESSION_KEY = "assessment_goal"


def _init_module_selection() -> None:
    for module_id in IMPLEMENTED_MODULE_IDS:
        st.session_state.setdefault(f"module_sel_{module_id}", False)


def _selected_module_ids() -> list[str]:
    return [
        module_id
        for module_id in IMPLEMENTED_MODULE_IDS
        if st.session_state.get(f"module_sel_{module_id}", False)
    ]


def _selection_requires_authorisation(module_ids: list[str]) -> bool:
    return any(
        (module := get_module(module_id)) is not None and module.requires_authorisation
        for module_id in module_ids
    )


def _sync_goal_selection(goal_id: str, target: str, target_type: str) -> None:
    prev_goal = st.session_state.get(PREV_GOAL_KEY)
    if prev_goal == goal_id:
        return
    if goal_id != GOAL_CUSTOM:
        include_port_scan = st.session_state.get("quick_check_include_port_scan", False)
        recommended = get_modules_for_goal(
            goal_id,
            target_type,
            target=target.strip() or None,
            quick_check_include_port_scan=include_port_scan,
        )
        apply_recommended_selection(recommended)
    st.session_state[PREV_GOAL_KEY] = goal_id


def _execute_modules(
    *,
    current_case: dict,
    target: str,
    selected_ids: list[str],
    operating_context: str,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
    run_mode_id: str,
) -> list[dict]:
    nmap_options = st.session_state.get("nmap_options", {})
    run_mode_label = get_run_mode_label(run_mode_id)
    persist_run_mode_for_case(current_case["id"], run_mode_id)
    run_results: list[dict] = []
    conn = get_db_conn()
    try:
        target_value = target.strip()
        entity = create_or_get_entity(
            current_case["id"],
            infer_entity_type(target_value),
            target_value,
            label=target_value,
            source="operation",
            conn=conn,
        )
        for module_id in selected_ids:
            module = get_module(module_id)
            if module is None or not is_executable(module):
                continue
            options: dict = {}
            if module_id == "infra_nmap":
                options = {"nmap_options": nmap_options}
            elif module_id == "infra_tls_review":
                tls_opts = st.session_state.get("tls_review_options", {})
                options = {
                    "port_override": tls_opts.get("port_override"),
                    "protocol_probes": tls_opts.get("protocol_probes", True),
                }
            elif module_id == "infra_http_security":
                http_opts = st.session_state.get("http_security_options", {})
                options = {"request_method": http_opts.get("request_method", "GET")}
            options["operating_context"] = operating_context
            options["personal_lab_confirmed"] = personal_lab_confirmed
            result = execute_module(
                module_id,
                target_value,
                options=options,
                db_context=conn,
                authorisation_confirmed=(
                    personal_lab_confirmed
                    if operating_context == PERSONAL_LAB
                    else authorisation_confirmed
                ),
                case_id=current_case["id"],
                entity_id=entity["id"],
                run_mode_id=run_mode_id,
                run_mode_label=run_mode_label,
            )
            run_results.append(result)
    finally:
        conn.close()
    return run_results


def _render_target_profile(profile: dict) -> None:
    with st.container(border=True):
        st.markdown("**Target profile**")
        if not profile.get("target"):
            st.caption("Enter a target to see type, case history, and suggested goals.")
            return
        cols = st.columns(4)
        cols[0].metric("Type", profile.get("target_type_label", "—"))
        cols[1].metric("In case", "Yes" if profile.get("known_in_case") else "No")
        cols[2].metric("Prior runs", profile.get("operations_count", 0))
        cols[3].metric("Open findings", profile.get("open_findings_count", 0))
        if profile.get("normalized") and profile["normalized"] != profile["target"]:
            st.caption(f"Normalised: `{profile['normalized']}`")
        elif profile.get("normalized"):
            st.caption(f"Value: `{profile['normalized']}`")
        if profile.get("known_in_case"):
            st.success("This target already exists in the current case.")
        families = profile.get("compatible_module_families") or []
        if families:
            st.caption("Compatible families: " + ", ".join(families))
        suggested = profile.get("suggested_goals") or []
        if suggested:
            st.caption(
                "Suggested goals: "
                + ", ".join(goal_label(goal_id) for goal_id in suggested[:4])
            )


def _render_journey_section(journey: dict) -> None:
    st.markdown("**Recommended journey**")

    def _list_rows(rows: list[dict], label: str, icon: str) -> None:
        if not rows:
            return
        st.caption(f"{icon} {label} ({len(rows)})")
        for row in rows[:12]:
            extra = ""
            if row.get("blocked_reason"):
                extra = f" — {row['blocked_reason']}"
            elif row.get("reason"):
                extra = f" — {row['reason']}"
            st.markdown(f"- {row['display_name']}{extra}")

    _list_rows(journey.get("recommended") or [], "Recommended checks", "✅")
    _list_rows(journey.get("active_needs_confirmation") or [], "Active — needs confirmation", "⚠️")
    _list_rows(journey.get("blocked") or [], "Blocked", "🚫")
    with st.expander("Optional checks", expanded=False):
        _list_rows(journey.get("optional") or [], "Optional", "○")
    with st.expander("Not relevant for this target", expanded=False):
        _list_rows(journey.get("not_relevant") or [], "Not relevant", "—")


def _render_custom_module_picker(target: str) -> None:
    with st.expander("Advanced / Custom module selection", expanded=False):
        st.caption("Power-user mode — pick any compatible module manually.")
        for module_id in IMPLEMENTED_MODULE_IDS:
            module = get_module(module_id)
            if module is None:
                continue
            enabled = module_enabled_for_ui(module, target)
            title = MODULE_CARD_TITLES.get(module_id, module.display_name)
            if enabled:
                st.checkbox(title, key=f"module_sel_{module_id}")
                render_module_info_expanders(module_id, target)
            else:
                reason = module_disable_reason(module, target) or "Unavailable"
                st.checkbox(title, value=False, disabled=True, key=f"module_sel_disabled_{module_id}")
                st.caption(reason)


def _render_next_actions(actions: list[dict]) -> None:
    st.markdown("**Suggested next actions**")
    if not actions:
        st.caption("Run checks to receive tailored suggestions.")
        return
    for action in actions[:8]:
        priority = action.get("priority", "medium")
        icon = {"high": "🔴", "medium": "🟡", "low": "⚪"}.get(priority, "○")
        st.markdown(f"{icon} **{action['title']}**")
        st.caption(action.get("reason", ""))


def render_assessment_workspace(current_case: dict, metrics: dict) -> None:
    _init_module_selection()
    st.session_state.setdefault("operation_target", "")
    st.session_state.setdefault(RUN_GOAL_SESSION_KEY, GOAL_QUICK_SAFETY)
    sync_run_mode_from_case(current_case, session_key="operation_run_mode")

    st.title("Assessment Workspace")
    st.caption(
        f"Case: **{current_case['name']}** (#{current_case['id']}) · "
        "Enter a target, choose a goal, review the journey, and run."
    )
    render_compact_metrics(metrics, minimal=True)

    if st.session_state.get("startup_notice") and not st.session_state.get("startup_notice_dismissed"):
        st.info(st.session_state.startup_notice)
        if st.button("Dismiss notice", key="dismiss_startup_notice_ws"):
            st.session_state.startup_notice_dismissed = True
            st.rerun()

    main_col, side_col = st.columns([3, 2], gap="large")

    with main_col:
        st.markdown("### Target")
        target = st.text_input(
            "Investigation target",
            value=st.session_state.operation_target,
            placeholder="IPv4, domain, URL, email, or username",
            key="workspace_target_input",
            label_visibility="collapsed",
        )
        st.session_state.operation_target = target

        target_type = get_target_type(target or "")
        conn = get_db_conn()
        try:
            profile = build_target_profile(current_case["id"], target.strip(), conn=conn)
        finally:
            conn.close()
        _render_target_profile(profile)

        st.markdown("### What do you want to achieve?")
        goal_ids = [goal_id for goal_id, _ in list_assessment_goals()]
        current_goal = st.session_state.get(RUN_GOAL_SESSION_KEY, GOAL_QUICK_SAFETY)
        if current_goal not in goal_ids:
            current_goal = GOAL_QUICK_SAFETY
        suggested = suggested_goals_for_target(target_type, target)
        default_index = goal_ids.index(current_goal) if current_goal in goal_ids else 0

        goal_id = st.selectbox(
            "Assessment goal",
            options=goal_ids,
            index=default_index,
            format_func=goal_label,
            key="assessment_goal_select",
            label_visibility="collapsed",
        )
        st.session_state[RUN_GOAL_SESSION_KEY] = goal_id
        st.caption(goal_description(goal_id))
        if suggested and goal_id not in suggested[:3]:
            st.caption(
                "Tip: "
                + ", ".join(goal_label(g) for g in suggested[:3])
                + " are commonly used for this target type."
            )

        include_port_scan = False
        if goal_id == GOAL_QUICK_SAFETY and quick_check_supports_port_scan_option(target_type):
            include_port_scan = st.checkbox(
                "Include light port scan (active — requires authorisation)",
                value=st.session_state.get("quick_check_include_port_scan", False),
                key="quick_check_include_port_scan",
            )

        _sync_goal_selection(goal_id, target, target_type)

        linked_engagement = get_engagement_for_case(current_case["id"])
        st.session_state.setdefault("operating_context", PASSIVE_RESEARCH)
        context_choices = [mode_id for mode_id, _ in list_operating_contexts()]
        if not linked_engagement:
            context_choices = [mode for mode in context_choices if mode != CLIENT_ENGAGEMENT]
        operating_context = st.session_state.get("operating_context", PASSIVE_RESEARCH)
        if operating_context not in context_choices:
            operating_context = PASSIVE_RESEARCH

        selected_ids = _selected_module_ids() if goal_id == GOAL_CUSTOM else []
        if goal_id != GOAL_CUSTOM:
            selected_ids = [
                module_id
                for module_id in get_modules_for_goal(
                    goal_id,
                    target_type,
                    target=target.strip() or None,
                    quick_check_include_port_scan=include_port_scan,
                )
                if (module := get_module(module_id)) and module_enabled_for_ui(module, target)
            ]
            apply_recommended_selection(selected_ids)
        else:
            selected_ids = _selected_module_ids()

        personal_lab_confirmed = st.session_state.get("personal_lab_confirmed", False)
        authorisation_confirmed = st.session_state.get("authorisation_confirmed", False)

        plan_conn = get_db_conn()
        try:
            journey = build_assessment_journey(
                case_id=current_case["id"],
                target=target,
                goal_id=goal_id,
                selected_module_ids=selected_ids,
                operating_context=operating_context,
                personal_lab_confirmed=personal_lab_confirmed,
                authorisation_confirmed=authorisation_confirmed,
                quick_check_include_port_scan=include_port_scan,
                conn=plan_conn,
            )
        finally:
            plan_conn.close()

        _render_journey_section(journey)
        if goal_id == GOAL_CUSTOM:
            _render_custom_module_picker(target)
        else:
            with st.expander("Module details (why / what / safety)", expanded=False):
                for module_id in selected_ids:
                    render_module_info_expanders(module_id, target)

        run_mode_id = goal_to_run_mode_id(goal_id)
        conservative_nmap = run_mode_id in {QUICK_CHECK, LOCAL_IP_CHECK}
        render_advanced_module_settings(
            selected_ids,
            target,
            conservative_nmap=conservative_nmap,
        )

        auth_required = _selection_requires_authorisation(selected_ids)
        passive_count = sum(
            1
            for module_id in selected_ids
            if (module := get_module(module_id)) and module.mode == "passive"
        )
        active_count = len(selected_ids) - passive_count

        plan_conn = get_db_conn()
        try:
            plan = enrich_operation_plan_with_preflight(
                build_operation_plan(
                    case_name=current_case["name"],
                    case_id=current_case["id"],
                    target=target,
                    selected_module_ids=selected_ids,
                    authorisation_confirmed=(
                        (personal_lab_confirmed if operating_context == PERSONAL_LAB else authorisation_confirmed)
                        if auth_required
                        else True
                    ),
                    run_mode_id=run_mode_id,
                    run_mode_label=goal_label(goal_id),
                ),
                target=target,
                case_id=current_case["id"],
                selected_module_ids=selected_ids,
                operating_context=operating_context,
                personal_lab_confirmed=personal_lab_confirmed,
                authorisation_confirmed=authorisation_confirmed,
                nmap_options=st.session_state.get("nmap_options", {}),
                conn=plan_conn,
            )
        finally:
            plan_conn.close()

        st.markdown("### Run")
        with st.container(border=True):
            oc_col, metrics_col = st.columns([2, 3])
            with oc_col:
                operating_context = st.radio(
                    "Operating context",
                    options=context_choices,
                    index=context_choices.index(operating_context),
                    format_func=operating_context_label,
                    key="workspace_operating_context",
                    horizontal=True,
                )
                st.session_state.operating_context = operating_context
            with metrics_col:
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Selected", len(selected_ids))
                m2.metric("Passive", passive_count)
                m3.metric("Active", active_count)
                m4.metric("Auth", "Yes" if auth_required else "No")
            st.caption(OPERATING_CONTEXT_DESCRIPTIONS.get(operating_context, ""))
            if plan.get("expected_outputs"):
                st.caption(
                    "Expected: "
                    + "; ".join(plan["expected_outputs"][:3])
                    + ("…" if len(plan["expected_outputs"]) > 3 else "")
                )

            preflight_status = render_compact_preflight(
                operating_context=operating_context,
                module_preflights=plan.get("module_preflights") or [],
                selected_module_ids=selected_ids,
            )
            scope_ready = not plan.get("engagement_blocked_modules")
            st.caption(f"Scope ready: **{'Yes' if scope_ready else 'No'}**")

            if auth_required and operating_context == PERSONAL_LAB:
                personal_lab_confirmed = st.checkbox(
                    PERSONAL_LAB_CONFIRMATION_TEXT,
                    value=st.session_state.get("personal_lab_confirmed", False),
                    key="workspace_personal_lab_confirmed",
                )
                st.session_state.personal_lab_confirmed = personal_lab_confirmed
            elif auth_required and operating_context == CLIENT_ENGAGEMENT:
                authorisation_confirmed = st.checkbox(
                    "I confirm authorisation under the linked client engagement.",
                    value=st.session_state.get("authorisation_confirmed", False),
                    key="workspace_client_auth_confirmed",
                )
                st.session_state.authorisation_confirmed = authorisation_confirmed

            if (
                operating_context == PERSONAL_LAB
                and target.strip()
                and any(row.get("needs_lab_scope_add") for row in plan.get("module_preflights") or [])
            ):
                is_private = target_type == "ipv4" and is_private_or_local_ip(target.strip())
                if is_private and st.button("Add to Personal Lab scope", key="ws_lab_scope_private"):
                    conn = get_db_conn()
                    try:
                        add_personal_lab_scope_item(current_case["id"], target.strip(), conn=conn)
                    finally:
                        conn.close()
                    st.rerun()
                elif personal_lab_confirmed and st.button("Add as authorised lab target", key="ws_lab_scope_public"):
                    conn = get_db_conn()
                    try:
                        add_personal_lab_scope_item(current_case["id"], target.strip(), conn=conn)
                    finally:
                        conn.close()
                    st.rerun()

            launch_blocked = None
            if goal_id == GOAL_EVIDENCE_REVIEW:
                launch_blocked = "Use Evidence Locker for uploaded artefact review."
            elif not target.strip():
                launch_blocked = "Enter a target."
            elif not selected_ids:
                launch_blocked = "No compatible checks for this goal and target."
            elif auth_required and operating_context == PASSIVE_RESEARCH:
                launch_blocked = "Select Personal Lab or Client Engagement for active checks."
            elif auth_required and operating_context == PERSONAL_LAB and not personal_lab_confirmed:
                launch_blocked = "Confirm Personal Lab authorisation."
            elif auth_required and operating_context == CLIENT_ENGAGEMENT and not authorisation_confirmed:
                launch_blocked = "Confirm client engagement authorisation."
            elif plan.get("engagement_blocked_modules"):
                launch_blocked = "Resolve preflight items before running."
            elif preflight_status.get("has_active") and not preflight_status.get("ready"):
                launch_blocked = "Active preflight needs action."

            run_clicked = st.button(
                "Run selected checks",
                type="primary",
                disabled=launch_blocked is not None,
                width="stretch",
            )
            if launch_blocked:
                st.caption(launch_blocked)

            if run_clicked and not launch_blocked:
                with st.spinner("Running checks…"):
                    results = _execute_modules(
                        current_case=current_case,
                        target=target,
                        selected_ids=selected_ids,
                        operating_context=operating_context,
                        personal_lab_confirmed=personal_lab_confirmed,
                        authorisation_confirmed=authorisation_confirmed,
                        run_mode_id=run_mode_id,
                    )
                st.session_state.latest_run_results = results
                st.session_state.latest_run_target = target.strip()
                record_workspace_run(
                    target=target.strip(),
                    module_ids=selected_ids,
                    results=results,
                    goal_label=goal_label(goal_id),
                )
                st.rerun()

        latest_results = st.session_state.get("latest_run_results") or []
        latest_target = st.session_state.get("latest_run_target", target)
        if latest_results and latest_target.strip():
            render_workspace_results(
                latest_results,
                target=latest_target,
                case_id=current_case["id"],
            )

    with side_col:
        st.markdown("### Workspace")
        st.caption(f"Target: `{target.strip() or '—'}`")
        st.caption(f"Context: {operating_context_label(st.session_state.get('operating_context', PASSIVE_RESEARCH))}")
        if linked_engagement:
            st.caption(f"Engagement: {linked_engagement.get('name')} ({linked_engagement.get('status')})")
        render_run_status_panel()

        profile_with_scope = dict(profile)
        profile_with_scope["needs_lab_scope"] = any(
            row.get("needs_lab_scope_add")
            for row in (plan.get("module_preflights") or [])
            if isinstance(row, dict)
        ) if target.strip() else False

        conn = get_db_conn()
        try:
            actions = suggest_next_actions(
                case_id=current_case["id"],
                target=target,
                goal_id=goal_id,
                target_profile=profile_with_scope,
                latest_results=st.session_state.get("latest_run_results") or [],
                operating_context=st.session_state.get("operating_context", PASSIVE_RESEARCH),
                conn=conn,
            )
        finally:
            conn.close()
        _render_next_actions(actions)

        st.markdown("**Analyst notes**")
        st.text_area(
            "Workspace notes",
            value=st.session_state.get("workspace_analyst_notes", ""),
            key="workspace_analyst_notes",
            height=100,
            label_visibility="collapsed",
            placeholder="Optional notes for this assessment session…",
        )

        if target.strip() and operating_context == CLIENT_ENGAGEMENT:
            scope_preview = assess_target_scope(target.strip(), case_id=current_case["id"])
            st.caption(
                f"Engagement scope: {(scope_preview.get('scope_status') or 'unknown').replace('_', ' ')}"
            )

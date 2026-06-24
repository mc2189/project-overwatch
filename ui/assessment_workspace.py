"""Guided assessment workspace — main Run Operation experience."""

from __future__ import annotations

import streamlit as st

from database.db_setup import create_or_get_entity, get_db_conn, infer_entity_type
from database.engagements import get_engagement_for_case
from modules.executor import execute_module
from modules.module_registry import get_module, is_executable
from ui.action_cards import render_action_cards
from ui.autopilot_panel import render_autopilot_panel
from ui.case_memory_panel import render_case_memory_panel
from ui.case_workflow_banner import render_case_workflow_strip
from ui.scroll_helpers import scroll_to_anchor
from ui.compact_preflight import render_compact_preflight
from ui.concise_results import render_workspace_results
from ui.constants import IMPLEMENTED_MODULE_IDS, MODULE_CARD_TITLES
from ui.module_config_compact import render_advanced_module_settings, render_module_info_expanders
from ui.module_runtime import module_disable_reason, module_enabled_for_ui
from ui.run_status_panel import record_workspace_run, render_run_status_panel
from ui.styles import apply_workspace_styles, section_heading
from ui.workspace_cards import (
    render_goal_card,
    render_mode_explainer,
    render_module_check_card,
    render_readiness_summary,
    render_target_profile_card,
)
from utils.assessment_goals import (
    GOAL_CUSTOM,
    GOAL_EVIDENCE_REVIEW,
    GOAL_LIVE_CAPTURE,
    GOAL_QUICK_SAFETY,
    get_modules_for_goal,
    goal_label,
    goal_to_run_mode_id,
    list_assessment_goals,
    suggested_goals_for_target,
)
from utils.engagement_guardrails import assess_target_scope
from utils.journey_planner import build_assessment_journey
from utils.module_compatibility import build_operation_plan
from utils.next_actions import suggest_next_actions
from utils.operating_context import (
    CLIENT_ENGAGEMENT,
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
from utils.pcap_storage import store_pcap_upload
from utils.pcap_analysis import is_supported_pcap_filename
from utils.file_metadata_storage import is_supported_metadata_filename, store_file_metadata_upload
from utils.target_detection import get_target_type, file_target_type
from utils.target_profile import build_target_profile
from utils.web_port_planner import (
    filter_modules_without_service_data,
    is_private_ipv4_target,
    parse_custom_web_port_list,
)

PREV_GOAL_KEY = "workspace_prev_goal"
RUN_GOAL_SESSION_KEY = "assessment_goal"
PCAP_UPLOAD_SESSION_KEY = "pcap_upload"
FILE_METADATA_UPLOADS_SESSION_KEY = "file_metadata_uploads"


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
                    "target_source": tls_opts.get("target_source", "default_assumption"),
                }
            elif module_id == "infra_http_security":
                http_opts = st.session_state.get("http_security_options", {})
                options = {
                    "request_method": http_opts.get("request_method", "GET"),
                    "port_override": http_opts.get("port_override"),
                    "scheme_override": http_opts.get("scheme_override"),
                    "requested_url": http_opts.get("requested_url"),
                    "target_source": http_opts.get("target_source", "default_assumption"),
                }
            elif module_id == "infra_web_stack_identifier":
                http_opts = st.session_state.get("http_security_options", {})
                options = {
                    "port_override": http_opts.get("port_override"),
                    "scheme_override": http_opts.get("scheme_override"),
                    "requested_url": http_opts.get("requested_url"),
                    "target_source": http_opts.get("target_source", "default_assumption"),
                }
            elif module_id == "infra_web_path_review":
                http_opts = st.session_state.get("http_security_options", {})
                options = {
                    "request_method": http_opts.get("request_method", "GET"),
                    "port_override": http_opts.get("port_override"),
                    "scheme_override": http_opts.get("scheme_override"),
                    "requested_url": http_opts.get("requested_url"),
                    "target_source": http_opts.get("target_source", "default_assumption"),
                }
            elif module_id == "infra_remote_access_review":
                latest = st.session_state.get("latest_run_results") or []
                nmap_ports: list[dict] = []
                for prior in latest:
                    if prior.get("module_id") == "infra_nmap" and prior.get("success"):
                        nmap_ports = (prior.get("parsed_data") or {}).get("parsed_ports") or []
                        break
                options = {"parsed_ports": nmap_ports, "latest_results": latest}
            elif module_id == "infra_ssh_review":
                latest = st.session_state.get("latest_run_results") or []
                nmap_ports: list[dict] = []
                for prior in latest:
                    if prior.get("module_id") == "infra_nmap" and prior.get("success"):
                        nmap_ports = (prior.get("parsed_data") or {}).get("parsed_ports") or []
                        break
                ssh_opts = st.session_state.get("ssh_review_options", {})
                options = {
                    "parsed_ports": nmap_ports,
                    "latest_results": latest,
                    "port_override": ssh_opts.get("port_override"),
                    "explicit_review": True,
                }
            elif module_id == "net_pcap_review":
                pcap_upload = st.session_state.get(PCAP_UPLOAD_SESSION_KEY) or {}
                options = {
                    "pcap_file_path": pcap_upload.get("storage_path"),
                    "pcap_filename": pcap_upload.get("filename") or target_value,
                    "pcap_sha256": pcap_upload.get("sha256"),
                    "pcap_size": pcap_upload.get("size_bytes"),
                    "case_id": current_case["id"],
                }
            elif module_id == "evidence_file_metadata":
                uploads = list(st.session_state.get(FILE_METADATA_UPLOADS_SESSION_KEY) or [])
                options = {
                    "uploaded_files": uploads,
                    "case_id": current_case["id"],
                    "target_type": file_target_type(uploads[0]["filename"]) if uploads else get_target_type(target_value),
                }
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


def _render_journey_details(journey: dict, target: str) -> None:
    """Full journey details inside an expander."""
    service_table = journey.get("service_table") or []
    if service_table:
        st.caption("Discovered services")
        st.dataframe(
            [
                {
                    "Port": row["port"],
                    "Service": row["detected_service"],
                    "Type": row["classification"],
                    "Check": row["recommended_check"],
                }
                for row in service_table[:12]
            ],
            width="stretch",
            hide_index=True,
        )

    for label, key, icon in (
        ("Blocked", "blocked", "⛔"),
        ("Optional", "optional", "○"),
        ("Not relevant", "not_relevant", "—"),
    ):
        rows = journey.get(key) or []
        if not rows:
            continue
        st.caption(f"{icon} {label} ({len(rows)})")
        for row in rows[:8]:
            extra = row.get("blocked_reason") or row.get("reason") or ""
            st.markdown(f"- {row['display_name']}" + (f" — {extra}" if extra else ""))


def render_assessment_workspace(current_case: dict, metrics: dict) -> None:
    del metrics  # workspace uses case-scoped inline metrics only
    apply_workspace_styles()
    _init_module_selection()
    from utils.autopilot_engine import SESSION_ASSESSMENT_MODE_KEY
    from utils.settings_manager import solo_operator_mode

    if solo_operator_mode():
        st.session_state.setdefault("personal_lab_confirmed", True)
        st.session_state.setdefault("authorisation_confirmed", True)
        st.session_state.setdefault("operating_context", PERSONAL_LAB)
        st.session_state.setdefault(SESSION_ASSESSMENT_MODE_KEY, "personal_lab_autopilot")
    st.session_state.setdefault("operation_target", "")
    st.session_state.setdefault(RUN_GOAL_SESSION_KEY, GOAL_QUICK_SAFETY)
    sync_run_mode_from_case(current_case, session_key="operation_run_mode")

    st.title("Assessment Workspace")
    st.caption(f"Case: **{current_case['name']}** (#{current_case['id']})")

    if st.session_state.get("startup_notice") and not st.session_state.get("startup_notice_dismissed"):
        st.info(st.session_state.startup_notice)
        if st.button("Dismiss notice", key="dismiss_startup_notice_ws"):
            st.session_state.startup_notice_dismissed = True
            st.rerun()

    if st.session_state.pop("workspace_focus_run_panel", False):
        st.session_state.workspace_scroll_to_readiness = True

    render_case_workflow_strip(current_case["id"])

    main_col, side_col = st.columns([3, 2], gap="large")

    with main_col:
        section_heading("Target")
        goal_ids = [goal_id for goal_id, _ in list_assessment_goals()]
        current_goal = st.session_state.get(RUN_GOAL_SESSION_KEY, GOAL_QUICK_SAFETY)
        if current_goal not in goal_ids:
            current_goal = GOAL_QUICK_SAFETY
        goal_id = st.selectbox(
            "Assessment goal",
            options=goal_ids,
            index=goal_ids.index(current_goal) if current_goal in goal_ids else 0,
            format_func=goal_label,
            key="assessment_goal_select",
            label_visibility="collapsed",
        )
        st.session_state[RUN_GOAL_SESSION_KEY] = goal_id
        render_goal_card(goal_id)

        if goal_id == GOAL_LIVE_CAPTURE:
            st.info(
                "Live capture runs on the dedicated **Packet Capture** page — "
                "no client engagement or scope setup required."
            )
            if st.button("Open Packet Capture", type="primary", width="stretch"):
                st.session_state.nav_page = "Packet Capture"
                st.rerun()

        pcap_upload = st.session_state.get(PCAP_UPLOAD_SESSION_KEY)
        file_uploads = list(st.session_state.get(FILE_METADATA_UPLOADS_SESSION_KEY) or [])
        if goal_id == GOAL_EVIDENCE_REVIEW:
            section_heading("Evidence files")
            uploaded_pcap = st.file_uploader(
                "Upload PCAP evidence",
                type=["pcap", "pcapng"],
                key="workspace_pcap_uploader",
                help="Local .pcap or .pcapng file only — no live capture in this version.",
            )
            if uploaded_pcap is not None:
                data = uploaded_pcap.getvalue()
                stored = store_pcap_upload(
                    current_case["id"],
                    uploaded_pcap.name,
                    data,
                )
                st.session_state[PCAP_UPLOAD_SESSION_KEY] = stored
                st.session_state.operation_target = stored["filename"]
                pcap_upload = stored
                st.caption(
                    f"**PCAP:** {stored['filename']} · {stored['size_bytes']:,} bytes · "
                    f"SHA-256 `{stored['sha256'][:16]}…`"
                )
            elif pcap_upload:
                st.caption(
                    f"**PCAP:** {pcap_upload['filename']} · SHA-256 `{pcap_upload['sha256'][:16]}…`"
                )

            uploaded_docs = st.file_uploader(
                "Upload document/image files for metadata review",
                type=["jpg", "jpeg", "png", "heic", "tif", "tiff", "pdf", "docx", "xlsx", "pptx", "txt", "csv"],
                accept_multiple_files=True,
                key="workspace_file_metadata_uploader",
                help="Local metadata review only — files are not sent externally.",
            )
            if uploaded_docs:
                stored_files: list[dict] = []
                for item in uploaded_docs:
                    if not is_supported_metadata_filename(item.name):
                        continue
                    stored_files.append(
                        store_file_metadata_upload(current_case["id"], item.name, item.getvalue())
                    )
                if stored_files:
                    st.session_state[FILE_METADATA_UPLOADS_SESSION_KEY] = stored_files
                    file_uploads = stored_files
                    if not st.session_state.operation_target:
                        st.session_state.operation_target = stored_files[0]["filename"]
                    names = ", ".join(row["filename"] for row in stored_files[:4])
                    suffix = f" (+{len(stored_files) - 4} more)" if len(stored_files) > 4 else ""
                    st.caption(f"**Metadata files:** {names}{suffix}")
            elif file_uploads:
                names = ", ".join(row["filename"] for row in file_uploads[:4])
                st.caption(f"**Metadata files:** {names}")

            target = st.session_state.operation_target or (pcap_upload or {}).get("filename") or (
                file_uploads[0]["filename"] if file_uploads else ""
            )
        else:
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
        suggested = suggested_goals_for_target(target_type, target)
        if goal_id != GOAL_EVIDENCE_REVIEW:
            render_target_profile_card(profile, suggested_goals=suggested)

        include_port_scan = False
        if goal_id == GOAL_QUICK_SAFETY and quick_check_supports_port_scan_option(target_type):
            include_port_scan = st.checkbox(
                "Include light port scan (active)",
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

        if goal_id == GOAL_CUSTOM:
            selected_ids = _selected_module_ids()
        else:
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
            if is_private_ipv4_target(target.strip()) and not profile.get("has_service_data"):
                selected_ids = filter_modules_without_service_data(selected_ids)
            apply_recommended_selection(selected_ids)

        personal_lab_confirmed = st.session_state.get("personal_lab_confirmed", False)
        authorisation_confirmed = st.session_state.get("authorisation_confirmed", False)
        run_mode_id = goal_to_run_mode_id(goal_id)

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
            plan = enrich_operation_plan_with_preflight(
                build_operation_plan(
                    case_name=current_case["name"],
                    case_id=current_case["id"],
                    target=target,
                    selected_module_ids=selected_ids,
                    authorisation_confirmed=(
                        (personal_lab_confirmed if operating_context == PERSONAL_LAB else authorisation_confirmed)
                        if _selection_requires_authorisation(selected_ids)
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

        auth_required = _selection_requires_authorisation(selected_ids)
        passive_count = sum(
            1
            for module_id in selected_ids
            if (module := get_module(module_id)) and module.mode == "passive"
        )
        active_count = len(selected_ids) - passive_count

        section_heading("Readiness")
        st.markdown('<div id="workspace-readiness"></div>', unsafe_allow_html=True)
        if st.session_state.pop("workspace_scroll_to_readiness", False):
            st.info("Module pre-selected from a workspace action — review readiness below and run when ready.")
            scroll_to_anchor("workspace-readiness")
        with st.container(border=True):
            operating_context = st.radio(
                "Operating context",
                options=context_choices,
                index=context_choices.index(operating_context),
                format_func=operating_context_label,
                key="workspace_operating_context",
                horizontal=True,
            )
            st.session_state.operating_context = operating_context
            render_mode_explainer(operating_context)

            if auth_required and operating_context == PERSONAL_LAB:
                personal_lab_confirmed = st.checkbox(
                    PERSONAL_LAB_CONFIRMATION_TEXT,
                    value=st.session_state.get("personal_lab_confirmed", False),
                    key="workspace_personal_lab_confirmed",
                )
                st.session_state.personal_lab_confirmed = personal_lab_confirmed
                from utils.personal_lab_readiness import classify_personal_lab_target

                target_class = classify_personal_lab_target(target.strip())
                if target_class.get("warning"):
                    st.warning(target_class["warning"])
            elif auth_required and operating_context == CLIENT_ENGAGEMENT:
                authorisation_confirmed = st.checkbox(
                    "I confirm authorisation under the linked client engagement.",
                    value=st.session_state.get("authorisation_confirmed", False),
                    key="workspace_client_auth_confirmed",
                )
                st.session_state.authorisation_confirmed = authorisation_confirmed

            if auth_required and operating_context == PERSONAL_LAB:
                plan_conn = get_db_conn()
                try:
                    plan = enrich_operation_plan_with_preflight(
                        build_operation_plan(
                            case_name=current_case["name"],
                            case_id=current_case["id"],
                            target=target,
                            selected_module_ids=selected_ids,
                            authorisation_confirmed=personal_lab_confirmed,
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

            preflight_status = render_compact_preflight(
                operating_context=operating_context,
                module_preflights=plan.get("module_preflights") or [],
                selected_module_ids=selected_ids,
                passive_count=passive_count,
                active_count=active_count,
            )

            launch_blocked = None
            if goal_id == GOAL_LIVE_CAPTURE:
                launch_blocked = "Use the Packet Capture page in the sidebar for live capture."
            elif goal_id == GOAL_EVIDENCE_REVIEW:
                needs_pcap = "net_pcap_review" in selected_ids
                needs_metadata = "evidence_file_metadata" in selected_ids
                has_pcap = bool(
                    pcap_upload and is_supported_pcap_filename((pcap_upload or {}).get("filename", ""))
                )
                has_metadata = bool(file_uploads)
                if needs_pcap and needs_metadata and not has_pcap and not has_metadata:
                    launch_blocked = "Upload a PCAP file and/or supported document/image files to review."
                elif needs_pcap and not has_pcap:
                    launch_blocked = "Upload a .pcap or .pcapng capture file to review."
                elif needs_metadata and not has_metadata:
                    launch_blocked = "Upload one or more supported document/image files for metadata review."
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
            elif plan.get("engagement_blocked_modules") and operating_context != PERSONAL_LAB:
                launch_blocked = "Resolve preflight items before running."
            elif preflight_status.get("has_active") and not preflight_status.get("ready"):
                launch_blocked = "Complete active check preflight before running."

            render_readiness_summary(
                selected_count=len(selected_ids),
                passive_count=passive_count,
                active_count=active_count,
                preflight_result=preflight_status.get("result", "ready"),
                operating_context=operating_context,
                one_line_warning=launch_blocked,
            )

            run_clicked = st.button(
                "Run selected checks",
                type="primary",
                disabled=launch_blocked is not None,
                width="stretch",
            )

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

        section_heading("Recommended checks")
        check_rows = (journey.get("recommended") or []) + (journey.get("active_needs_confirmation") or [])
        if not check_rows:
            st.caption("Select a goal and target to see recommended checks.")
        else:
            for row in check_rows[:8]:
                render_module_check_card(row, target=target)

        with st.expander("Journey details", expanded=False):
            _render_journey_details(journey, target)

        if is_private_ipv4_target(target.strip()):
            with st.expander("Local IP web port options", expanded=False):
                custom_ports_text = st.text_input(
                    "Custom web port list (max 10)",
                    value=st.session_state.get("custom_web_ports_text", ""),
                    placeholder="e.g. 8080, 8443",
                    key="custom_web_ports_input",
                )
                ports, port_error = parse_custom_web_port_list(custom_ports_text)
                if port_error and custom_ports_text.strip():
                    st.caption(port_error)
                if st.checkbox(
                    "Confirm ports for HTTP/TLS checking",
                    key="custom_web_ports_confirmed",
                ) and ports:
                    st.session_state.pending_custom_web_ports = ports

        if goal_id == GOAL_CUSTOM:
            _render_custom_module_picker(target)

        conservative_nmap = run_mode_id in {QUICK_CHECK, LOCAL_IP_CHECK}
        render_advanced_module_settings(
            selected_ids,
            target,
            conservative_nmap=conservative_nmap,
            goal_id=goal_id,
            run_mode_id=run_mode_id,
        )

        latest_results = st.session_state.get("latest_run_results") or []
        latest_target = st.session_state.get("latest_run_target", target)
        if latest_results and latest_target.strip():
            render_workspace_results(
                latest_results,
                target=latest_target,
                case_id=current_case["id"],
            )

    with side_col:
        engagement = get_engagement_for_case(current_case["id"]) if current_case else None
        emergency_stop_active = bool(engagement and engagement.get("emergency_stop_active"))

        conn = get_db_conn()
        try:
            render_case_memory_panel(current_case["id"], conn=conn)
            render_autopilot_panel(
                case_id=current_case["id"],
                target=target,
                goal_id=goal_id,
                latest_results=st.session_state.get("latest_run_results") or [],
                operating_context=st.session_state.get("operating_context", PASSIVE_RESEARCH),
                personal_lab_confirmed=bool(st.session_state.get("personal_lab_confirmed")),
                authorisation_confirmed=bool(st.session_state.get("authorisation_confirmed")),
                emergency_stop_active=emergency_stop_active,
                conn=conn,
            )
        finally:
            conn.close()

        section_heading("Next steps")
        profile_with_scope = dict(profile)
        if target.strip() and auth_required and st.session_state.get("operating_context") == PERSONAL_LAB:
            profile_with_scope["needs_lab_scope"] = any(
                row.get("needs_lab_scope_add") and not row.get("can_auto_scope")
                for row in (plan.get("module_preflights") or [])
            )
            profile_with_scope["personal_lab_confirmed"] = st.session_state.get(
                "personal_lab_confirmed", False
            )

        conn = get_db_conn()
        try:
            actions = suggest_next_actions(
                case_id=current_case["id"],
                target=target,
                goal_id=goal_id,
                target_profile=profile_with_scope,
                latest_results=st.session_state.get("latest_run_results") or [],
                operating_context=st.session_state.get("operating_context", PASSIVE_RESEARCH),
                personal_lab_confirmed=bool(st.session_state.get("personal_lab_confirmed")),
                authorisation_confirmed=bool(st.session_state.get("authorisation_confirmed")),
                conn=conn,
            )
        finally:
            conn.close()
        render_action_cards(actions, case_id=current_case["id"], limit=3)

        with st.expander("Recent runs", expanded=False):
            render_run_status_panel()

        with st.expander("Analyst notes", expanded=False):
            st.text_area(
                "Workspace notes",
                value=st.session_state.get("workspace_analyst_notes", ""),
                key="workspace_analyst_notes",
                height=100,
                label_visibility="collapsed",
                placeholder="Optional notes for this session…",
            )

        if target.strip() and operating_context == CLIENT_ENGAGEMENT:
            scope_preview = assess_target_scope(target.strip(), case_id=current_case["id"])
            st.caption(
                f"Scope: {(scope_preview.get('scope_status') or 'unknown').replace('_', ' ')}"
            )

"""Run Operation workflow page for Project Overwatch."""

from __future__ import annotations

import streamlit as st

from database.db_setup import create_or_get_entity, get_db_conn, infer_entity_type
from modules.executor import execute_module
from modules.module_registry import get_module, is_executable
from ui.constants import IMPLEMENTED_MODULE_IDS, MODULE_CARD_TITLES
from ui.metrics import render_compact_metrics
from ui.module_runtime import module_disable_reason, module_enabled_for_ui, module_runtime_error
from ui.results import render_latest_results
from utils.module_compatibility import (
    build_operation_plan,
    get_compatible_modules,
    module_detailed_help,
    module_short_help,
)
from utils.nmap_options import PROFILE_QUICK_CHECK, SCRIPT_VULN
from utils.nmap_ui import render_nmap_options
from utils.run_modes import (
    CUSTOM,
    PREV_PORT_SCAN_KEY,
    QUICK_CHECK,
    QUICK_CHECK_PORT_SCAN_KEY,
    apply_recommended_selection,
    get_recommendation_reason,
    get_run_mode_description,
    get_run_mode_label,
    list_run_modes,
    mode_uses_conservative_nmap,
    persist_run_mode_for_case,
    quick_check_supports_port_scan_option,
    resolve_recommended_modules_for_mode,
    should_auto_apply_selection,
    sync_run_mode_from_case,
)
from utils.settings_manager import has_api_key
from utils.target_detection import get_target_type, normalize_target_value, target_type_label

RUN_MODE_SESSION_KEY = "operation_run_mode"
PREV_RUN_MODE_KEY = "operation_prev_run_mode"
PREV_TARGET_KEY = "operation_prev_target"


def _init_module_selection() -> None:
    for module_id in IMPLEMENTED_MODULE_IDS:
        key = f"module_sel_{module_id}"
        st.session_state.setdefault(key, False)


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


def _render_module_card(module, target: str, *, selectable: bool) -> None:
    module_id = module.module_id
    card_title = MODULE_CARD_TITLES.get(module_id, module.display_name)
    enabled = module_enabled_for_ui(module, target)
    disable_reason = module_disable_reason(module, target)
    mode_label = module.mode.title()
    accepted = ", ".join(module.accepted_target_types) if module.accepted_target_types else "—"

    with st.container(border=True):
        st.markdown(f"#### {card_title}")
        st.caption(
            f"{mode_label} · {module.risk_level.title()} risk · "
            f"Accepts: {accepted}"
        )
        st.write(module_short_help(module))
        if module.output_summary:
            st.markdown(f"**Expected outputs:** {module.output_summary}")

        if selectable and enabled:
            st.checkbox(
                "Select module",
                key=f"module_sel_{module_id}",
            )
        else:
            st.checkbox(
                "Select module",
                value=False,
                disabled=True,
                key=f"module_sel_disabled_{module_id}",
            )
            if disable_reason:
                st.warning(disable_reason)
            elif module_runtime_error(module_id):
                st.error(module_runtime_error(module_id))


def _render_module_lab() -> None:
    with st.expander("Module Lab / Advanced", expanded=False):
        st.caption(
            "Full metadata for implemented modules. Selection and execution still use the "
            "module cards and operation plan above — this panel is reference only."
        )
        for module_id in IMPLEMENTED_MODULE_IDS:
            module = get_module(module_id)
            if module is None:
                continue
            card_title = MODULE_CARD_TITLES.get(module_id, module.display_name)
            st.markdown(f"**{card_title}** (`{module_id}`)")
            st.caption(
                f"Status: {module.status} · Mode: {module.mode} · "
                f"Risk: {module.risk_level} · Implemented: {module.implemented}"
            )
            if module.accepted_target_types:
                st.caption(
                    "Accepted target types: "
                    + ", ".join(target_type_label(value) for value in module.accepted_target_types)
                )
            st.write(module_detailed_help(module))
            if module.output_summary:
                st.markdown(f"**Expected outputs:** {module.output_summary}")
            if module.caution_notes:
                st.markdown(f"**Caution:** {module.caution_notes}")
            st.divider()


def _sync_run_mode_selection(
    run_mode: str,
    target: str,
    target_type: str,
    *,
    include_port_scan: bool,
) -> None:
    prev_mode = st.session_state.get(PREV_RUN_MODE_KEY)
    prev_target = st.session_state.get(PREV_TARGET_KEY)
    prev_port_scan = st.session_state.get(PREV_PORT_SCAN_KEY)
    if should_auto_apply_selection(
        run_mode,
        prev_mode,
        target,
        prev_target,
        include_port_scan=include_port_scan,
        previous_include_port_scan=prev_port_scan,
    ):
        recommended = resolve_recommended_modules_for_mode(
            run_mode,
            target_type,
            quick_check_include_port_scan=include_port_scan,
            target=target,
        )
        compatible_ids = {
            module.module_id
            for module in get_compatible_modules(target)
        }
        filtered = [module_id for module_id in recommended if module_id in compatible_ids]
        apply_recommended_selection(filtered)
    st.session_state[PREV_RUN_MODE_KEY] = run_mode
    st.session_state[PREV_TARGET_KEY] = target.strip()
    st.session_state[PREV_PORT_SCAN_KEY] = include_port_scan


def render_run_operation_page(current_case: dict, metrics: dict) -> None:
    _init_module_selection()
    if "operation_target" not in st.session_state:
        st.session_state.operation_target = ""
    st.session_state.setdefault(RUN_MODE_SESSION_KEY, QUICK_CHECK)
    sync_run_mode_from_case(current_case, session_key=RUN_MODE_SESSION_KEY)

    st.title("Run Operation")
    st.caption(
        f"Case: **{current_case['name']}** (#{current_case['id']}) · "
        "Choose a run mode, confirm module recommendations, review the plan, then run."
    )
    render_compact_metrics(metrics, minimal=True)
    st.divider()

    if st.session_state.get("startup_notice") and not st.session_state.get("startup_notice_dismissed"):
        st.info(st.session_state.startup_notice)
        if st.button("Dismiss notice", key="dismiss_startup_notice"):
            st.session_state.startup_notice_dismissed = True
            st.rerun()

    # Step 1 — Target
    st.markdown("### Step 1 — Target")
    target = st.text_input(
        "Investigation target",
        value=st.session_state.operation_target,
        placeholder="e.g. 192.168.1.1, example.com, or https://example.com/path",
        help="IPv4 address, domain, URL, email, or username-like value.",
        key="run_operation_target_input",
    )
    st.session_state.operation_target = target

    target_type = get_target_type(target or "")
    normalized = normalize_target_value(target.strip(), target_type) if target.strip() else ""

    if target.strip():
        st.markdown(f"**Detected type:** {target_type_label(target_type)}")
        if normalized and normalized != target.strip():
            st.markdown(f"**Normalised host:** `{normalized}`")
        elif normalized:
            st.markdown(f"**Normalised host:** `{normalized}`")

    st.divider()

    # Run mode selector
    mode_options = list_run_modes()
    mode_ids = [mode_id for mode_id, _ in mode_options]
    current_mode = st.session_state.get(RUN_MODE_SESSION_KEY, QUICK_CHECK)
    mode_index = mode_ids.index(current_mode) if current_mode in mode_ids else 0

    run_mode = st.radio(
        "What do you want to do?",
        options=mode_ids,
        index=mode_index,
        format_func=get_run_mode_label,
        key="run_mode_radio",
        help="Guided run modes recommend sensible module bundles for your target.",
    )
    st.session_state[RUN_MODE_SESSION_KEY] = run_mode
    st.caption(get_run_mode_description(run_mode))

    include_port_scan = False
    if run_mode == QUICK_CHECK and quick_check_supports_port_scan_option(target_type):
        include_port_scan = st.checkbox(
            "Include light port scan (requires authorisation)",
            value=st.session_state.get(QUICK_CHECK_PORT_SCAN_KEY, False),
            key=QUICK_CHECK_PORT_SCAN_KEY,
            help=(
                "Adds Network Service Check with a conservative profile to domain/URL Quick Check. "
                "Use only with permission."
            ),
        )

    if current_case.get("default_run_mode") != run_mode:
        persist_key = (current_case["id"], run_mode)
        if st.session_state.get("persisted_run_mode") != persist_key:
            persist_run_mode_for_case(current_case["id"], run_mode)
            st.session_state["persisted_run_mode"] = persist_key
            current_case["default_run_mode"] = run_mode

    recommendation_reason = get_recommendation_reason(
        run_mode,
        target_type,
        quick_check_include_port_scan=include_port_scan,
        target=target,
    )
    if target.strip():
        if run_mode != CUSTOM:
            st.info(recommendation_reason)
        _sync_run_mode_selection(
            run_mode,
            target,
            target_type,
            include_port_scan=include_port_scan,
        )

    st.divider()

    # Step 2 — Module Selection
    st.markdown("### Step 2 — Module Selection")
    compatible_modules: list = []
    incompatible_modules: list = []
    for module_id in IMPLEMENTED_MODULE_IDS:
        module = get_module(module_id)
        if module is None:
            continue
        if module_enabled_for_ui(module, target):
            compatible_modules.append(module)
        else:
            incompatible_modules.append(module)

    recommended_ids = set(
        resolve_recommended_modules_for_mode(
            run_mode,
            target_type,
            quick_check_include_port_scan=include_port_scan,
            target=target,
        )
    )
    recommended_compatible = [
        module for module in compatible_modules if module.module_id in recommended_ids
    ]
    available_not_recommended = [
        module for module in compatible_modules if module.module_id not in recommended_ids
    ]

    if run_mode == CUSTOM:
        if compatible_modules:
            st.markdown("**Compatible modules**")
            for module in compatible_modules:
                _render_module_card(module, target, selectable=True)
    else:
        if recommended_compatible:
            st.markdown("**Recommended for this target**")
            for module in recommended_compatible:
                _render_module_card(module, target, selectable=True)
        elif target.strip() and run_mode in {QUICK_CHECK} and not recommended_ids:
            st.warning(recommendation_reason)

        if available_not_recommended:
            with st.expander(
                "Available but not recommended by this mode",
                expanded=False,
            ):
                for module in available_not_recommended:
                    _render_module_card(module, target, selectable=True)

    if incompatible_modules:
        st.markdown("**Not available for this target**")
        for module in incompatible_modules:
            _render_module_card(module, target, selectable=False)

    st.caption("Planned modules are on the **Roadmap** page — not shown in the run workflow.")
    _render_module_lab()

    selected_ids = _selected_module_ids()
    st.divider()

    # Step 3 — Module Configuration
    st.markdown("### Step 3 — Module Configuration")
    if not selected_ids:
        st.info("Select one or more compatible modules above to configure them.")
    else:
        nmap_options: dict = {}
        conservative_nmap = mode_uses_conservative_nmap(run_mode) or (
            run_mode == QUICK_CHECK and "infra_nmap" in selected_ids
        )
        for module_id in selected_ids:
            module = get_module(module_id)
            if module is None:
                continue
            card_title = MODULE_CARD_TITLES.get(module_id, module.display_name)
            expanded = module_id != "infra_nmap" or not conservative_nmap
            with st.expander(f"{card_title} configuration", expanded=expanded):
                if module_id == "infra_nmap":
                    st.caption("Active module — authorisation required before run.")
                    if conservative_nmap:
                        st.caption(
                            f"Using conservative default profile ({PROFILE_QUICK_CHECK}). "
                            "Expand scan settings below to change profile."
                        )
                    nmap_options = render_nmap_options(
                        True,
                        initial_profile=PROFILE_QUICK_CHECK if conservative_nmap else None,
                        collapse_settings=conservative_nmap,
                    )
                    if nmap_options.get("script_category") == SCRIPT_VULN:
                        st.warning(
                            "**High-risk option:** `--script=vuln` runs intrusive checks. "
                            "Use only with explicit written permission."
                        )
                elif module_id == "infra_domain_intel":
                    st.caption("Passive module — no authorisation required.")
                    st.write(
                        "Collects public DNS, HTTP/TLS, security headers, and Wayback data. "
                        "No additional configuration is required."
                    )
                elif module_id == "infra_cert_subdomain":
                    st.caption("Passive module — no authorisation required.")
                    st.write(
                        "Queries public certificate transparency data for related hostnames. "
                        "Certificate-derived names are leads for review, not confirmed live hosts."
                    )
                elif module_id == "infra_website_metadata":
                    st.caption("Passive module — no authorisation required.")
                    st.write(
                        "Fetches the public homepage and reviews title, meta tags, headers, "
                        "link/form counts, robots.txt, and sitemap hints. Does not submit forms."
                    )
                elif module_id == "infra_whois_rdap":
                    st.caption("Passive module — no authorisation required.")
                    st.write(
                        "Collects public registration and allocation metadata using RDAP for domains, "
                        "URLs (host extracted), and public IPv4 addresses. Private/local IPs return an "
                        "informational result without public lookup."
                    )
                elif module_id == "intel_virustotal":
                    st.caption("Passive module — no authorisation required.")
                    st.write(
                        "Requires VIRUSTOTAL_API_KEY in .env. The key is masked in Settings and must never "
                        "be stored in observations, findings, evidence, reports or logs."
                    )
                    st.write(
                        "Queries VirusTotal for passive reputation enrichment. Results are third-party "
                        "reputation signals and should be treated as reported intelligence, not confirmed fact."
                    )
                    if not has_api_key("VIRUSTOTAL_API_KEY"):
                        st.warning(
                            "VirusTotal is unavailable — VIRUSTOTAL_API_KEY is not configured in your local "
                            ".env file. This module will be blocked until a key is set."
                        )
                elif module_id == "intel_abuseipdb":
                    st.caption("Passive module — no authorisation required.")
                    st.write(
                        "Requires ABUSEIPDB_API_KEY in .env. The key is masked in Settings and must never "
                        "be stored in observations, findings, evidence, reports or logs."
                    )
                    st.write(
                        "Queries AbuseIPDB for passive abuse-confidence enrichment on public IPv4 addresses only. "
                        "Lookup-only — does not submit reports. Results are third-party reputation signals and "
                        "should be treated as reported intelligence, not confirmed fact."
                    )
                    if not has_api_key("ABUSEIPDB_API_KEY"):
                        st.warning(
                            "AbuseIPDB is unavailable — ABUSEIPDB_API_KEY is not configured in your local "
                            ".env file. This module will be blocked until a key is set."
                        )
                elif module_id == "intel_greynoise":
                    st.caption("Passive module — no authorisation required.")
                    st.write(
                        "GREYNOISE_API_KEY in .env is optional but recommended. The key is masked in Settings "
                        "and must never be stored in observations, findings, evidence, reports or logs."
                    )
                    st.write(
                        "Queries GreyNoise v3 Community API for internet-noise and RIOT context on public IPv4 "
                        "addresses only. Results are third-party signals and should be treated as reported "
                        "intelligence, not confirmed fact."
                    )
                    if not has_api_key("GREYNOISE_API_KEY"):
                        st.info(
                            "No GreyNoise API key configured — limited unauthenticated Community lookups may "
                            "still run. Add GREYNOISE_API_KEY to .env for authenticated lookups."
                        )
        st.session_state.nmap_options = nmap_options

    st.divider()

    # Step 4 — Operation Plan
    st.markdown("### Step 4 — Operation Plan")
    auth_required = _selection_requires_authorisation(selected_ids)
    authorisation_confirmed = st.session_state.get("authorisation_confirmed", False)

    plan = build_operation_plan(
        case_name=current_case["name"],
        case_id=current_case["id"],
        target=target,
        selected_module_ids=selected_ids,
        authorisation_confirmed=authorisation_confirmed if auth_required else True,
        run_mode_id=run_mode,
        run_mode_label=get_run_mode_label(run_mode),
        recommendation_reason=recommendation_reason,
    )

    with st.container(border=True):
        if not plan["target"]:
            st.info("Enter a target to build an operation plan.")
        elif not plan["selected_modules"]:
            st.info("Select compatible modules to build an operation plan.")
        else:
            st.markdown(f"**Case:** {plan['case_name']} (#{plan['case_id']})")
            st.markdown(f"**Run mode:** {plan.get('run_mode_label') or get_run_mode_label(run_mode)}")
            if plan.get("recommendation_reason"):
                st.markdown(f"**Why these modules:** {plan['recommendation_reason']}")
            st.markdown(f"**Original target:** `{plan['target']}`")
            if plan.get("normalized_target"):
                st.markdown(f"**Normalised host:** `{plan['normalized_target']}`")
            st.markdown(f"**Detected type:** {plan['target_type_label']}")
            st.markdown("**Selected modules:** " + ", ".join(plan["selected_modules"]))
            if plan["active_modules"]:
                st.markdown("**Active modules:** " + ", ".join(plan["active_modules"]))
            if plan["passive_modules"]:
                st.markdown("**Passive modules:** " + ", ".join(plan["passive_modules"]))
            st.markdown(
                "**Authorisation required:** "
                + ("Yes" if plan["authorisation_required"] else "No")
            )
            if plan["expected_outputs"]:
                st.markdown("**Expected outputs:**")
                for line in plan["expected_outputs"]:
                    st.markdown(f"- {line}")
            if plan["incompatible_modules"]:
                st.warning("Some selected modules are incompatible with this target:")
                for line in plan["incompatible_modules"]:
                    st.markdown(f"- {line}")

    st.divider()

    # Authorisation and launch
    if auth_required:
        authorisation_confirmed = st.checkbox(
            "I confirm I am authorised to run active checks against this target.",
            value=st.session_state.get("authorisation_confirmed", False),
            key="authorisation_confirmed_checkbox",
        )
        st.session_state.authorisation_confirmed = authorisation_confirmed
        st.caption(
            "Required for active modules such as Nmap. "
            "Use only on systems you own, lab environments, or targets with written permission."
        )
    elif selected_ids:
        st.caption("No authorisation checkbox is required — all selected modules are passive.")
        authorisation_confirmed = False

    launch_blocked_reason = None
    if not target.strip():
        launch_blocked_reason = "Enter a target before running modules."
    elif not selected_ids:
        launch_blocked_reason = "Select at least one compatible module."
    elif plan["incompatible_modules"]:
        launch_blocked_reason = "Remove incompatible modules from the selection."
    elif auth_required and not authorisation_confirmed:
        launch_blocked_reason = "Confirm authorisation for active modules before running."

    execute_btn = st.button(
        "Run selected modules",
        type="primary",
        disabled=launch_blocked_reason is not None,
        width="stretch",
    )
    if launch_blocked_reason:
        st.caption(launch_blocked_reason)

    if execute_btn and not launch_blocked_reason:
        nmap_options = st.session_state.get("nmap_options", {})
        run_mode_label = get_run_mode_label(run_mode)
        persist_run_mode_for_case(current_case["id"], run_mode)
        run_results: list[dict] = []
        with st.status("Running selected modules...", expanded=True) as status:
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
                    options = {}
                    if module_id == "infra_nmap":
                        options = {"nmap_options": nmap_options}
                    result = execute_module(
                        module_id,
                        target_value,
                        options=options,
                        db_context=conn,
                        authorisation_confirmed=authorisation_confirmed,
                        case_id=current_case["id"],
                        entity_id=entity["id"],
                        run_mode_id=run_mode,
                        run_mode_label=run_mode_label,
                    )
                    run_results.append(result)
            finally:
                conn.close()
            status.update(label="Module run complete", state="complete")

        st.session_state.latest_run_results = run_results
        st.session_state.latest_run_target = target_value
        st.rerun()

    latest_results = st.session_state.get("latest_run_results") or []
    latest_target = st.session_state.get("latest_run_target", target)
    if latest_results:
        render_latest_results(latest_results, target=latest_target)

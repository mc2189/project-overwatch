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
from utils.module_compatibility import build_operation_plan, get_compatible_modules, module_short_help
from utils.nmap_options import SCRIPT_VULN
from utils.nmap_ui import render_nmap_options
from utils.target_detection import get_target_type, normalize_target_value, target_type_label


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


def _render_module_card(module, target: str, *, compatible_section: bool) -> None:
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

        if compatible_section and enabled:
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


def render_run_operation_page(current_case: dict, metrics: dict) -> None:
    _init_module_selection()
    if "operation_target" not in st.session_state:
        st.session_state.operation_target = ""

    st.title("Run Operation")
    st.caption(
        f"Case: **{current_case['name']}** (#{current_case['id']}) · "
        "Configure a target, choose compatible modules, review the plan, then run."
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

        compatible = get_compatible_modules(target)
        if compatible:
            names = ", ".join(MODULE_CARD_TITLES.get(m.module_id, m.display_name) for m in compatible)
            st.success(f"Compatible modules for this target: {names}")
        else:
            st.warning("No implemented modules are compatible with this target type.")

    st.divider()

    # Step 2 — Module Selection
    st.markdown("### Step 2 — Module Selection")
    compatible_modules = []
    incompatible_modules = []
    for module_id in IMPLEMENTED_MODULE_IDS:
        module = get_module(module_id)
        if module is None:
            continue
        if module_enabled_for_ui(module, target):
            compatible_modules.append(module)
        else:
            incompatible_modules.append(module)

    if compatible_modules:
        st.markdown("**Compatible modules**")
        for module in compatible_modules:
            _render_module_card(module, target, compatible_section=True)

    if incompatible_modules:
        st.markdown("**Incompatible or unavailable modules**")
        for module in incompatible_modules:
            _render_module_card(module, target, compatible_section=False)

    selected_ids = _selected_module_ids()
    st.divider()

    # Step 3 — Module Configuration
    st.markdown("### Step 3 — Module Configuration")
    if not selected_ids:
        st.info("Select one or more compatible modules above to configure them.")
    else:
        nmap_options: dict = {}
        for module_id in selected_ids:
            module = get_module(module_id)
            if module is None:
                continue
            card_title = MODULE_CARD_TITLES.get(module_id, module.display_name)
            with st.expander(f"{card_title} configuration", expanded=True):
                if module_id == "infra_nmap":
                    st.caption("Active module — authorisation required before run.")
                    nmap_options = render_nmap_options(True)
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
    )

    with st.container(border=True):
        if not plan["target"]:
            st.info("Enter a target to build an operation plan.")
        elif not plan["selected_modules"]:
            st.info("Select compatible modules to build an operation plan.")
        else:
            st.markdown(f"**Case:** {plan['case_name']} (#{plan['case_id']})")
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

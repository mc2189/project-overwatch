"""Compact per-module advanced configuration expanders."""

from __future__ import annotations

import streamlit as st

from modules.module_registry import get_module
from ui.constants import MODULE_CARD_TITLES
from utils.module_compatibility import module_detailed_help, module_short_help
from utils.nmap_options import PROFILE_QUICK_CHECK, SCRIPT_VULN
from utils.nmap_ui import render_nmap_options
from utils.target_detection import get_target_type, normalize_target_value


def render_module_info_expanders(module_id: str, target: str) -> None:
    module = get_module(module_id)
    if module is None:
        return
    title = MODULE_CARD_TITLES.get(module_id, module.display_name)
    with st.expander(f"{title} — why / what / safety", expanded=False):
        st.caption(module_short_help(module))
        with st.expander("Why this check?", expanded=False):
            st.write(module_detailed_help(module))
        with st.expander("What does this collect?", expanded=False):
            st.write(module.output_summary or "Module-specific observations, entities, and findings.")
        with st.expander("Safety / authorisation notes", expanded=False):
            st.write(module.caution_notes or "Follow operating context and scope rules before running.")


def render_advanced_module_settings(
    module_ids: list[str],
    target: str,
    *,
    conservative_nmap: bool = False,
    goal_id: str | None = None,
    run_mode_id: str | None = None,
) -> dict[str, dict]:
    """Render collapsed advanced settings for selected modules."""
    nmap_options: dict = st.session_state.get("nmap_options", {})
    tls_review_options: dict = st.session_state.get("tls_review_options", {})
    http_security_options: dict = st.session_state.get("http_security_options", {})

    active_selected = [
        module_id
        for module_id in module_ids
        if module_id in {"infra_nmap", "infra_tls_review", "infra_http_security", "infra_web_stack_identifier", "infra_web_path_review"}
    ]
    if not active_selected:
        return {
            "nmap_options": nmap_options,
            "tls_review_options": tls_review_options,
            "http_security_options": http_security_options,
        }

    with st.expander("Advanced settings (active modules)", expanded=False):
        for module_id in active_selected:
            title = MODULE_CARD_TITLES.get(module_id, module_id)
            if module_id == "infra_nmap":
                nmap_options = render_nmap_options(
                    True,
                    initial_profile=PROFILE_QUICK_CHECK if conservative_nmap else None,
                    conservative_nmap=conservative_nmap,
                    goal_id=goal_id,
                    run_mode_id=run_mode_id,
                    collapse_settings=conservative_nmap,
                )
                if nmap_options.get("script_category") == SCRIPT_VULN:
                    st.warning("High-risk: --script=vuln requires explicit written permission.")
            elif module_id == "infra_tls_review":
                target_type = get_target_type(target)
                derived_port = 443
                if target_type == "url":
                    from urllib.parse import urlparse

                    parsed = urlparse(target if "://" in target else f"https://{target}")
                    if parsed.port:
                        derived_port = parsed.port
                port_override = st.number_input(
                    f"{title} port",
                    min_value=1,
                    max_value=65535,
                    value=int(st.session_state.get("tls_review_port_override", derived_port)),
                    key="tls_review_port_override",
                )
                tls_review_options = {
                    "port_override": int(port_override),
                    "protocol_probes": True,
                    "target_source": st.session_state.get("tls_target_source", "default_assumption"),
                }
                note_key = st.session_state.get("tls_target_source", "default_assumption")
                from utils.web_port_planner import http_target_note

                st.caption(http_target_note(target_source=note_key))
            elif module_id == "infra_http_security":
                request_method = st.selectbox(
                    f"{title} request method",
                    options=["GET", "HEAD"],
                    index=0,
                    key="http_security_request_method",
                )
                http_review_options = {
                    "request_method": request_method,
                    "target_source": st.session_state.get("http_target_source", "default_assumption"),
                }
                pending_url = st.session_state.get("http_requested_url")
                if pending_url:
                    http_review_options["requested_url"] = pending_url
                    http_review_options["target_source"] = "manual_port"
                from utils.web_port_planner import http_target_note

                st.caption(
                    http_target_note(
                        target_source=http_review_options.get("target_source", "default_assumption")
                    )
                )
                http_security_options = http_review_options

    st.session_state.nmap_options = nmap_options
    st.session_state.tls_review_options = tls_review_options
    st.session_state.http_security_options = http_security_options
    return {
        "nmap_options": nmap_options,
        "tls_review_options": tls_review_options,
        "http_security_options": http_security_options,
    }

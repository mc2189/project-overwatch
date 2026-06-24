"""Streamlit UI helpers for guided Nmap scan configuration."""

from __future__ import annotations

from typing import Any

import streamlit as st

from utils.nmap_options import (
    OPTION_HELP,
    PROFILE_CUSTOM,
    SCRIPT_DEFAULT,
    SCRIPT_DISCOVERY,
    SCRIPT_NONE,
    SCRIPT_SAFE,
    SCRIPT_VULN,
    TIMING_AGGRESSIVE,
    TIMING_NORMAL,
    TIMING_POLITE,
    normalize_options,
    validation_messages,
)
from utils.nmap_profiles import (
    PROFILE_CUSTOM_PORTS,
    PROFILE_ORDER,
    default_profile_for_context,
    get_profile_definition,
    parse_custom_port_list,
    profile_display_name,
    resolve_profile_id,
)
from utils.privileges import has_root_privileges

SCRIPT_CATEGORIES = [
    ("None", SCRIPT_NONE),
    ("Safe", SCRIPT_SAFE),
    ("Default", SCRIPT_DEFAULT),
    ("Discovery", SCRIPT_DISCOVERY),
    ("Vuln", SCRIPT_VULN),
]


def render_privilege_status() -> bool:
    """Show whether the Streamlit session has elevated privileges."""
    root_available = has_root_privileges()
    if root_available:
        st.info("Running with elevated privileges")
    else:
        st.caption("Standard user session · elevated privileges not available")
    return root_available


def render_nmap_options(
    enabled: bool,
    *,
    initial_profile: str | None = None,
    initial_profile_id: str | None = None,
    goal_id: str | None = None,
    run_mode_id: str | None = None,
    conservative_nmap: bool = False,
    collapse_settings: bool = False,
) -> dict[str, Any]:
    """Render Nmap Profile Runner UI and return the selected option set."""
    root_available = has_root_privileges()
    default_id = initial_profile_id or resolve_profile_id(initial_profile or "")
    if not initial_profile_id and not initial_profile:
        default_id = default_profile_for_context(
            goal_id=goal_id,
            run_mode_id=run_mode_id,
            conservative=conservative_nmap,
        )

    if default_id not in PROFILE_ORDER:
        default_id = PROFILE_ORDER[0]

    def _render_profile_ui() -> dict[str, Any]:
        display_options = [profile_display_name(pid) for pid in PROFILE_ORDER]
        default_index = PROFILE_ORDER.index(default_id)
        selected_label = st.selectbox(
            "Network Service Check profile",
            options=display_options,
            index=default_index,
            disabled=not enabled,
            help="Choose a guided Nmap profile. Custom Port List accepts up to 50 comma-separated ports.",
            key="nmap_profile_select",
        )
        profile_id = PROFILE_ORDER[display_options.index(selected_label)]
        definition = get_profile_definition(profile_id)

        st.caption(definition["description"])
        meta_bits = [
            f"Noise: {definition['estimated_noise']}",
            f"Testing: {definition['testing_level'].replace('_', ' ')}",
        ]
        if definition.get("requires_elevation"):
            meta_bits.append("May use elevation for OS detail")
        st.caption(" · ".join(meta_bits))
        st.caption(definition["active_warning"])

        if not root_available and definition.get("requires_elevation"):
            st.caption(
                "OS detection needs elevated privileges and will be skipped in this session if selected."
            )

        custom_ports = ""
        if profile_id == PROFILE_CUSTOM_PORTS:
            custom_ports = st.text_input(
                "Custom ports (comma-separated, max 50)",
                value=st.session_state.get("nmap_custom_ports_text", ""),
                disabled=not enabled,
                placeholder="22,80,443,8080",
                key="nmap_custom_ports_input",
            )
            validated, errors = parse_custom_port_list(custom_ports)
            if errors and custom_ports.strip():
                for err in errors:
                    st.caption(err)
            elif validated:
                st.caption(f"Ports to scan: {validated}")

        from utils.nmap_profiles import options_for_profile
        from utils.nmap_options import build_nmap_flags

        options = options_for_profile(profile_id, custom_ports=custom_ports)
        if profile_id == PROFILE_CUSTOM_PORTS:
            options["profile"] = PROFILE_CUSTOM

        with st.expander("Advanced Nmap flags", expanded=False):
            if profile_id == PROFILE_CUSTOM_PORTS:
                options = _render_custom_options(options, enabled, root_available)
            else:
                preview = normalize_options(options)
                st.caption("Command flags: " + " ".join(build_nmap_flags(preview)))
                if preview.get("os_detection_skipped"):
                    st.caption("OS detection needs elevated privileges and was skipped.")

        normalized = normalize_options(options)
        for message in validation_messages(options):
            st.caption(message)
        return normalized

    if collapse_settings:
        with st.expander("Network Service Check settings", expanded=False):
            st.caption(f"Default profile: {profile_display_name(default_id)}")
            return _render_profile_ui()
    return _render_profile_ui()


def _render_custom_options(
    options: dict[str, Any],
    enabled: bool,
    root_available: bool,
) -> dict[str, Any]:
    host_discovery_only = st.checkbox(
        "Host discovery only",
        value=options.get("host_discovery_only", False),
        disabled=not enabled,
        help=OPTION_HELP["host_discovery_only"],
    )
    options["host_discovery_only"] = host_discovery_only

    port_disabled = host_discovery_only or not enabled
    options["fast_scan"] = st.checkbox(
        "Fast scan (-F)",
        value=options.get("fast_scan", False),
        disabled=port_disabled or bool(options.get("custom_ports")) or bool(options.get("top_ports")),
        help=OPTION_HELP["fast_scan"],
    )

    use_top_ports = st.checkbox(
        "Top ports",
        value=bool(options.get("top_ports")),
        disabled=port_disabled or options.get("fast_scan") or bool(str(options.get("custom_ports") or "").strip()),
        help=OPTION_HELP["top_ports"],
    )
    if use_top_ports:
        options["top_ports"] = st.number_input(
            "Number of top ports",
            min_value=10,
            max_value=1000,
            value=int(options.get("top_ports") or 100),
            step=10,
            disabled=port_disabled,
        )
    else:
        options["top_ports"] = None

    custom_ports = st.text_input(
        "Legacy custom ports",
        value=str(options.get("custom_ports") or ""),
        disabled=port_disabled or options.get("fast_scan") or use_top_ports,
        help=OPTION_HELP["custom_ports"],
        placeholder="22,80,443",
    )
    options["custom_ports"] = custom_ports.strip()

    scan_disabled = host_discovery_only or not enabled
    options["service_version"] = st.checkbox(
        "Service/version detection (-sV)",
        value=options.get("service_version", True),
        disabled=scan_disabled,
        help=OPTION_HELP["service_version"],
    )
    os_disabled = scan_disabled or not root_available
    options["os_detection"] = st.checkbox(
        "OS detection (-O)",
        value=bool(options.get("os_detection")) and root_available,
        disabled=os_disabled,
        help=OPTION_HELP["os_detection"],
    )

    script_labels = [label for label, _ in SCRIPT_CATEGORIES]
    script_values = {label: value for label, value in SCRIPT_CATEGORIES}
    current_script_label = next(
        (label for label, value in SCRIPT_CATEGORIES if value == options.get("script_category", SCRIPT_NONE)),
        "None",
    )
    selected_script_label = st.radio(
        "Script category",
        options=script_labels,
        index=script_labels.index(current_script_label),
        disabled=scan_disabled,
        help=OPTION_HELP["script_category"],
        horizontal=True,
    )
    options["script_category"] = script_values[selected_script_label]

    options["show_reasons"] = st.checkbox(
        "Show reasons",
        value=options.get("show_reasons", False),
        disabled=scan_disabled,
        help=OPTION_HELP["show_reasons"],
    )
    options["open_only"] = st.checkbox(
        "Show only open ports",
        value=options.get("open_only", False),
        disabled=scan_disabled,
        help=OPTION_HELP["open_only"],
    )
    options["traceroute"] = st.checkbox(
        "Traceroute",
        value=bool(options.get("traceroute")) and root_available,
        disabled=host_discovery_only or not enabled or not root_available,
        help=OPTION_HELP["traceroute"],
    )

    timing_labels = [TIMING_POLITE.title(), TIMING_NORMAL.title(), TIMING_AGGRESSIVE.title()]
    timing_values = {
        TIMING_POLITE.title(): TIMING_POLITE,
        TIMING_NORMAL.title(): TIMING_NORMAL,
        TIMING_AGGRESSIVE.title(): TIMING_AGGRESSIVE,
    }
    current_timing = str(options.get("timing_profile", TIMING_NORMAL)).title()
    selected_timing = st.radio(
        "Timing profile",
        options=timing_labels,
        index=timing_labels.index(current_timing),
        disabled=not enabled,
        help=OPTION_HELP["timing_profile"],
        horizontal=True,
    )
    options["timing_profile"] = timing_values[selected_timing]

    if options.get("script_category") == SCRIPT_VULN:
        st.warning(
            "Vuln scripts are high-risk and should only be used on systems you own "
            "or have explicit written permission to test."
        )

    return options

"""Streamlit UI helpers for guided Nmap scan configuration."""

from __future__ import annotations

from typing import Any

import streamlit as st

from utils.nmap_options import (
    OPTION_HELP,
    PROFILE_CUSTOM,
    PROFILES,
    SCRIPT_DEFAULT,
    SCRIPT_DISCOVERY,
    SCRIPT_NONE,
    SCRIPT_SAFE,
    SCRIPT_VULN,
    TIMING_AGGRESSIVE,
    TIMING_NORMAL,
    TIMING_POLITE,
    default_options_for_profile,
    normalize_options,
    validation_messages,
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


def render_nmap_options(enabled: bool) -> dict[str, Any]:
    """Render guided Nmap profile/options UI and return the selected option set."""
    root_available = has_root_privileges()

    profile = st.selectbox(
        "Nmap scan profile",
        options=PROFILES,
        index=PROFILES.index("Standard service scan"),
        disabled=not enabled,
        help="Choose a guided scan profile. Custom guided scan exposes individual options.",
    )

    if not root_available:
        st.caption(
            "OS detection and traceroute may require elevated privileges and are unavailable in this session."
        )

    options = default_options_for_profile(profile)
    options["profile"] = profile

    if profile == PROFILE_CUSTOM:
        options = _render_custom_options(options, enabled, root_available)
    else:
        normalized = normalize_options(options)
        active = [
            f"{key}={value}"
            for key, value in normalized.items()
            if key
            not in ("profile", "os_detection_requested", "os_detection_skipped")
            and value not in (None, "", False)
        ]
        st.caption("Profile settings: " + (", ".join(active) if active else "defaults"))
        if normalized.get("os_detection_skipped"):
            st.caption(
                "OS detection was requested by this profile but will be skipped because elevated "
                "privileges are not available. The rest of the scan will still run."
            )
        if normalized.get("traceroute_skipped"):
            st.caption(
                "Traceroute was requested but will be skipped because elevated privileges are not available."
            )

    normalized = normalize_options(options)
    for message in validation_messages(options):
        st.caption(message)

    return normalized


def _render_custom_options(
    options: dict[str, Any],
    enabled: bool,
    root_available: bool,
) -> dict[str, Any]:
    host_discovery_only = st.checkbox(
        "Host discovery only",
        value=options["host_discovery_only"],
        disabled=not enabled,
        help=OPTION_HELP["host_discovery_only"],
    )
    options["host_discovery_only"] = host_discovery_only

    port_disabled = host_discovery_only or not enabled
    options["fast_scan"] = st.checkbox(
        "Fast scan (-F)",
        value=options["fast_scan"],
        disabled=port_disabled or bool(options.get("custom_ports")) or bool(options.get("top_ports")),
        help=OPTION_HELP["fast_scan"],
    )

    use_top_ports = st.checkbox(
        "Top ports",
        value=bool(options.get("top_ports")),
        disabled=port_disabled or options["fast_scan"] or bool(str(options.get("custom_ports") or "").strip()),
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
        "Custom ports",
        value=str(options.get("custom_ports") or ""),
        disabled=port_disabled or options["fast_scan"] or use_top_ports,
        help=OPTION_HELP["custom_ports"],
        placeholder="22,80,443",
    )
    options["custom_ports"] = custom_ports.strip()

    scan_disabled = host_discovery_only or not enabled
    options["service_version"] = st.checkbox(
        "Service/version detection (-sV)",
        value=options["service_version"],
        disabled=scan_disabled,
        help=OPTION_HELP["service_version"],
    )
    os_disabled = scan_disabled or not root_available
    options["os_detection"] = st.checkbox(
        "OS detection (-O)",
        value=options["os_detection"] and root_available,
        disabled=os_disabled,
        help=OPTION_HELP["os_detection"],
    )
    if not root_available:
        st.caption(
            "OS detection and traceroute require elevated privileges and are unavailable in this Streamlit session."
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
        value=options["show_reasons"],
        disabled=scan_disabled,
        help=OPTION_HELP["show_reasons"],
    )
    options["open_only"] = st.checkbox(
        "Show only open ports",
        value=options["open_only"],
        disabled=scan_disabled,
        help=OPTION_HELP["open_only"],
    )
    options["traceroute"] = st.checkbox(
        "Traceroute",
        value=options["traceroute"] and root_available,
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

    if options["script_category"] == SCRIPT_VULN:
        st.warning(
            "Vuln scripts are high-risk and should only be used on systems you own "
            "or have explicit written permission to test."
        )

    if options.get("host_discovery_only"):
        st.info("Host discovery only disables port, version, OS, and script scanning.")

    return options

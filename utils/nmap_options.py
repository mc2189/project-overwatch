"""Guided Nmap scan profiles, option metadata, compatibility rules, and flag building."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

from utils.privileges import has_root_privileges

PROFILE_QUICK_CHECK = "Quick check"
PROFILE_STANDARD = "Standard service scan"
PROFILE_DETAILED = "Detailed authorised scan"
PROFILE_HOST_DISCOVERY = "Host discovery only"
PROFILE_CUSTOM = "Custom guided scan"

PROFILES = [
    PROFILE_QUICK_CHECK,
    PROFILE_STANDARD,
    PROFILE_DETAILED,
    PROFILE_HOST_DISCOVERY,
    PROFILE_CUSTOM,
]

SCRIPT_NONE = "none"
SCRIPT_SAFE = "safe"
SCRIPT_DEFAULT = "default"
SCRIPT_DISCOVERY = "discovery"
SCRIPT_VULN = "vuln"

TIMING_POLITE = "polite"
TIMING_NORMAL = "normal"
TIMING_AGGRESSIVE = "aggressive"

OPTION_HELP: dict[str, str] = {
    "host_discovery_only": "Ping and discovery only. Does not scan ports, detect versions, run OS detection, or scripts.",
    "fast_scan": "Scan fewer ports using Nmap's fast mode (-F). Cannot be combined with custom ports.",
    "top_ports": "Scan the most common N ports (--top-ports). Cannot be combined with custom ports or fast scan.",
    "custom_ports": "Scan a guided list of ports such as 22,80,443. Cannot be combined with fast scan or top ports.",
    "service_version": "Probe open ports to identify service names and versions (-sV).",
    "os_detection": "Attempt operating system fingerprinting (-O). Requires authorisation and elevated (root) privileges.",
    "script_category": "Run one NSE script category: Safe, Default, Discovery, or Vuln. Requires authorisation.",
    "show_reasons": "Show Nmap's reasons why a port is in a given state (--reason).",
    "open_only": "Show only open ports in the output (--open).",
    "traceroute": "Trace the network path to the target (--traceroute). Requires authorisation.",
    "timing_profile": "Select one timing template: Polite (T2), Normal (T3), or Aggressive (T4).",
}

PROFILE_DEFAULTS: dict[str, dict[str, Any]] = {
    PROFILE_QUICK_CHECK: {
        "profile": PROFILE_QUICK_CHECK,
        "host_discovery_only": False,
        "fast_scan": True,
        "top_ports": None,
        "custom_ports": "",
        "service_version": False,
        "os_detection": False,
        "script_category": SCRIPT_NONE,
        "show_reasons": False,
        "open_only": True,
        "traceroute": False,
        "timing_profile": TIMING_NORMAL,
    },
    PROFILE_STANDARD: {
        "profile": PROFILE_STANDARD,
        "host_discovery_only": False,
        "fast_scan": False,
        "top_ports": None,
        "custom_ports": "",
        "service_version": True,
        "os_detection": False,
        "script_category": SCRIPT_NONE,
        "show_reasons": False,
        "open_only": False,
        "traceroute": False,
        "timing_profile": TIMING_NORMAL,
    },
    PROFILE_DETAILED: {
        "profile": PROFILE_DETAILED,
        "host_discovery_only": False,
        "fast_scan": False,
        "top_ports": None,
        "custom_ports": "",
        "service_version": True,
        "os_detection": True,
        "script_category": SCRIPT_SAFE,
        "show_reasons": True,
        "open_only": False,
        "traceroute": False,
        "timing_profile": TIMING_NORMAL,
    },
    PROFILE_HOST_DISCOVERY: {
        "profile": PROFILE_HOST_DISCOVERY,
        "host_discovery_only": True,
        "fast_scan": False,
        "top_ports": None,
        "custom_ports": "",
        "service_version": False,
        "os_detection": False,
        "script_category": SCRIPT_NONE,
        "show_reasons": False,
        "open_only": False,
        "traceroute": False,
        "timing_profile": TIMING_POLITE,
    },
    PROFILE_CUSTOM: {
        "profile": PROFILE_CUSTOM,
        "host_discovery_only": False,
        "fast_scan": False,
        "top_ports": None,
        "custom_ports": "",
        "service_version": True,
        "os_detection": False,
        "script_category": SCRIPT_NONE,
        "show_reasons": False,
        "open_only": False,
        "traceroute": False,
        "timing_profile": TIMING_NORMAL,
    },
}


def default_options_for_profile(profile: str) -> dict[str, Any]:
    return deepcopy(PROFILE_DEFAULTS.get(profile, PROFILE_DEFAULTS[PROFILE_STANDARD]))


def normalize_options(options: dict[str, Any]) -> dict[str, Any]:
    """Apply compatibility rules and return a safe option set."""
    normalized = deepcopy(options)
    profile = normalized.get("profile", PROFILE_STANDARD)

    if profile != PROFILE_CUSTOM:
        preset = default_options_for_profile(profile)
        preset.update({k: v for k, v in normalized.items() if k != "profile"})
        preset["profile"] = profile
        normalized = preset

    if normalized.get("host_discovery_only"):
        normalized["fast_scan"] = False
        normalized["top_ports"] = None
        normalized["custom_ports"] = ""
        normalized["service_version"] = False
        normalized["os_detection"] = False
        normalized["script_category"] = SCRIPT_NONE
        normalized["open_only"] = False
        return normalized

    if normalized.get("fast_scan"):
        normalized["custom_ports"] = ""
        normalized["top_ports"] = None

    custom_ports = str(normalized.get("custom_ports") or "").strip()
    top_ports = normalized.get("top_ports")

    if custom_ports:
        normalized["fast_scan"] = False
        normalized["top_ports"] = None
    elif top_ports:
        normalized["fast_scan"] = False
        normalized["custom_ports"] = ""
    else:
        normalized["custom_ports"] = ""

    script_category = normalized.get("script_category", SCRIPT_NONE)
    if script_category not in {SCRIPT_NONE, SCRIPT_SAFE, SCRIPT_DEFAULT, SCRIPT_DISCOVERY, SCRIPT_VULN}:
        normalized["script_category"] = SCRIPT_NONE

    timing = normalized.get("timing_profile", TIMING_NORMAL)
    if timing not in {TIMING_POLITE, TIMING_NORMAL, TIMING_AGGRESSIVE}:
        normalized["timing_profile"] = TIMING_NORMAL

    normalized["os_detection_requested"] = bool(normalized.get("os_detection"))
    if normalized["os_detection_requested"] and not has_root_privileges():
        normalized["os_detection"] = False
        normalized["os_detection_skipped"] = True
    else:
        normalized["os_detection_skipped"] = False

    return normalized


def options_require_authorisation(options: dict[str, Any]) -> bool:
    """Return True when selected options include higher-risk active checks."""
    normalized = normalize_options(options)
    if normalized.get("host_discovery_only"):
        return True
    if normalized.get("os_detection"):
        return True
    if normalized.get("traceroute"):
        return True
    if normalized.get("script_category", SCRIPT_NONE) != SCRIPT_NONE:
        return True
    return True


def build_nmap_flags(options: dict[str, Any]) -> list[str]:
    """Build a safe Nmap argument list from guided options."""
    normalized = normalize_options(options)
    flags: list[str] = []

    if normalized.get("host_discovery_only"):
        flags.append("-sn")
        timing_flag = _timing_flag(normalized.get("timing_profile", TIMING_POLITE))
        if timing_flag:
            flags.append(timing_flag)
        return flags

    if normalized.get("fast_scan"):
        flags.append("-F")
    elif normalized.get("top_ports"):
        flags.append(f"--top-ports={int(normalized['top_ports'])}")
    elif normalized.get("custom_ports"):
        flags.append(f"-p{normalized['custom_ports'].replace(' ', '')}")

    if normalized.get("service_version"):
        flags.append("-sV")

    if normalized.get("os_detection"):
        flags.append("-O")

    script_category = normalized.get("script_category", SCRIPT_NONE)
    if script_category != SCRIPT_NONE:
        flags.append(f"--script={script_category}")

    if normalized.get("show_reasons"):
        flags.append("--reason")

    if normalized.get("open_only"):
        flags.append("--open")

    if normalized.get("traceroute"):
        flags.append("--traceroute")

    timing_flag = _timing_flag(normalized.get("timing_profile", TIMING_NORMAL))
    if timing_flag:
        flags.append(timing_flag)

    if not flags:
        flags.append("-sV")

    return flags


def _timing_flag(timing_profile: str) -> str | None:
    mapping = {
        TIMING_POLITE: "-T2",
        TIMING_NORMAL: "-T3",
        TIMING_AGGRESSIVE: "-T4",
    }
    return mapping.get(timing_profile)


def validation_messages(options: dict[str, Any]) -> list[str]:
    """Return user-facing compatibility warnings for the current option set."""
    messages: list[str] = []
    normalized = normalize_options(options)

    if options.get("host_discovery_only") and any(
        [
            options.get("service_version"),
            options.get("os_detection"),
            options.get("script_category", SCRIPT_NONE) != SCRIPT_NONE,
            options.get("fast_scan"),
            options.get("custom_ports"),
            options.get("top_ports"),
        ]
    ):
        messages.append("Host discovery only disables port, version, OS, and script scanning.")

    if options.get("fast_scan") and (options.get("custom_ports") or options.get("top_ports")):
        messages.append("Fast scan cannot be combined with top ports or custom ports.")

    if options.get("custom_ports") and options.get("top_ports"):
        messages.append("Use either top ports or custom ports, not both.")

    if normalized.get("script_category") == SCRIPT_VULN:
        messages.append("Vuln scripts are high-risk and require explicit authorisation.")

    if normalized.get("os_detection_skipped"):
        messages.append(
            "OS detection requires elevated privileges and is unavailable in this Streamlit session."
        )

    return messages

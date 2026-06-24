"""Nmap profile definitions for the Advanced Profile Runner."""

from __future__ import annotations

import re
from copy import deepcopy
from typing import Any

from utils.nmap_options import (
    PROFILE_CUSTOM,
    SCRIPT_NONE,
    SCRIPT_SAFE,
    TIMING_NORMAL,
    TIMING_POLITE,
)

PROFILE_QUICK_SERVICE = "quick_service_check"
PROFILE_STANDARD_SERVICE = "standard_service_detection"
PROFILE_LOCAL_DEVICE = "local_device_detail"
PROFILE_WEB_SURFACE = "web_surface_discovery"
PROFILE_FULL_TCP = "full_tcp_common_ports"
PROFILE_CUSTOM_PORTS = "custom_port_list"
PROFILE_SCRIPT_SAFE = "script_assisted_safe_review"

# Legacy profile labels still accepted in saved session state.
LEGACY_PROFILE_ALIASES: dict[str, str] = {
    "Quick check": PROFILE_QUICK_SERVICE,
    "Standard service scan": PROFILE_STANDARD_SERVICE,
    "Detailed authorised scan": PROFILE_LOCAL_DEVICE,
    "Host discovery only": PROFILE_QUICK_SERVICE,
    "Custom guided scan": PROFILE_CUSTOM_PORTS,
}

PROFILE_ORDER: tuple[str, ...] = (
    PROFILE_QUICK_SERVICE,
    PROFILE_STANDARD_SERVICE,
    PROFILE_LOCAL_DEVICE,
    PROFILE_WEB_SURFACE,
    PROFILE_FULL_TCP,
    PROFILE_CUSTOM_PORTS,
    PROFILE_SCRIPT_SAFE,
)

WEB_SURFACE_PORTS = (80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 7000, 9443)
MAX_CUSTOM_PORTS = 50
MAX_TOP_PORTS_FULL_TCP = 200
_PORT_TOKEN_RE = re.compile(r"^\d{1,5}$")

PROFILE_DEFINITIONS: dict[str, dict[str, Any]] = {
    PROFILE_QUICK_SERVICE: {
        "profile_id": PROFILE_QUICK_SERVICE,
        "display_name": "Quick Service Check",
        "description": "Fast overview of common ports using Nmap fast mode.",
        "intended_use": "First-pass service discovery on a single host when breadth should stay minimal.",
        "estimated_noise": "low",
        "testing_level": "safe_active_check",
        "requires_elevation": False,
        "active_warning": "Active port probe against the selected target only.",
        "suitable_targets": ("ipv4", "domain"),
        "default_ports": None,
        "nmap_args_hint": "-F --open",
    },
    PROFILE_STANDARD_SERVICE: {
        "profile_id": PROFILE_STANDARD_SERVICE,
        "display_name": "Standard Service Detection",
        "description": "Service and version detection on default Nmap port selection.",
        "intended_use": "Identify open ports and service versions for authorised assessment.",
        "estimated_noise": "medium",
        "testing_level": "safe_active_check",
        "requires_elevation": False,
        "active_warning": "Runs service/version detection (-sV) on the target.",
        "suitable_targets": ("ipv4", "domain"),
        "default_ports": None,
        "nmap_args_hint": "-sV",
    },
    PROFILE_LOCAL_DEVICE: {
        "profile_id": PROFILE_LOCAL_DEVICE,
        "display_name": "Local Device Detail",
        "description": "Richer local device fingerprint with service detection and optional OS hints.",
        "intended_use": "Home lab or Personal Lab device review on private IPs.",
        "estimated_noise": "medium",
        "testing_level": "safe_active_check",
        "requires_elevation": True,
        "active_warning": "OS detection is attempted only when elevated privileges are available.",
        "suitable_targets": ("ipv4", "domain"),
        "default_ports": None,
        "nmap_args_hint": "-sV -O (OS if elevated)",
    },
    PROFILE_WEB_SURFACE: {
        "profile_id": PROFILE_WEB_SURFACE,
        "display_name": "Web Surface Discovery",
        "description": "Focused scan of common HTTP/TLS and application web ports.",
        "intended_use": "Find web-like services before HTTP/TLS posture review.",
        "estimated_noise": "low",
        "testing_level": "safe_active_check",
        "requires_elevation": False,
        "active_warning": "Probes a fixed list of common web ports only.",
        "suitable_targets": ("ipv4", "domain"),
        "default_ports": WEB_SURFACE_PORTS,
        "nmap_args_hint": f"-p {','.join(str(p) for p in WEB_SURFACE_PORTS)} -sV",
    },
    PROFILE_FULL_TCP: {
        "profile_id": PROFILE_FULL_TCP,
        "display_name": "Full TCP Common Ports",
        "description": f"Bounded review of the top {MAX_TOP_PORTS_FULL_TCP} TCP ports.",
        "intended_use": "Broader but capped TCP review when a quick scan is insufficient.",
        "estimated_noise": "medium",
        "testing_level": "safe_active_check",
        "requires_elevation": False,
        "active_warning": f"Scans up to {MAX_TOP_PORTS_FULL_TCP} common TCP ports — still single-host only.",
        "suitable_targets": ("ipv4", "domain"),
        "default_ports": None,
        "nmap_args_hint": f"--top-ports {MAX_TOP_PORTS_FULL_TCP} -sV",
    },
    PROFILE_CUSTOM_PORTS: {
        "profile_id": PROFILE_CUSTOM_PORTS,
        "display_name": "Custom Port List",
        "description": f"User-selected ports (max {MAX_CUSTOM_PORTS}, comma-separated).",
        "intended_use": "Targeted checks when you already know which ports matter.",
        "estimated_noise": "low",
        "testing_level": "safe_active_check",
        "requires_elevation": False,
        "active_warning": "Only the ports you enter are scanned.",
        "suitable_targets": ("ipv4", "domain"),
        "default_ports": None,
        "nmap_args_hint": "-p <your ports> -sV",
    },
    PROFILE_SCRIPT_SAFE: {
        "profile_id": PROFILE_SCRIPT_SAFE,
        "display_name": "Script-assisted Safe Review",
        "description": "Service detection plus safe/default NSE scripts for extra detail.",
        "intended_use": "More detailed review when authorised — not selected by default.",
        "estimated_noise": "high",
        "testing_level": "intrusive_active_check",
        "requires_elevation": False,
        "active_warning": "Runs NSE safe scripts in addition to service detection.",
        "suitable_targets": ("ipv4", "domain"),
        "default_ports": None,
        "nmap_args_hint": "-sV --script safe",
        "disabled_reason": None,
    },
}


def resolve_profile_id(profile: str | None) -> str:
    """Map display label, legacy label, or profile_id to canonical profile_id."""
    if not profile:
        return PROFILE_STANDARD_SERVICE
    if profile in PROFILE_DEFINITIONS:
        return profile
    if profile in LEGACY_PROFILE_ALIASES:
        return LEGACY_PROFILE_ALIASES[profile]
    for definition in PROFILE_DEFINITIONS.values():
        if definition.get("display_name") == profile:
            return definition["profile_id"]
    return PROFILE_STANDARD_SERVICE


def get_profile_definition(profile_id: str) -> dict[str, Any]:
    canonical = resolve_profile_id(profile_id)
    return deepcopy(PROFILE_DEFINITIONS.get(canonical, PROFILE_DEFINITIONS[PROFILE_STANDARD_SERVICE]))


def profile_display_name(profile_id: str) -> str:
    return get_profile_definition(profile_id)["display_name"]


def all_profile_ids() -> tuple[str, ...]:
    return PROFILE_ORDER


def default_profile_for_context(
    *,
    goal_id: str | None = None,
    run_mode_id: str | None = None,
    conservative: bool = False,
) -> str:
    """Choose a sensible default profile from workspace context."""
    from utils.assessment_goals import GOAL_LOCAL_NETWORK, GOAL_WEBSITE_POSTURE
    from utils.run_modes import LOCAL_IP_CHECK, QUICK_CHECK, WEBSITE_FOOTPRINT

    if goal_id == GOAL_LOCAL_NETWORK or run_mode_id == LOCAL_IP_CHECK:
        return PROFILE_STANDARD_SERVICE
    if goal_id == GOAL_WEBSITE_POSTURE or run_mode_id == WEBSITE_FOOTPRINT:
        return PROFILE_WEB_SURFACE
    if conservative or run_mode_id == QUICK_CHECK:
        return PROFILE_QUICK_SERVICE
    return PROFILE_QUICK_SERVICE


def parse_custom_port_list(text: str, *, max_ports: int = MAX_CUSTOM_PORTS) -> tuple[str, list[str]]:
    """Validate comma-separated ports. Returns (normalized_csv, errors)."""
    errors: list[str] = []
    raw = str(text or "").strip()
    if not raw:
        return "", ["Enter at least one port."]

    if "-" in raw and not _is_bounded_range(raw):
        errors.append("Port ranges are not enabled by default. Use comma-separated ports.")

    tokens = [token.strip() for token in re.split(r"[,\\s]+", raw) if token.strip()]
    ports: list[int] = []
    for token in tokens:
        if "-" in token:
            errors.append(f"Range token not allowed: {token}")
            continue
        if not _PORT_TOKEN_RE.match(token):
            errors.append(f"Invalid port: {token}")
            continue
        port = int(token)
        if port < 1 or port > 65535:
            errors.append(f"Port out of range: {port}")
            continue
        if port not in ports:
            ports.append(port)
        if len(ports) > max_ports:
            errors.append(f"Maximum {max_ports} ports allowed.")
            break

    if errors:
        return "", errors
    if not ports:
        return "", ["No valid ports parsed."]
    ports.sort()
    return ",".join(str(port) for port in ports), []


def _is_bounded_range(text: str) -> bool:
    return False


def options_for_profile(
    profile_id: str,
    *,
    custom_ports: str = "",
) -> dict[str, Any]:
    """Build nmap_options dict for a profile_id."""
    canonical = resolve_profile_id(profile_id)
    definition = get_profile_definition(canonical)
    options: dict[str, Any] = {
        "profile_id": canonical,
        "profile": definition["display_name"],
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
    }

    if canonical == PROFILE_QUICK_SERVICE:
        options.update(
            {
                "fast_scan": True,
                "service_version": False,
                "open_only": True,
            }
        )
    elif canonical == PROFILE_STANDARD_SERVICE:
        options.update({"service_version": True})
    elif canonical == PROFILE_LOCAL_DEVICE:
        options.update(
            {
                "service_version": True,
                "os_detection": True,
                "show_reasons": True,
                "timing_profile": TIMING_POLITE,
            }
        )
    elif canonical == PROFILE_WEB_SURFACE:
        options.update(
            {
                "custom_ports": ",".join(str(port) for port in WEB_SURFACE_PORTS),
                "service_version": True,
                "open_only": True,
            }
        )
    elif canonical == PROFILE_FULL_TCP:
        options.update(
            {
                "top_ports": MAX_TOP_PORTS_FULL_TCP,
                "service_version": True,
            }
        )
    elif canonical == PROFILE_CUSTOM_PORTS:
        normalized, errors = parse_custom_port_list(custom_ports)
        options.update(
            {
                "profile": PROFILE_CUSTOM,
                "custom_ports": normalized,
                "custom_port_errors": errors,
                "service_version": True,
            }
        )
    elif canonical == PROFILE_SCRIPT_SAFE:
        options.update(
            {
                "service_version": True,
                "script_category": SCRIPT_SAFE,
                "show_reasons": True,
            }
        )

    return options


def profile_testing_level(profile_id: str, options: dict[str, Any] | None = None) -> str:
    definition = get_profile_definition(profile_id)
    level = definition.get("testing_level", "safe_active_check")
    opts = options or {}
    if opts.get("script_category") not in (None, "", SCRIPT_NONE):
        return "intrusive_active_check"
    return str(level)


def enrich_parsed_scan_metadata(
    parsed_data: dict[str, Any],
    *,
    target: str,
    nmap_options: dict[str, Any],
    flags: list[str],
) -> dict[str, Any]:
    """Attach profile and command summary to parsed Nmap output."""
    profile_id = resolve_profile_id(nmap_options.get("profile_id") or nmap_options.get("profile"))
    definition = get_profile_definition(profile_id)
    parsed_data["scan_profile"] = {
        "profile_id": profile_id,
        "display_name": definition["display_name"],
        "description": definition["description"],
        "estimated_noise": definition["estimated_noise"],
        "testing_level": profile_testing_level(profile_id, nmap_options),
        "flags": list(flags),
        "target": target,
    }
    return parsed_data


def dangerous_default_flags() -> list[str]:
    """Profiles that must not imply broad network ranges in defaults."""
    risky: list[str] = []
    for profile_id, definition in PROFILE_DEFINITIONS.items():
        hint = str(definition.get("nmap_args_hint") or "")
        if any(token in hint for token in ("/8", "/16", "0.0.0.0/0")):
            risky.append(profile_id)
    return risky

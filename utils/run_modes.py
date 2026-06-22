"""Guided run modes for the Run Operation workflow."""

from __future__ import annotations

from modules.module_registry import get_module
from ui.constants import MODULE_CARD_TITLES
from utils.target_detection import TARGET_TYPES, target_type_label

QUICK_CHECK = "quick_check"
WEBSITE_FOOTPRINT = "website_footprint"
LOCAL_IP_CHECK = "local_ip_check"
CUSTOM = "custom"

QUICK_CHECK_PORT_SCAN_KEY = "quick_check_include_port_scan"
PREV_PORT_SCAN_KEY = "quick_check_prev_include_port_scan"
RUN_MODE_CASE_KEY = "run_mode_loaded_case_id"

RUN_MODE_ORDER: tuple[str, ...] = (
    QUICK_CHECK,
    WEBSITE_FOOTPRINT,
    LOCAL_IP_CHECK,
    CUSTOM,
)

RUN_MODE_LABELS: dict[str, str] = {
    QUICK_CHECK: "Quick Check",
    WEBSITE_FOOTPRINT: "Website / Domain Footprint",
    LOCAL_IP_CHECK: "Local Device / IP Check",
    CUSTOM: "Custom Module Selection",
}

MODE_DESCRIPTIONS: dict[str, str] = {
    QUICK_CHECK: (
        "Simple default mode. Recommends the safest useful modules for the detected target type."
    ),
    WEBSITE_FOOTPRINT: (
        "Passive domain footprinting for domains and URLs using DNS, HTTP/TLS, and certificate transparency."
    ),
    LOCAL_IP_CHECK: (
        "Conservative active network service check for a single IPv4 address. Authorisation required."
    ),
    CUSTOM: (
        "Choose any compatible implemented modules manually. Recommended modules are suggested but optional."
    ),
}

# Deterministic recommendations by mode and target type (module IDs).
_MODE_TARGET_RECOMMENDATIONS: dict[str, dict[str, tuple[str, ...]]] = {
    QUICK_CHECK: {
        "ipv4": ("infra_nmap",),
        "domain": ("infra_domain_intel", "infra_cert_subdomain"),
        "url": ("infra_domain_intel", "infra_cert_subdomain"),
        "email": (),
        "username": (),
        "unknown": (),
    },
    WEBSITE_FOOTPRINT: {
        "domain": ("infra_domain_intel", "infra_cert_subdomain"),
        "url": ("infra_domain_intel", "infra_cert_subdomain"),
    },
    LOCAL_IP_CHECK: {
        "ipv4": ("infra_nmap",),
    },
}


def list_run_modes() -> list[tuple[str, str]]:
    """Return run mode id/label pairs in display order."""
    return [(mode_id, RUN_MODE_LABELS[mode_id]) for mode_id in RUN_MODE_ORDER]


def get_run_mode_label(mode_id: str) -> str:
    return RUN_MODE_LABELS.get(mode_id, mode_id)


def get_run_mode_description(mode_id: str) -> str:
    return MODE_DESCRIPTIONS.get(mode_id, "")


def get_recommended_modules_for_mode(mode_id: str, target_type: str) -> list[str]:
    """Return recommended module IDs for a run mode and target type."""
    if mode_id == CUSTOM:
        return []
    if target_type not in TARGET_TYPES:
        target_type = "unknown"
    by_target = _MODE_TARGET_RECOMMENDATIONS.get(mode_id, {})
    return list(by_target.get(target_type, ()))


def resolve_recommended_modules_for_mode(
    mode_id: str,
    target_type: str,
    *,
    quick_check_include_port_scan: bool = False,
) -> list[str]:
    """Return recommendations, including optional Quick Check port scan."""
    modules = get_recommended_modules_for_mode(mode_id, target_type)
    if (
        mode_id == QUICK_CHECK
        and quick_check_include_port_scan
        and target_type in {"domain", "url"}
        and "infra_nmap" not in modules
    ):
        return [*modules, "infra_nmap"]
    return modules


def quick_check_supports_port_scan_option(target_type: str) -> bool:
    """Return True when Quick Check may offer an optional light port scan."""
    return target_type in {"domain", "url"}


def get_recommendation_reason(
    mode_id: str,
    target_type: str,
    *,
    quick_check_include_port_scan: bool = False,
) -> str:
    """Explain why modules are recommended for this mode and target."""
    label = target_type_label(target_type)
    recommended = resolve_recommended_modules_for_mode(
        mode_id,
        target_type,
        quick_check_include_port_scan=quick_check_include_port_scan,
    )

    if mode_id == CUSTOM:
        return "Custom mode — select any compatible modules. Suggestions are optional."

    if mode_id == QUICK_CHECK:
        if not recommended:
            return (
                f"Quick Check found no implemented modules suitable for an {label} target. "
                "Planned identity modules may support this target type in a future release."
            )
        if target_type == "ipv4":
            return f"Quick Check recommends an active network service check for this {label}."
        if target_type in {"domain", "url"}:
            if quick_check_include_port_scan:
                return (
                    f"Quick Check recommends passive domain modules plus an optional light port scan "
                    f"for this {label}. Authorisation is required for the port scan."
                )
            return (
                f"Quick Check recommends passive domain modules for this {label} "
                "(no port scan by default)."
            )
        names = _module_display_names(recommended)
        return f"Quick Check recommends: {names}."

    if mode_id == WEBSITE_FOOTPRINT:
        if target_type not in {"domain", "url"}:
            return (
                "Website / Domain Footprint is designed for domain or URL targets. "
                "Enter a domain or URL, or switch run mode."
            )
        return (
            "Website / Domain Footprint recommends passive DNS, HTTP/TLS, and certificate "
            "transparency lookups. Nmap is not included by default."
        )

    if mode_id == LOCAL_IP_CHECK:
        if target_type != "ipv4":
            return (
                "Local Device / IP Check is designed for IPv4 addresses. "
                "Enter an IP address, or switch run mode."
            )
        return (
            "Local Device / IP Check recommends Network Service Check with a conservative "
            "scan profile. Authorisation is required before launch."
        )

    return "Select compatible modules for this target."


def get_run_mode_expected_outputs(mode_id: str, target_type: str) -> list[str]:
    """Return expected output summaries for a mode and target type."""
    module_ids = get_recommended_modules_for_mode(mode_id, target_type)
    if mode_id == CUSTOM:
        return ["Depends on modules you select in Custom Module Selection mode."]
    outputs: list[str] = []
    for module_id in module_ids:
        module = get_module(module_id)
        if module is None:
            continue
        title = MODULE_CARD_TITLES.get(module_id, module.display_name)
        summary = module.output_summary or module.short_help or module.description
        outputs.append(f"{title}: {summary}")
    if not outputs:
        outputs.append("No module outputs expected — no suitable modules for this mode and target.")
    return outputs


def mode_uses_conservative_nmap(mode_id: str) -> bool:
    """Return True when Nmap should default to a conservative profile."""
    return mode_id in {QUICK_CHECK, LOCAL_IP_CHECK}


def should_auto_apply_selection(
    run_mode: str,
    previous_mode: str | None,
    target: str,
    previous_target: str | None,
    *,
    include_port_scan: bool = False,
    previous_include_port_scan: bool | None = None,
) -> bool:
    """Return True when module checkboxes should be reset from mode recommendations."""
    if run_mode == CUSTOM:
        return False
    if previous_mode != run_mode:
        return True
    if target.strip() != (previous_target or "").strip():
        return True
    if run_mode == QUICK_CHECK and include_port_scan != bool(previous_include_port_scan):
        return True
    return False


def apply_recommended_selection(recommended_module_ids: list[str]) -> None:
    """Set Streamlit session state checkboxes for implemented modules."""
    from ui.constants import IMPLEMENTED_MODULE_IDS
    import streamlit as st

    recommended = set(recommended_module_ids)
    for module_id in IMPLEMENTED_MODULE_IDS:
        st.session_state[f"module_sel_{module_id}"] = module_id in recommended


def sync_run_mode_from_case(case: dict, *, session_key: str = "operation_run_mode") -> None:
    """Load a case's stored run mode into session state when the active case changes."""
    import streamlit as st

    case_id = case["id"]
    if st.session_state.get(RUN_MODE_CASE_KEY) == case_id:
        return
    stored = case.get("default_run_mode") or QUICK_CHECK
    if stored not in RUN_MODE_LABELS:
        stored = QUICK_CHECK
    st.session_state[session_key] = stored
    st.session_state["operation_prev_run_mode"] = None
    st.session_state[RUN_MODE_CASE_KEY] = case_id
    st.session_state.pop("persisted_run_mode", None)
    st.session_state.pop("run_mode_radio", None)
    st.session_state.pop(QUICK_CHECK_PORT_SCAN_KEY, None)
    st.session_state.pop(PREV_PORT_SCAN_KEY, None)


def persist_run_mode_for_case(case_id: int, run_mode_id: str) -> None:
    """Save the current run mode on the active case."""
    from database.db_setup import update_case_run_mode

    update_case_run_mode(case_id, run_mode_id)


def _module_display_names(module_ids: list[str]) -> str:
    return ", ".join(MODULE_CARD_TITLES.get(module_id, module_id) for module_id in module_ids)

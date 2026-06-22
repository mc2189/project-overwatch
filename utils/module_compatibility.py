"""Module and target compatibility helpers for Project Overwatch."""

from __future__ import annotations

from modules.module_registry import MODULES, ModuleEntry, get_module, is_executable
from utils.target_detection import get_target_type, target_type_label


def module_short_help(module: ModuleEntry) -> str:
    """Return sidebar help text, with a planned-module fallback."""
    if module.short_help:
        return module.short_help
    if not module.implemented:
        return f"{module.display_name} is planned for a future release."
    return module.description


def module_detailed_help(module: ModuleEntry) -> str:
    """Return longer module guidance for expanders."""
    if module.detailed_help:
        return module.detailed_help
    if not module.implemented:
        return (
            f"{module.display_name} is not available in this release. "
            f"It is registered as a {module.mode} module ({module.risk_level} risk)."
        )
    return module.description


def module_accepts_target(module: ModuleEntry, target_type: str) -> bool:
    """Return True when the module declares support for the detected target type."""
    if not module.accepted_target_types:
        return False
    return target_type in module.accepted_target_types


def get_compatible_modules(target: str) -> list[ModuleEntry]:
    """Return implemented active modules compatible with the target value."""
    target_type = get_target_type(target)
    return [
        module
        for module in MODULES
        if is_executable(module) and module_accepts_target(module, target_type)
    ]


def get_incompatible_reason(module: ModuleEntry, target_type: str) -> str:
    """Explain why a module cannot run against the detected target type."""
    if not module.implemented or module.status != "active":
        return f"{module.display_name} is not available in this release."

    if not module.accepted_target_types:
        return f"{module.display_name} does not declare supported target types."

    if module_accepts_target(module, target_type):
        return ""

    accepted_labels = ", ".join(target_type_label(value) for value in module.accepted_target_types)
    detected = target_type_label(target_type)

    if target_type == "email":
        return (
            f"Requires {accepted_labels}; detected target type is {detected}. "
            "Planned identity modules such as Holehe may support email targets in a future release."
        )
    if target_type == "username":
        return (
            f"Requires {accepted_labels}; detected target type is {detected}. "
            "Planned identity modules such as Sherlock may support username targets in a future release."
        )
    if target_type == "unknown":
        return (
            f"Requires {accepted_labels}; could not recognise the target type. "
            "Enter an IPv4 address, domain, or URL."
        )
    if target_type == "ipv4" and "domain" in module.accepted_target_types and "url" in module.accepted_target_types:
        return f"Requires a domain or URL; detected target type is {detected}."
    if target_type == "ipv4" and "domain" in module.accepted_target_types:
        return f"Requires a domain or URL; detected target type is {detected}."

    return f"Requires {accepted_labels}; detected target type is {detected}."


def module_is_selectable(
    module: ModuleEntry,
    target: str,
    *,
    runtime_ready: bool,
) -> bool:
    """Return True when a module can be selected in the sidebar for the current target."""
    if not is_executable(module):
        return False
    if not runtime_ready:
        return False
    cleaned = target.strip()
    if not cleaned:
        return True
    return module_accepts_target(module, get_target_type(cleaned))


def get_module_disable_reason(
    module: ModuleEntry,
    target: str,
    *,
    runtime_ready: bool,
    runtime_error: str | None,
) -> str | None:
    """Return a short UI reason when a module checkbox is disabled."""
    if not is_executable(module):
        return None
    if not runtime_ready:
        return runtime_error or "Runtime is not ready."
    cleaned = target.strip()
    if cleaned:
        target_type = get_target_type(cleaned)
        if not module_accepts_target(module, target_type):
            return get_incompatible_reason(module, target_type)
    return None


def build_operation_plan(
    *,
    case_name: str,
    case_id: int,
    target: str,
    selected_module_ids: list[str],
    authorisation_confirmed: bool,
) -> dict:
    """Build a pre-launch operation plan summary for the dashboard."""
    target_type = get_target_type(target)
    modules = [get_module(module_id) for module_id in selected_module_ids]
    modules = [module for module in modules if module is not None]

    active_modules = [module.display_name for module in modules if module.mode == "active"]
    passive_modules = [module.display_name for module in modules if module.mode == "passive"]
    analysis_modules = [module.display_name for module in modules if module.mode == "analysis"]

    expected_outputs: list[str] = []
    for module in modules:
        if module.output_summary:
            expected_outputs.append(f"{module.display_name}: {module.output_summary}")
        elif module.short_help:
            expected_outputs.append(f"{module.display_name}: {module.short_help}")

    auth_required = any(module.requires_authorisation for module in modules)

    incompatible: list[str] = []
    if target.strip():
        for module_id in selected_module_ids:
            module = get_module(module_id)
            if module is None:
                continue
            reason = get_incompatible_reason(module, target_type)
            if reason:
                incompatible.append(f"{module.display_name}: {reason}")

    return {
        "case_name": case_name,
        "case_id": case_id,
        "target": target.strip(),
        "target_type": target_type,
        "target_type_label": target_type_label(target_type),
        "selected_modules": [module.display_name for module in modules],
        "active_modules": active_modules,
        "passive_modules": passive_modules,
        "analysis_modules": analysis_modules,
        "authorisation_required": auth_required,
        "authorisation_confirmed": authorisation_confirmed,
        "expected_outputs": expected_outputs,
        "incompatible_modules": incompatible,
        "ready_to_run": bool(target.strip() and modules and not incompatible and (not auth_required or authorisation_confirmed)),
    }

"""Module runtime helpers for the Streamlit UI."""

from __future__ import annotations

from modules.executor import get_runtime_error, is_runtime_ready
from modules.module_registry import ModuleEntry, is_executable
from utils.module_compatibility import get_module_disable_reason, module_accepts_target, module_is_selectable


def module_runtime_ready(module_id: str) -> bool:
    return is_runtime_ready(module_id)


def module_runtime_error(module_id: str) -> str | None:
    return get_runtime_error(module_id)


def module_selectable(module: ModuleEntry, target: str) -> bool:
    return module_is_selectable(
        module,
        target,
        runtime_ready=module_runtime_ready(module.module_id),
    )


def module_disable_reason(module: ModuleEntry, target: str) -> str | None:
    return get_module_disable_reason(
        module,
        target,
        runtime_ready=module_runtime_ready(module.module_id),
        runtime_error=module_runtime_error(module.module_id),
    )


def module_enabled_for_ui(module: ModuleEntry, target: str) -> bool:
    return is_executable(module) and module_selectable(module, target)

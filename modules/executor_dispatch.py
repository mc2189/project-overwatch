"""Central dispatch registry for module execution wiring.

New modules register one entry here (via register_executor at the bottom of
executor.py) instead of adding branches to is_runtime_ready, get_runtime_error,
and execute_module separately.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

ExecuteFn = Callable[..., dict[str, Any]]
LoadFn = Callable[[], None]
ReadyFn = Callable[[], bool]
ErrorFn = Callable[[], str | None]

_REGISTRY: dict[str, ModuleDispatchEntry] = {}


@dataclass
class ModuleDispatchEntry:
    """Runtime loader + execute handler for one module."""

    module_id: str
    load: LoadFn
    is_ready: ReadyFn
    get_error: ErrorFn
    execute: ExecuteFn
    unavailable_label: str
    persist_hook: Callable[..., None] | None = field(default=None)


def register_executor(entry: ModuleDispatchEntry) -> None:
    """Register a wired module executor entry."""
    if entry.module_id in _REGISTRY:
        raise ValueError(f"Duplicate executor registration for {entry.module_id}")
    _REGISTRY[entry.module_id] = entry


def get_dispatch_entry(module_id: str) -> ModuleDispatchEntry | None:
    return _REGISTRY.get(module_id)


def list_registered_module_ids() -> tuple[str, ...]:
    return tuple(sorted(_REGISTRY.keys()))


def is_dispatch_ready(module_id: str) -> bool:
    entry = get_dispatch_entry(module_id)
    if entry is None:
        return False
    entry.load()
    return entry.is_ready()


def get_dispatch_error(module_id: str) -> str | None:
    entry = get_dispatch_entry(module_id)
    if entry is None:
        return None
    entry.load()
    return entry.get_error()


def run_dispatch(
    module_id: str,
    target: str,
    options: dict[str, Any],
    db_context: Any,
    authorisation_confirmed: bool,
    case_id: int | None,
    entity_id: int | None,
    run_mode_id: str | None,
    run_mode_label: str | None,
    *,
    make_unavailable_result: Callable[..., dict[str, Any]],
) -> dict[str, Any] | None:
    """Run a registered module. Returns None when module_id is not wired."""
    entry = get_dispatch_entry(module_id)
    if entry is None:
        return None
    entry.load()
    if not entry.is_ready():
        error_message = entry.get_error() or f"{entry.unavailable_label} runtime is not ready."
        return make_unavailable_result(
            module_id,
            summary=f"{entry.unavailable_label} module is not available.",
            error_message=error_message,
        )
    return entry.execute(
        module_id,
        target,
        options,
        db_context,
        authorisation_confirmed,
        case_id,
        entity_id,
        run_mode_id,
        run_mode_label,
    )

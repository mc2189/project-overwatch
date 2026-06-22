"""Standard module run result statuses for Project Overwatch."""

from __future__ import annotations

STATUS_COMPLETED = "completed"
STATUS_COMPLETED_WITH_WARNINGS = "completed_with_warnings"
STATUS_PARTIAL = "partial"
STATUS_BLOCKED = "blocked"
STATUS_ERROR = "error"

SUCCESS_STATUSES: frozenset[str] = frozenset(
    {STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_PARTIAL}
)

PERSISTABLE_STATUSES: frozenset[str] = SUCCESS_STATUSES

STATUS_LABELS: dict[str, str] = {
    STATUS_COMPLETED: "Completed",
    STATUS_COMPLETED_WITH_WARNINGS: "Completed with warnings",
    STATUS_PARTIAL: "Partial",
    STATUS_BLOCKED: "Blocked",
    STATUS_ERROR: "Error",
}


def normalize_run_status(status: str | None) -> str:
    if status in STATUS_LABELS:
        return status
    if status == "completed":
        return STATUS_COMPLETED
    return status or STATUS_ERROR


def is_success_status(status: str | None) -> bool:
    return normalize_run_status(status) in SUCCESS_STATUSES


def should_persist_observation(status: str | None) -> bool:
    return normalize_run_status(status) in PERSISTABLE_STATUSES


def status_label(status: str | None) -> str:
    return STATUS_LABELS.get(normalize_run_status(status), status or "Unknown")


def resolve_collection_status(
    *,
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
    has_core_data: bool = True,
) -> str:
    """Pick a collection status from warnings, errors, and whether useful data was returned."""
    warning_list = [item for item in (warnings or []) if item]
    error_list = [item for item in (errors or []) if item]
    if error_list and not has_core_data:
        return STATUS_ERROR
    if warning_list and not has_core_data:
        return STATUS_PARTIAL
    if warning_list:
        return STATUS_COMPLETED_WITH_WARNINGS
    return STATUS_COMPLETED

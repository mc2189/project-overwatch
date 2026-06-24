"""Baseline snapshot operations — create, replace, and clean-run detection."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from database.db_setup import create_case_baseline, get_latest_case_baseline, update_case_baseline
from utils.baseline_compare import compare_case_to_latest_baseline
from utils.case_memory import build_baseline_snapshot, build_case_memory
from utils.settings_manager import auto_offer_baseline_snapshot, change_meets_sensitivity


def unexpected_baseline_changes(comparison: dict[str, Any]) -> list[dict[str, Any]]:
    """Return new/changed baseline deltas that are not marked expected."""
    rows: list[dict[str, Any]] = []
    for change in comparison.get("changes") or []:
        if change.get("expected"):
            continue
        if change.get("category") not in {"new", "changed"}:
            continue
        importance = (change.get("importance") or change.get("severity") or "info").lower()
        if not change_meets_sensitivity(importance):
            continue
        rows.append(change)
    return rows


def is_baseline_snapshot_ready(comparison: dict[str, Any]) -> bool:
    """True when current case state is clean enough to snapshot as the new baseline."""
    if not comparison.get("has_baseline"):
        return True
    return not unexpected_baseline_changes(comparison)


def baseline_snapshot_summary(comparison: dict[str, Any]) -> str:
    """Human-readable readiness message for baseline snapshot UI."""
    if not comparison.get("has_baseline"):
        return "No baseline yet — snapshot will create your first comparison point."
    unexpected = unexpected_baseline_changes(comparison)
    if not unexpected:
        return "Current state matches your expectations — safe to snapshot as the new baseline."
    return (
        f"{len(unexpected)} unreviewed change(s) since baseline — "
        "snapshot only if you accept the current state."
    )


def default_baseline_name(case_id: int, *, conn: Any, prefix: str = "Lab baseline") -> str:
    memory = build_case_memory(case_id, conn=conn)
    latest = memory.get("latest_baseline") or {}
    if latest.get("name"):
        return str(latest["name"])
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return f"{prefix} {stamp}"


def snapshot_and_replace_baseline(
    case_id: int,
    *,
    name: str | None = None,
    notes: str | None = None,
    source: str = "assessment_workspace",
    conn: Any,
) -> dict[str, Any]:
    """Create the first baseline or replace the latest baseline with current case state."""
    latest = get_latest_case_baseline(case_id, conn=conn)
    resolved_name = (name or "").strip() or default_baseline_name(case_id, conn=conn)
    snapshot = build_baseline_snapshot(case_id, conn=conn, name=resolved_name)
    if latest and latest.get("baseline_id"):
        baseline = update_case_baseline(
            int(latest["baseline_id"]),
            summary=snapshot,
            name=resolved_name,
            notes=notes,
            conn=conn,
        )
        action = "updated"
    else:
        baseline = create_case_baseline(
            case_id,
            name=resolved_name,
            summary=snapshot,
            source=source,
            notes=notes,
            conn=conn,
        )
        action = "created"
    comparison = compare_case_to_latest_baseline(case_id, conn=conn)
    return {
        "action": action,
        "baseline": baseline or {},
        "comparison": comparison,
        "ready": is_baseline_snapshot_ready(comparison),
        "name": resolved_name,
    }


def assess_baseline_snapshot(
    case_id: int,
    *,
    conn: Any,
    latest_results: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Assess whether a baseline snapshot is appropriate after a run."""
    comparison = compare_case_to_latest_baseline(case_id, conn=conn)
    unexpected = unexpected_baseline_changes(comparison)
    run_success = bool(latest_results) and all(result.get("success") for result in latest_results)
    ready = is_baseline_snapshot_ready(comparison)
    offer = auto_offer_baseline_snapshot() and run_success and ready
    return {
        "comparison": comparison,
        "ready": ready,
        "offer_snapshot": offer,
        "unexpected_count": len(unexpected),
        "summary_text": baseline_snapshot_summary(comparison),
        "run_success": run_success,
    }

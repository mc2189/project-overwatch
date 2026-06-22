"""Persistence layer for batch queue items and run history."""

from __future__ import annotations

from typing import Any

from database.db_setup import (
    batch_queue_item_counts,
    create_batch_queue_run,
    get_db_conn,
    list_batch_queue_items,
    list_batch_queue_runs,
    list_cases,
    sync_batch_queue_items,
)
from utils.batch_queue import SESSION_QUEUE_KEY, set_case_queue


def load_batch_queue(case_id: int) -> list[dict[str, Any]]:
    """Load batch queue items for a case from the database."""
    conn = get_db_conn()
    try:
        return list_batch_queue_items(case_id, conn=conn)
    finally:
        conn.close()


def save_batch_queue(case_id: int, items: list[dict[str, Any]]) -> None:
    """Persist batch queue items for a case."""
    conn = get_db_conn()
    try:
        sync_batch_queue_items(case_id, items, conn=conn)
    finally:
        conn.close()


def migrate_session_batch_queue(case_id: int, session_state: Any) -> None:
    """One-time migration of session-state queue items into SQLite."""
    migrated_cases: list[int] = session_state.setdefault("batch_queue_db_migrated_cases", [])
    if case_id in migrated_cases:
        return

    legacy_store = session_state.get(SESSION_QUEUE_KEY) or {}
    legacy_items = legacy_store.get(str(case_id)) or legacy_store.get(case_id) or []

    conn = get_db_conn()
    try:
        existing = list_batch_queue_items(case_id, conn=conn)
        if legacy_items and not existing:
            sync_batch_queue_items(case_id, legacy_items, conn=conn)
        elif legacy_items and existing:
            merged = list(existing)
            existing_keys = {
                (item["entity_id"], item["module_id"], item.get("status", "queued"))
                for item in existing
            }
            for item in legacy_items:
                key = (item["entity_id"], item["module_id"], item.get("status", "queued"))
                if key not in existing_keys and item.get("status", "queued") == "queued":
                    merged.append(item)
            sync_batch_queue_items(case_id, merged, conn=conn)
    finally:
        conn.close()

    if legacy_items:
        session_state[SESSION_QUEUE_KEY] = set_case_queue(legacy_store, case_id, [])
    migrated_cases.append(case_id)


def move_queue_item(
    items: list[dict[str, Any]],
    queue_id: str,
    direction: str,
) -> list[dict[str, Any]]:
    """Move a queue item up or down by swapping position values."""
    ordered = sorted(items, key=lambda item: (item.get("position", 0), item.get("created_at", "")))
    index = next((idx for idx, item in enumerate(ordered) if item.get("queue_id") == queue_id), None)
    if index is None:
        return items

    swap_index = index - 1 if direction == "up" else index + 1
    if swap_index < 0 or swap_index >= len(ordered):
        return items

    ordered[index], ordered[swap_index] = ordered[swap_index], ordered[index]
    return [{**item, "position": position} for position, item in enumerate(ordered)]


def record_batch_queue_run(
    case_id: int,
    results: list[dict[str, Any]],
    *,
    started_at: str | None = None,
) -> dict[str, Any]:
    """Persist a batch queue run summary from execution results."""
    processed = len(results)
    completed = sum(1 for row in results if row["queue_item"].get("status") == "completed")
    warnings = sum(
        1 for row in results if row["queue_item"].get("status") == "completed_with_warnings"
    )
    failed = sum(
        1
        for row in results
        if row["queue_item"].get("status") in {"blocked", "error"}
    )
    lines = [
        f"Processed {processed} item(s): {completed} completed, {warnings} with warnings, {failed} blocked/error.",
    ]
    for row in results[:20]:
        item = row["queue_item"]
        lines.append(
            f"- {item.get('entity_value')} · {item.get('module_display_name')} · "
            f"{item.get('status')}: {item.get('summary') or '-'}"
        )
    if processed > 20:
        lines.append(f"- … and {processed - 20} more item(s)")

    conn = get_db_conn()
    try:
        return create_batch_queue_run(
            case_id,
            items_processed=processed,
            items_completed=completed,
            items_warnings=warnings,
            items_failed=failed,
            run_summary="\n".join(lines),
            started_at=started_at,
            conn=conn,
        )
    finally:
        conn.close()


def other_case_queue_summary(current_case_id: int) -> list[str]:
    """Return summary lines for batch queues in other cases."""
    conn = get_db_conn()
    try:
        counts = batch_queue_item_counts(conn=conn)
        cases = {case["id"]: case for case in list_cases(conn=conn)}
    finally:
        conn.close()

    lines: list[str] = []
    for case_id, stats in sorted(counts.items()):
        if case_id == current_case_id:
            continue
        case = cases.get(case_id)
        name = case.get("name") if case else f"Case #{case_id}"
        lines.append(f"{name} (#{case_id}): {stats['queued']} queued / {stats['total']} total")
    return lines


def load_recent_batch_runs(case_id: int, limit: int = 5) -> list[dict[str, Any]]:
    conn = get_db_conn()
    try:
        return list_batch_queue_runs(case_id, limit=limit, conn=conn)
    finally:
        conn.close()

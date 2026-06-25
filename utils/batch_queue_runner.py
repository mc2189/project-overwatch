"""Shared batch queue execution helpers for CLI and background worker."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from database.db_setup import batch_queue_item_counts, get_db_conn
from utils.batch_queue import execute_queue_items, sort_queue_items
from utils.batch_queue_store import load_batch_queue, record_batch_queue_run, save_batch_queue
from utils.batch_queue_summary import summarize_batch_queue
from utils.operating_context import CLIENT_ENGAGEMENT, PERSONAL_LAB, PASSIVE_RESEARCH


def select_queue_ids(items: list[dict[str, Any]], mode: str) -> list[str]:
    """Return queue IDs eligible for execution under the requested mode."""
    queued = [item for item in items if item.get("status") == "queued"]
    if mode == "all":
        return [item["queue_id"] for item in queued if item.get("queue_id")]
    if mode == "selected":
        return [item["queue_id"] for item in queued if item.get("queue_id")]
    if mode == "active":
        return [
            item["queue_id"]
            for item in queued
            if item.get("queue_id") and item.get("mode") == "active"
        ]
    if mode == "passive":
        return [
            item["queue_id"]
            for item in queued
            if item.get("queue_id") and item.get("mode") == "passive"
        ]
    return []


def cases_with_queued_items(*, passive_only: bool = True) -> list[int]:
    """Return case IDs that currently have queued batch items."""
    conn = get_db_conn()
    try:
        counts = batch_queue_item_counts(conn=conn)
    finally:
        conn.close()
    case_ids: list[int] = []
    for case_id, stats in counts.items():
        if passive_only and stats.get("queued", 0) <= 0:
            continue
        if not passive_only and stats.get("total", 0) <= 0:
            continue
        case_ids.append(int(case_id))
    return sorted(case_ids)


def run_batch_queue_for_case(
    case_id: int,
    *,
    mode: str = "passive",
    operating_context: str = PERSONAL_LAB,
    authorisation_confirmed: bool = False,
    personal_lab_confirmed: bool = False,
    delay_seconds: float | None = None,
    stop_after_first: bool = False,
    dry_run: bool = False,
) -> dict[str, Any]:
    """Execute queued batch items for one case and return a run summary."""
    from utils.batch_queue import DEFAULT_COURTESY_DELAY_SECONDS

    items = sort_queue_items(load_batch_queue(case_id))
    summary_before = summarize_batch_queue(items)
    queue_ids = select_queue_ids(items, mode)

    result: dict[str, Any] = {
        "case_id": case_id,
        "mode": mode,
        "dry_run": dry_run,
        "selected_count": len(queue_ids),
        "before": summary_before,
        "processed": 0,
        "completed": 0,
        "warnings": 0,
        "failed": 0,
        "messages": [],
        "results": [],
    }

    if not queue_ids:
        result["messages"].append("No queued items to run.")
        return result

    needs_auth = any(
        item.get("mode") == "active"
        for item in items
        if item.get("queue_id") in queue_ids
    )
    if needs_auth and operating_context == PASSIVE_RESEARCH:
        result["messages"].append("Active queue items require Personal Lab or Client Engagement context.")
        result["exit_code"] = 2
        return result
    if needs_auth and not (authorisation_confirmed or personal_lab_confirmed):
        result["messages"].append(
            "Active queue items require authorisation or Personal Lab confirmation."
        )
        result["exit_code"] = 2
        return result

    if dry_run:
        result["messages"].append(f"Dry run — would execute {len(queue_ids)} item(s).")
        result["preview"] = [
            {
                "entity_value": item.get("entity_value"),
                "module_display_name": item.get("module_display_name"),
                "mode": item.get("mode"),
            }
            for item in items
            if item.get("queue_id") in queue_ids
        ]
        return result

    started_at = datetime.now(timezone.utc).isoformat()
    conn = get_db_conn()
    try:
        updated, results = execute_queue_items(
            case_id,
            items,
            queue_ids,
            db_conn=conn,
            authorisation_confirmed=authorisation_confirmed,
            operating_context=operating_context,
            personal_lab_confirmed=personal_lab_confirmed,
            delay_seconds=delay_seconds if delay_seconds is not None else DEFAULT_COURTESY_DELAY_SECONDS,
            stop_after_first=stop_after_first,
        )
    finally:
        conn.close()

    save_batch_queue(case_id, updated)
    if results:
        record_batch_queue_run(case_id, results, started_at=started_at)

    completed = sum(1 for row in results if row["queue_item"].get("status") == "completed")
    warnings = sum(
        1 for row in results if row["queue_item"].get("status") == "completed_with_warnings"
    )
    failed = sum(
        1
        for row in results
        if row["queue_item"].get("status") in {"blocked", "error"}
    )
    result.update(
        {
            "processed": len(results),
            "completed": completed,
            "warnings": warnings,
            "failed": failed,
            "results": results,
            "after": summarize_batch_queue(sort_queue_items(load_batch_queue(case_id))),
            "exit_code": 0 if failed == 0 else 1,
        }
    )
    result["messages"].append(
        f"Processed {len(results)} item(s): {completed} completed, "
        f"{warnings} with warnings, {failed} blocked/error."
    )
    return result


def resolve_case_ids(
    *,
    case_ids: list[int] | None = None,
    all_cases_with_queue: bool = False,
    passive_only: bool = True,
) -> list[int]:
    if case_ids:
        return sorted({int(case_id) for case_id in case_ids})
    if all_cases_with_queue:
        return cases_with_queued_items(passive_only=passive_only)
    return []

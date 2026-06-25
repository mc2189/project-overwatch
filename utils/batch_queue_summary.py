"""Summaries for persisted batch queue items."""

from __future__ import annotations

from typing import Any


def summarize_batch_queue(items: list[dict[str, Any]]) -> dict[str, Any]:
    """Return counts and preview rows for queue UI and CLI status."""
    queued = [item for item in items if item.get("status") == "queued"]
    passive_queued = [item for item in queued if item.get("mode") == "passive"]
    active_queued = [item for item in queued if item.get("mode") == "active"]
    completed = sum(
        1 for item in items if item.get("status") in {"completed", "completed_with_warnings"}
    )
    failed = sum(1 for item in items if item.get("status") in {"blocked", "error"})
    running = sum(1 for item in items if item.get("status") == "running")
    return {
        "total": len(items),
        "queued": len(queued),
        "passive_queued": len(passive_queued),
        "active_queued": len(active_queued),
        "completed": completed,
        "failed": failed,
        "running": running,
        "preview_queued": queued[:8],
        "passive_queue_ids": [
            item["queue_id"] for item in passive_queued if item.get("queue_id")
        ],
        "active_queue_ids": [
            item["queue_id"] for item in active_queued if item.get("queue_id")
        ],
    }

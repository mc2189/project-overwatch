"""Autopilot queue model, deduplication, and stop conditions."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from utils.assessment_playbooks import AssessmentPlaybook, playbook_limits

AUTOPILOT_STATUSES: tuple[str, ...] = (
    "proposed",
    "queued",
    "running",
    "completed",
    "blocked",
    "skipped",
    "failed",
)

TERMINAL_AUTOPILOT_STATUSES: frozenset[str] = frozenset(
    {"completed", "blocked", "skipped", "failed"}
)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def autopilot_pair_key(
    target: str | None,
    module_id: str | None,
    playbook_id: str | None,
    *,
    action_type: str | None = None,
) -> tuple[str, str, str, str]:
    return (
        (target or "").strip().lower(),
        module_id or "",
        playbook_id or "",
        action_type or "",
    )


def build_autopilot_item(action: dict[str, Any], *, playbook_id: str | None = None) -> dict[str, Any]:
    """Convert a proposed autopilot action into a queue item."""
    return {
        "autopilot_id": str(uuid.uuid4()),
        "playbook_id": playbook_id or action.get("playbook_id"),
        "parent_action_id": action.get("parent_action_id"),
        "source_module_id": action.get("source_module_id") or action.get("source_result_id"),
        "source_result_id": action.get("source_result_id"),
        "target": action.get("target"),
        "module_id": action.get("module_id"),
        "title": action.get("title"),
        "reason": action.get("reason"),
        "why_detail": action.get("why_detail") or action.get("reason"),
        "priority": action.get("priority") or "medium",
        "action_type": action.get("autopilot_action_type") or action.get("action_type"),
        "is_passive": bool(action.get("is_passive")),
        "is_active": bool(action.get("is_active")),
        "requires_confirmation": bool(action.get("requires_confirmation", True)),
        "blocked_reason": action.get("blocked_reason"),
        "status": action.get("autopilot_status") or "proposed",
        "created_at": _now_iso(),
        "completed_at": None,
        "batch_queue_id": None,
        "source": "playbook/autopilot",
    }


def is_duplicate_autopilot_item(
    items: list[dict[str, Any]],
    action: dict[str, Any],
    *,
    playbook_id: str | None = None,
) -> bool:
    """Prevent duplicate target/module/playbook pairs in non-terminal states."""
    key = autopilot_pair_key(
        action.get("target"),
        action.get("module_id"),
        playbook_id or action.get("playbook_id"),
        action_type=action.get("autopilot_action_type") or action.get("action_type"),
    )
    for item in items:
        existing = autopilot_pair_key(
            item.get("target"),
            item.get("module_id"),
            item.get("playbook_id"),
            action_type=item.get("action_type"),
        )
        if existing == key and item.get("status") in {"proposed", "queued", "running", "completed"}:
            return True
    return False


def merge_proposed_actions(
    existing: list[dict[str, Any]],
    proposed: list[dict[str, Any]],
    *,
    playbook_id: str | None = None,
) -> tuple[list[dict[str, Any]], list[str]]:
    """Add proposed actions, skipping duplicates. Returns updated list and skip reasons."""
    updated = list(existing)
    skipped: list[str] = []
    for action in proposed:
        if is_duplicate_autopilot_item(updated, action, playbook_id=playbook_id):
            skipped.append(
                f"{action.get('title')} ({action.get('module_id') or action.get('action_type')}) already queued"
            )
            continue
        updated.append(build_autopilot_item(action, playbook_id=playbook_id))
    return updated, skipped


def count_autopilot_usage(items: list[dict[str, Any]]) -> dict[str, int]:
    counts = {
        "total": 0,
        "active": 0,
        "passive": 0,
        "completed": 0,
        "blocked": 0,
        "skipped": 0,
        "failed": 0,
        "failures": 0,
    }
    for item in items:
        if item.get("status") in {"proposed"}:
            continue
        counts["total"] += 1
        if item.get("is_active"):
            counts["active"] += 1
        elif item.get("is_passive"):
            counts["passive"] += 1
        status = item.get("status")
        if status == "completed":
            counts["completed"] += 1
        elif status == "blocked":
            counts["blocked"] += 1
        elif status == "skipped":
            counts["skipped"] += 1
        elif status == "failed":
            counts["failed"] += 1
            counts["failures"] += 1
    return counts


def evaluate_stop_conditions(
    items: list[dict[str, Any]],
    *,
    playbook: AssessmentPlaybook | None,
    settings: dict[str, Any] | None = None,
    user_stopped: bool = False,
    emergency_stop_active: bool = False,
) -> tuple[bool, str | None]:
    """Return (should_stop, reason)."""
    if user_stopped:
        return True, "Autopilot stopped by analyst."
    if emergency_stop_active:
        return True, "Emergency stop is active — autopilot paused."

    limits = playbook_limits(playbook, settings=settings)
    usage = count_autopilot_usage(items)

    if usage["total"] >= limits["max_steps"]:
        return True, f"Playbook step limit reached ({limits['max_steps']})."
    if usage["active"] >= limits["max_active"]:
        return True, f"Active check limit reached ({limits['max_active']})."
    if usage["passive"] >= limits["max_passive"]:
        return True, f"Passive check limit reached ({limits['max_passive']})."
    if usage["failures"] >= limits["max_failures"]:
        return True, f"Failure limit reached ({limits['max_failures']}) — review before continuing."

    pending = [item for item in items if item.get("status") in {"proposed", "queued"}]
    if pending and all(item.get("status") == "blocked" or item.get("blocked_reason") for item in pending):
        return True, "Only blocked actions remain — autopilot paused."

    return False, None


def items_ready_to_queue(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Session items eligible to copy into the persisted Batch Queue.

    Includes both ``proposed`` and session-``queued`` rows that have not yet
    been linked to a batch queue id (``update_autopilot_from_results`` promotes
    proposed → queued before auto-run calls ``queue_autopilot_to_batch``).
    """
    return [
        item
        for item in items
        if item.get("status") in {"proposed", "queued"}
        and not item.get("batch_queue_id")
        and not item.get("blocked_reason")
        and item.get("module_id")
        and item.get("action_type") in {"add_to_queue", "run_module"}
    ]


def items_ready_for_passive_auto_run(
    items: list[dict[str, Any]],
    *,
    requires_confirmation: bool = False,
) -> list[dict[str, Any]]:
    return [
        item
        for item in items
        if item.get("status") in {"proposed", "queued"}
        and item.get("is_passive")
        and not item.get("blocked_reason")
        and item.get("module_id")
        and (not item.get("requires_confirmation") or not requires_confirmation)
    ]


def mark_autopilot_item(
    items: list[dict[str, Any]],
    autopilot_id: str,
    *,
    status: str,
    blocked_reason: str | None = None,
    batch_queue_id: str | None = None,
) -> list[dict[str, Any]]:
    updated: list[dict[str, Any]] = []
    for item in items:
        if item.get("autopilot_id") != autopilot_id:
            updated.append(item)
            continue
        new_item = dict(item)
        new_item["status"] = status
        if blocked_reason is not None:
            new_item["blocked_reason"] = blocked_reason
        if batch_queue_id is not None:
            new_item["batch_queue_id"] = batch_queue_id
        if status in TERMINAL_AUTOPILOT_STATUSES:
            new_item["completed_at"] = _now_iso()
        updated.append(new_item)
    return updated


def autopilot_item_to_batch_metadata(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "source": item.get("source") or "playbook/autopilot",
        "playbook_id": item.get("playbook_id"),
        "autopilot_id": item.get("autopilot_id"),
        "parent_action_id": item.get("parent_action_id"),
        "source_module_id": item.get("source_module_id"),
        "reason": item.get("reason"),
        "why_detail": item.get("why_detail"),
        "requires_confirmation": item.get("requires_confirmation"),
    }

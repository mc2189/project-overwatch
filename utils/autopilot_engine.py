"""Assessment autopilot orchestration — modes, queue build, and passive execution."""

from __future__ import annotations

import json
from typing import Any

from database.db_setup import create_or_get_entity, get_db_conn, infer_entity_type, list_operations
from utils.assessment_playbooks import (
    MODE_ASSISTED,
    MODE_MANUAL,
    MODE_PASSIVE_AUTOPILOT,
    MODE_PERSONAL_LAB_AUTOPILOT,
    AssessmentPlaybook,
    get_playbook,
    mode_allows_auto_active,
    mode_allows_auto_passive,
    playbook_for_goal,
)
from utils.autopilot_queue import (
    autopilot_item_to_batch_metadata,
    evaluate_stop_conditions,
    items_ready_for_passive_auto_run,
    items_ready_to_queue,
    mark_autopilot_item,
    merge_proposed_actions,
)
from utils.autopilot_rules import propose_followup_actions
from utils.batch_queue import add_queue_item, execute_queue_items, sort_queue_items
from utils.batch_queue_store import load_batch_queue, save_batch_queue
from utils.next_actions import finalize_actions
from utils.settings_manager import autopilot_settings

SESSION_AUTOPILOT_QUEUE_KEY = "autopilot_queue_by_case"
SESSION_AUTOPILOT_STOP_KEY = "autopilot_stopped"
SESSION_AUTOPILOT_CONFIRMED_KEY = "autopilot_lab_confirmed"
SESSION_AUTOPILOT_SUMMARY_KEY = "autopilot_summary_by_case"
SESSION_ASSESSMENT_MODE_KEY = "assessment_mode"
SESSION_PLAYBOOK_KEY = "autopilot_playbook_id"


def get_case_autopilot_queue(session_state: dict[str, Any], case_id: int) -> list[dict[str, Any]]:
    store = session_state.get(SESSION_AUTOPILOT_QUEUE_KEY) or {}
    return list(store.get(str(case_id), []))


def set_case_autopilot_queue(
    session_state: dict[str, Any],
    case_id: int,
    items: list[dict[str, Any]],
) -> None:
    store = dict(session_state.get(SESSION_AUTOPILOT_QUEUE_KEY) or {})
    store[str(case_id)] = items
    session_state[SESSION_AUTOPILOT_QUEUE_KEY] = store


def build_autopilot_summary(
    *,
    playbook: AssessmentPlaybook | None,
    items: list[dict[str, Any]],
    latest_results: list[dict[str, Any]],
    stop_reason: str | None = None,
) -> dict[str, Any]:
    modules_run = sorted(
        {
            result.get("module_id")
            for result in latest_results
            if result.get("module_id") and result.get("success")
        }
    )
    targets = sorted({item.get("target") for item in items if item.get("target")})
    completed = sum(1 for item in items if item.get("status") == "completed")
    blocked = sum(1 for item in items if item.get("status") == "blocked")
    skipped = sum(1 for item in items if item.get("status") == "skipped")
    proposed = sum(1 for item in items if item.get("status") == "proposed")
    severities = []
    for result in latest_results:
        for finding in result.get("interpreter_findings") or []:
            severities.append((finding.get("severity") or "info").lower())
    highest = None
    rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    for severity in severities:
        if highest is None or rank.get(severity, 0) > rank.get(highest, 0):
            highest = severity
    manual_next = next(
        (
            item.get("title")
            for item in items
            if item.get("status") == "proposed" and item.get("requires_confirmation")
        ),
        "Review proposed checks and confirm next module manually.",
    )
    return {
        "playbook_id": playbook.playbook_id if playbook else None,
        "playbook_name": playbook.display_name if playbook else "Custom",
        "targets_assessed": targets,
        "modules_run": modules_run,
        "completed": completed,
        "blocked": blocked,
        "skipped": skipped,
        "proposed": proposed,
        "findings_count": sum(len(result.get("interpreter_findings") or []) for result in latest_results),
        "highest_severity": highest,
        "stop_reason": stop_reason,
        "next_manual_action": manual_next,
    }


def enrich_proposed_actions(
    actions: list[dict[str, Any]],
    *,
    case_id: int,
    operating_context: str,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
    conn: Any | None = None,
) -> list[dict[str, Any]]:
    finalized = finalize_actions(
        actions,
        case_id=case_id,
        operating_context=operating_context,
        personal_lab_confirmed=personal_lab_confirmed,
        authorisation_confirmed=authorisation_confirmed,
        conn=conn,
    )
    enriched: list[dict[str, Any]] = []
    for action in finalized:
        item = dict(action)
        if not action.get("enabled") and action.get("blocked_reason"):
            item["blocked_reason"] = action["blocked_reason"]
            item["autopilot_status"] = "blocked"
        enriched.append(item)
    return enriched


def update_autopilot_from_results(
    *,
    case_id: int,
    target: str,
    latest_results: list[dict[str, Any]],
    session_state: dict[str, Any],
    operating_context: str,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
    goal_id: str | None = None,
    emergency_stop_active: bool = False,
    conn: Any | None = None,
) -> dict[str, Any]:
    """Run follow-up rules and update autopilot queue based on assessment mode."""
    mode = session_state.get(SESSION_ASSESSMENT_MODE_KEY) or autopilot_settings()["default_mode"]
    playbook_id = session_state.get(SESSION_PLAYBOOK_KEY) or (playbook_for_goal(goal_id).playbook_id if playbook_for_goal(goal_id) else None)
    playbook = get_playbook(playbook_id)
    settings = autopilot_settings()

    if mode == MODE_MANUAL:
        proposed = propose_followup_actions(latest_results=latest_results, target=target, playbook=playbook)
        proposed = enrich_proposed_actions(
            proposed,
            case_id=case_id,
            operating_context=operating_context,
            personal_lab_confirmed=personal_lab_confirmed,
            authorisation_confirmed=authorisation_confirmed,
            conn=conn,
        )
        return {
            "mode": mode,
            "playbook": playbook,
            "proposed": proposed,
            "queue": get_case_autopilot_queue(session_state, case_id),
            "skipped": [],
            "stop": False,
            "stop_reason": None,
            "summary": build_autopilot_summary(
                playbook=playbook,
                items=get_case_autopilot_queue(session_state, case_id),
                latest_results=latest_results,
            ),
        }

    existing = get_case_autopilot_queue(session_state, case_id)
    proposed_raw = propose_followup_actions(latest_results=latest_results, target=target, playbook=playbook)
    proposed = enrich_proposed_actions(
        proposed_raw,
        case_id=case_id,
        operating_context=operating_context,
        personal_lab_confirmed=personal_lab_confirmed,
        authorisation_confirmed=authorisation_confirmed,
        conn=conn,
    )
    merged, skipped = merge_proposed_actions(existing, proposed, playbook_id=playbook_id)

    user_stopped = bool(session_state.get(SESSION_AUTOPILOT_STOP_KEY))
    should_stop, stop_reason = evaluate_stop_conditions(
        merged,
        playbook=playbook,
        settings=settings,
        user_stopped=user_stopped,
        emergency_stop_active=emergency_stop_active,
    )

    if mode in {MODE_ASSISTED, MODE_PASSIVE_AUTOPILOT, MODE_PERSONAL_LAB_AUTOPILOT} and not should_stop:
        for item in merged:
            if item.get("status") != "proposed" or item.get("blocked_reason"):
                continue
            if item.get("action_type") in {"add_to_queue", "run_module"}:
                item["status"] = "queued"

    set_case_autopilot_queue(session_state, case_id, merged)
    summary = build_autopilot_summary(
        playbook=playbook,
        items=merged,
        latest_results=latest_results,
        stop_reason=stop_reason,
    )
    session_state.setdefault(SESSION_AUTOPILOT_SUMMARY_KEY, {})[str(case_id)] = summary

    auto_run_results: list[dict[str, Any]] = []
    if mode == MODE_PASSIVE_AUTOPILOT and not should_stop and not user_stopped:
        auto_run_results = run_autopilot_passive_queue(
            case_id=case_id,
            session_state=session_state,
            operating_context=operating_context,
            personal_lab_confirmed=personal_lab_confirmed,
            authorisation_confirmed=authorisation_confirmed,
        )
    elif mode == MODE_PERSONAL_LAB_AUTOPILOT and not should_stop and not user_stopped:
        if mode_allows_auto_active(
            mode,
            personal_lab_confirmed=personal_lab_confirmed,
            autopilot_confirmed=bool(session_state.get(SESSION_AUTOPILOT_CONFIRMED_KEY)),
        ):
            auto_run_results = run_autopilot_confirmed_queue(
                case_id=case_id,
                session_state=session_state,
                operating_context=operating_context,
                personal_lab_confirmed=personal_lab_confirmed,
                authorisation_confirmed=authorisation_confirmed,
                include_active=True,
            )

    return {
        "mode": mode,
        "playbook": playbook,
        "proposed": proposed,
        "queue": merged,
        "skipped": skipped,
        "stop": should_stop,
        "stop_reason": stop_reason,
        "summary": summary,
        "auto_run_results": auto_run_results,
    }


def queue_autopilot_to_batch(
    case_id: int,
    session_state: dict[str, Any],
    *,
    operating_context: str,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
) -> tuple[list[dict[str, Any]], list[str], list[dict[str, Any]]]:
    """Move queued autopilot module actions into the existing Batch Queue."""
    autopilot_items = get_case_autopilot_queue(session_state, case_id)
    ready = items_ready_to_queue(autopilot_items)
    messages: list[str] = []
    batch_items = load_batch_queue(case_id)
    conn = get_db_conn()
    try:
        operations = list_operations(case_id, conn=conn)
        for item in ready:
            target = (item.get("target") or "").strip()
            module_id = item.get("module_id")
            if not target or not module_id:
                continue
            if item.get("is_active") and item.get("requires_confirmation"):
                messages.append(f"Skipped active check {module_id} — requires run panel confirmation.")
                autopilot_items = mark_autopilot_item(
                    autopilot_items,
                    item["autopilot_id"],
                    status="blocked",
                    blocked_reason="Active check requires explicit confirmation in the run panel.",
                )
                continue
            entity = create_or_get_entity(
                case_id,
                infer_entity_type(target),
                target,
                label=target,
                source="autopilot",
                conn=conn,
            )
            batch_items, added, reason = add_queue_item(
                batch_items,
                case_id,
                entity,
                module_id,
                operations=operations,
            )
            if added:
                meta = autopilot_item_to_batch_metadata(item)
                added["summary"] = json.dumps(meta, ensure_ascii=False)[:500]
                added["autopilot_metadata"] = meta
                autopilot_items = mark_autopilot_item(
                    autopilot_items,
                    item["autopilot_id"],
                    status="queued",
                    batch_queue_id=added["queue_id"],
                )
                messages.append(f"Queued {module_id} for {target}.")
            elif reason:
                autopilot_items = mark_autopilot_item(
                    autopilot_items,
                    item["autopilot_id"],
                    status="skipped",
                    blocked_reason=reason,
                )
                messages.append(reason)
        save_batch_queue(case_id, sort_queue_items(batch_items))
    finally:
        conn.close()
    set_case_autopilot_queue(session_state, case_id, autopilot_items)
    return autopilot_items, messages, batch_items


def run_autopilot_passive_queue(
    *,
    case_id: int,
    session_state: dict[str, Any],
    operating_context: str,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
) -> list[dict[str, Any]]:
    """Queue and execute passive autopilot items only."""
    _, messages, batch_items = queue_autopilot_to_batch(
        case_id,
        session_state,
        operating_context=operating_context,
        personal_lab_confirmed=personal_lab_confirmed,
        authorisation_confirmed=authorisation_confirmed,
    )
    passive_ids = [
        item["queue_id"]
        for item in batch_items
        if item.get("status") == "queued" and item.get("mode") == "passive"
    ]
    if not passive_ids:
        return [{"messages": messages}]
    conn = get_db_conn()
    try:
        updated, results = execute_queue_items(
            case_id,
            batch_items,
            passive_ids,
            db_conn=conn,
            authorisation_confirmed=authorisation_confirmed,
            operating_context=operating_context,
            personal_lab_confirmed=personal_lab_confirmed,
            run_mode_label="Autopilot (passive)",
        )
        save_batch_queue(case_id, sort_queue_items(updated))
        autopilot_items = get_case_autopilot_queue(session_state, case_id)
        for row in results:
            meta = (row.get("queue_item") or {}).get("autopilot_metadata") or {}
            autopilot_id = meta.get("autopilot_id")
            if not autopilot_id:
                continue
            result = row.get("result") or {}
            status = "completed" if result.get("success") else "failed"
            autopilot_items = mark_autopilot_item(autopilot_items, autopilot_id, status=status)
        set_case_autopilot_queue(session_state, case_id, autopilot_items)
        return results
    finally:
        conn.close()


def run_autopilot_confirmed_queue(
    *,
    case_id: int,
    session_state: dict[str, Any],
    operating_context: str,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
    include_active: bool = False,
) -> list[dict[str, Any]]:
    """Execute queued batch items after Personal Lab autopilot confirmation."""
    batch_items = load_batch_queue(case_id)
    queued_ids = [
        item["queue_id"]
        for item in batch_items
        if item.get("status") == "queued"
        and item.get("compatibility_status") == "compatible"
        and (include_active or item.get("mode") == "passive")
    ]
    if not queued_ids:
        return []
    conn = get_db_conn()
    try:
        updated, results = execute_queue_items(
            case_id,
            batch_items,
            queued_ids,
            db_conn=conn,
            authorisation_confirmed=authorisation_confirmed,
            operating_context=operating_context,
            personal_lab_confirmed=personal_lab_confirmed,
            run_mode_label="Autopilot (Personal Lab)",
        )
        save_batch_queue(case_id, sort_queue_items(updated))
        return results
    finally:
        conn.close()


def stop_autopilot(session_state: dict[str, Any]) -> None:
    session_state[SESSION_AUTOPILOT_STOP_KEY] = True


def resume_autopilot(session_state: dict[str, Any]) -> None:
    session_state[SESSION_AUTOPILOT_STOP_KEY] = False

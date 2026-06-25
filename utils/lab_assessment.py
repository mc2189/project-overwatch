"""Unified Personal Lab assessment orchestration."""

from __future__ import annotations

from typing import Any

from database.db_setup import get_db_conn
from utils.autopilot_engine import update_autopilot_from_results
from utils.baseline_ops import maybe_auto_snapshot_after_run
from utils.case_memory_refresh import store_case_memory_refresh
from utils.workspace_runner import execute_workspace_modules


def _collect_autopilot_results(auto_run_results: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    collected: list[dict[str, Any]] = []
    for row in auto_run_results or []:
        if not isinstance(row, dict):
            continue
        result = row.get("result")
        if isinstance(result, dict) and result.get("module_id"):
            collected.append(result)
    return collected


def finalize_lab_assessment(
    *,
    case_id: int,
    target: str,
    goal_id: str | None,
    primary_results: list[dict[str, Any]],
    session_state: dict[str, Any],
    operating_context: str,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
    emergency_stop_active: bool = False,
    conn: Any,
) -> dict[str, Any]:
    """Run autopilot follow-ups and optional auto-snapshot after primary module results."""
    update = update_autopilot_from_results(
        case_id=case_id,
        target=target.strip(),
        latest_results=primary_results,
        session_state=session_state,
        operating_context=operating_context,
        personal_lab_confirmed=personal_lab_confirmed,
        authorisation_confirmed=authorisation_confirmed,
        goal_id=goal_id,
        emergency_stop_active=emergency_stop_active,
        conn=conn,
    )
    all_results = list(primary_results) + _collect_autopilot_results(update.get("auto_run_results"))
    snapshot = maybe_auto_snapshot_after_run(case_id, latest_results=all_results, conn=conn)

    messages: list[str] = []
    autopilot_results = _collect_autopilot_results(update.get("auto_run_results"))
    if autopilot_results:
        messages.append(f"Autopilot completed {len(autopilot_results)} follow-up check(s).")
    if snapshot:
        verb = "created" if snapshot.get("action") == "created" else "updated"
        messages.append(f"Baseline auto-{verb}: {snapshot.get('name')}.")

    memory_refresh = store_case_memory_refresh(
        session_state,
        case_id,
        conn=conn,
        scroll_after=True,
    )

    return {
        "results": all_results,
        "update": update,
        "snapshot": snapshot,
        "memory_refresh": memory_refresh,
        "message": " ".join(messages) if messages else None,
    }


def run_lab_assessment_session(
    *,
    current_case: dict,
    target: str,
    selected_ids: list[str],
    operating_context: str,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
    run_mode_id: str,
    goal_id: str | None,
    session_state: dict[str, Any],
    emergency_stop_active: bool = False,
    pcap_session_key: str = "pcap_upload",
    file_metadata_session_key: str = "file_metadata_uploads",
) -> dict[str, Any]:
    """Run primary checks, autopilot follow-ups, and optional auto-snapshot."""
    session_state["latest_run_results"] = []
    primary_results = execute_workspace_modules(
        current_case=current_case,
        target=target,
        selected_ids=selected_ids,
        operating_context=operating_context,
        personal_lab_confirmed=personal_lab_confirmed,
        authorisation_confirmed=authorisation_confirmed,
        run_mode_id=run_mode_id,
        session_state=session_state,
        pcap_session_key=pcap_session_key,
        file_metadata_session_key=file_metadata_session_key,
    )
    session_state["latest_run_results"] = primary_results

    conn = get_db_conn()
    try:
        return finalize_lab_assessment(
            case_id=int(current_case["id"]),
            target=target,
            goal_id=goal_id,
            primary_results=primary_results,
            session_state=session_state,
            operating_context=operating_context,
            personal_lab_confirmed=personal_lab_confirmed,
            authorisation_confirmed=authorisation_confirmed,
            emergency_stop_active=emergency_stop_active,
            conn=conn,
        )
    finally:
        conn.close()


def apply_post_run_hooks(
    *,
    case_id: int,
    latest_results: list[dict[str, Any]],
    session_state: dict[str, Any] | None = None,
    conn: Any | None = None,
) -> dict[str, Any] | None:
    """Apply optional post-run automation such as auto-snapshot."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        snapshot = maybe_auto_snapshot_after_run(case_id, latest_results=latest_results, conn=conn)
        if session_state is not None:
            store_case_memory_refresh(
                session_state,
                case_id,
                conn=conn,
                scroll_after=bool(snapshot),
            )
        return snapshot
    finally:
        if own_conn:
            conn.close()

"""Post-run case memory refresh hints for the Assessment Workspace."""

from __future__ import annotations

from typing import Any

from utils.baseline_compare import compare_case_to_latest_baseline
from utils.baseline_ops import unexpected_baseline_changes
from utils.case_memory import build_case_memory

CASE_MEMORY_REFRESH_SESSION_KEY = "case_memory_refresh_by_case"
WORKSPACE_SCROLL_TO_CASE_MEMORY_KEY = "workspace_scroll_to_case_memory"
CASE_MEMORY_ANCHOR_ID = "workspace-case-memory"


def build_case_memory_refresh(
    case_id: int,
    *,
    conn: Any,
) -> dict[str, Any]:
    """Build a compact memory/baseline delta summary after an assessment run."""
    memory = build_case_memory(case_id, conn=conn)
    comparison = compare_case_to_latest_baseline(case_id, conn=conn)
    unexpected = unexpected_baseline_changes(comparison)
    notable = comparison.get("notable_changes") or (comparison.get("changes") or [])[:3]
    return {
        "case_id": case_id,
        "device_count": len(memory.get("known_devices") or []),
        "service_count": len(memory.get("known_services") or []),
        "open_findings": len(memory.get("open_findings") or []),
        "accepted_findings": len(memory.get("accepted_findings") or []),
        "comparison_summary": comparison.get("summary_text") or "",
        "unexpected_count": len(unexpected),
        "has_baseline": bool(comparison.get("has_baseline")),
        "notable_changes": [
            {
                "title": change.get("title"),
                "summary": change.get("summary"),
                "change_type": change.get("change_type"),
            }
            for change in notable[:3]
        ],
    }


def focus_case_memory_panel(session_state: dict[str, Any], case_id: int) -> None:
    """Scroll to case memory and expand the change summary on the next render."""
    session_state[WORKSPACE_SCROLL_TO_CASE_MEMORY_KEY] = True
    session_state[f"case_memory_compare_{case_id}"] = True


def store_case_memory_refresh(
    session_state: dict[str, Any],
    case_id: int,
    *,
    conn: Any,
    scroll_after: bool = False,
) -> dict[str, Any]:
    """Persist a refresh payload in Streamlit session state for the case memory panel."""
    payload = build_case_memory_refresh(case_id, conn=conn)
    store = session_state.setdefault(CASE_MEMORY_REFRESH_SESSION_KEY, {})
    store[str(case_id)] = payload
    if scroll_after:
        focus_case_memory_panel(session_state, case_id)
    return payload


def pop_case_memory_refresh(session_state: dict[str, Any], case_id: int) -> dict[str, Any] | None:
    """Return and remove the refresh payload for a case, if present."""
    store = session_state.get(CASE_MEMORY_REFRESH_SESSION_KEY) or {}
    return store.pop(str(case_id), None)


def get_case_memory_refresh(session_state: dict[str, Any], case_id: int) -> dict[str, Any] | None:
    store = session_state.get(CASE_MEMORY_REFRESH_SESSION_KEY) or {}
    payload = store.get(str(case_id))
    return payload if isinstance(payload, dict) else None

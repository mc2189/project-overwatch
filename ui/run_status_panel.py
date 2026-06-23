"""Run queue and recent run status panel."""

from __future__ import annotations

from typing import Any

import streamlit as st

from utils.result_status import status_label


def record_workspace_run(
    *,
    target: str,
    module_ids: list[str],
    results: list[dict[str, Any]],
    goal_label: str,
) -> None:
    """Append a run record to session state for the status panel."""
    history: list[dict[str, Any]] = list(st.session_state.get("workspace_run_history") or [])
    history.insert(
        0,
        {
            "target": target,
            "module_ids": module_ids,
            "results": results,
            "goal_label": goal_label,
            "summary": _brief_summary(results),
        },
    )
    st.session_state.workspace_run_history = history[:8]
    st.session_state.workspace_current_run = {
        "target": target,
        "module_ids": module_ids,
        "results": results,
        "goal_label": goal_label,
    }


def _brief_summary(results: list[dict[str, Any]]) -> str:
    completed = sum(1 for row in results if row.get("success"))
    blocked = sum(1 for row in results if row.get("status") == "blocked")
    warnings = sum(len(row.get("warnings") or []) for row in results)
    return f"{completed}/{len(results)} completed · {blocked} blocked · {warnings} warnings"


def render_run_status_panel() -> None:
    """Render current/recent run status in the side panel."""
    st.markdown("**Current run / recent runs**")
    current = st.session_state.get("workspace_current_run")
    if current:
        st.caption(f"Latest: `{current.get('target', '—')}` · {current.get('goal_label', 'Assessment')}")
        st.write(current.get("summary", ""))
        for result in current.get("results") or []:
            module_id = result.get("module_id", "unknown")
            st.markdown(
                f"- `{module_id}`: **{status_label(result.get('status'))}** — "
                f"{(result.get('summary') or '')[:80]}"
            )
    else:
        st.caption("No runs yet in this session.")

    history = st.session_state.get("workspace_run_history") or []
    if len(history) > 1:
        with st.expander("Earlier session runs", expanded=False):
            for entry in history[1:5]:
                st.caption(f"`{entry.get('target')}` · {entry.get('summary')}")

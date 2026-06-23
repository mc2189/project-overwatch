"""Compact preflight card for active module guardrails."""

from __future__ import annotations

from typing import Any

import streamlit as st

from utils.module_testing_levels import get_module_testing_level, is_active_testing_level
from utils.operating_context import operating_context_label


def render_compact_preflight(
    *,
    operating_context: str,
    module_preflights: list[dict[str, Any]],
    selected_module_ids: list[str],
    on_switch_personal_lab: bool = False,
) -> dict[str, Any]:
    """Render a compact preflight summary; return aggregate status."""
    active_rows = [
        row
        for row in module_preflights
        if row.get("module_id") in selected_module_ids
        and is_active_testing_level(get_module_testing_level(row.get("module_id", "")))
    ]
    if not active_rows:
        return {"has_active": False, "ready": True, "result": "ready"}

    all_ready = all(row.get("allowed") for row in active_rows)
    any_blocked = any(row.get("result") == "blocked" for row in active_rows)
    result = "ready" if all_ready else ("blocked" if any_blocked else "needs_action")

    with st.container(border=True):
        st.markdown("**Active check preflight**")
        st.caption(f"Operating context: **{operating_context_label(operating_context)}**")
        for row in active_rows:
            icon = "✅" if row.get("allowed") else ("🚫" if row.get("result") == "blocked" else "⚠️")
            label = row.get("display_name") or row.get("module_id")
            st.markdown(f"{icon} **{label}** — {row.get('result', 'unknown').replace('_', ' ')}")
            if row.get("blocked_reason") and not row.get("allowed"):
                st.caption(row["blocked_reason"])
            for item in row.get("items") or []:
                if item.get("status") == "fail" and item.get("fix"):
                    st.caption(f"→ {item['fix']}")

    return {"has_active": True, "ready": all_ready, "result": result}

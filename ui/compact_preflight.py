"""Compact preflight card for active module guardrails."""

from __future__ import annotations

from typing import Any

import streamlit as st

from utils.module_testing_levels import get_module_testing_level, is_active_testing_level
from utils.operating_context import PERSONAL_LAB, operating_context_label


def _aggregate_personal_lab_status(active_rows: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not active_rows:
        return None
    first = active_rows[0]
    readiness = first.get("lab_readiness") or {}
    if not readiness and active_rows:
        readiness = {
            "confirmed": first.get("personal_lab_confirmed"),
            "scope_label": first.get("scope_status", "unknown"),
            "allowed": all(row.get("allowed") for row in active_rows),
            "result": "ready" if all(row.get("allowed") for row in active_rows) else "needs_action",
            "target_hint": first.get("target_hint"),
            "target_warning": first.get("target_warning"),
        }
    all_allowed = all(row.get("allowed") for row in active_rows)
    any_blocked = any(row.get("result") == "blocked" for row in active_rows)
    if all_allowed:
        result = "ready"
    elif any_blocked:
        result = "blocked"
    else:
        result = readiness.get("result") or "needs_confirmation"
        if result == "needs_action":
            result = "needs_confirmation"
    return {**readiness, "allowed": all_allowed, "result": result}


def render_compact_preflight(
    *,
    operating_context: str,
    module_preflights: list[dict[str, Any]],
    selected_module_ids: list[str],
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

    with st.container(border=True):
        st.markdown("**Active check preflight**")

        if operating_context == PERSONAL_LAB:
            lab_status = _aggregate_personal_lab_status(active_rows) or {}
            st.caption(f"Operating context: **Personal Lab**")
            confirmation_label = "confirmed" if lab_status.get("confirmed") else "required"
            st.markdown(f"- Lab confirmation: **{confirmation_label}**")
            scope_label = lab_status.get("scope_label") or "unknown"
            st.markdown(f"- Lab scope: **{scope_label}**")
            st.markdown("- Testing level: **safe active permitted**")
            st.markdown("- Emergency stop: **not applicable**")
            result = lab_status.get("result", "needs_confirmation")
            result_display = {
                "ready": "Ready",
                "needs_confirmation": "Needs confirmation",
                "needs_action": "Needs confirmation",
                "blocked": "Blocked",
            }.get(result, result.replace("_", " ").title())
            if lab_status.get("allowed"):
                st.success(f"Result: **Ready**")
            elif result in {"needs_confirmation", "needs_action"}:
                st.warning(f"Result: **{result_display}**")
            else:
                st.error(f"Result: **{result_display}**")
            if lab_status.get("target_hint"):
                st.info(lab_status["target_hint"])
            if lab_status.get("target_warning"):
                st.warning(lab_status["target_warning"])
            for row in active_rows:
                if not row.get("allowed") and row.get("blocked_reason"):
                    st.caption(f"{row.get('display_name')}: {row['blocked_reason']}")
        else:
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

    all_ready = all(row.get("allowed") for row in active_rows)
    any_blocked = any(row.get("result") == "blocked" for row in active_rows)
    result = "ready" if all_ready else ("blocked" if any_blocked else "needs_confirmation")
    return {"has_active": True, "ready": all_ready, "result": result}

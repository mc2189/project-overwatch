"""Compact preflight card for active module guardrails."""

from __future__ import annotations

from typing import Any

import streamlit as st

from ui.styles import render_status_chip, status_chip
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


def _build_summary_line(
    *,
    active_count: int,
    operating_context: str,
    result: str,
    personal_lab_confirmed: bool | None = None,
) -> str:
    if active_count == 0:
        return "No active checks in this run."
    if result == "ready":
        return f"Ready to run {active_count} active check(s)."
    if result == "blocked":
        return f"{active_count} active check(s). One or more checks are blocked."
    if operating_context == PERSONAL_LAB and not personal_lab_confirmed:
        return f"{active_count} active check(s) selected. Personal Lab confirmation required."
    return f"{active_count} active check(s) selected. Confirmation required."


def _render_preflight_details(
    *,
    operating_context: str,
    active_rows: list[dict[str, Any]],
    lab_status: dict[str, Any] | None,
) -> None:
    if operating_context == PERSONAL_LAB and lab_status:
        st.caption(f"Operating context: **Personal Lab**")
        confirmation_label = "confirmed" if lab_status.get("confirmed") else "required"
        st.markdown(f"- Lab confirmation: **{confirmation_label}**")
        st.markdown(f"- Lab scope: **{lab_status.get('scope_label') or 'unknown'}**")
        st.markdown("- Testing level: **safe active permitted**")
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


def render_compact_preflight(
    *,
    operating_context: str,
    module_preflights: list[dict[str, Any]],
    selected_module_ids: list[str],
    passive_count: int = 0,
    active_count: int = 0,
) -> dict[str, Any]:
    """Render a compact preflight summary; return aggregate status."""
    active_rows = [
        row
        for row in module_preflights
        if row.get("module_id") in selected_module_ids
        and is_active_testing_level(get_module_testing_level(row.get("module_id", "")))
    ]
    if not active_rows:
        if active_count:
            st.caption(_build_summary_line(active_count=active_count, operating_context=operating_context, result="ready"))
        return {"has_active": False, "ready": True, "result": "ready", "summary": "Passive checks only."}

    lab_status = _aggregate_personal_lab_status(active_rows) if operating_context == PERSONAL_LAB else None
    all_ready = all(row.get("allowed") for row in active_rows)
    any_blocked = any(row.get("result") == "blocked" for row in active_rows)
    result = "ready" if all_ready else ("blocked" if any_blocked else "needs_confirmation")

    summary = _build_summary_line(
        active_count=len(active_rows),
        operating_context=operating_context,
        result=result,
        personal_lab_confirmed=lab_status.get("confirmed") if lab_status else None,
    )

    chip_key = "ready" if result == "ready" else ("blocked" if result == "blocked" else "needs_confirmation")
    render_status_chip(chip_key, label=summary)

    with st.expander("Show readiness details", expanded=False):
        _render_preflight_details(
            operating_context=operating_context,
            active_rows=active_rows,
            lab_status=lab_status,
        )

    return {"has_active": True, "ready": all_ready, "result": result, "summary": summary}

"""Preflight panel rendering for Run Operation active module guardrails."""

from __future__ import annotations

from typing import Any

import streamlit as st

from modules.module_registry import get_module
from utils.module_testing_levels import is_active_testing_level, get_module_testing_level


def _result_badge(result: str) -> str:
    if result == "ready":
        return "✅ Ready"
    if result == "needs_action":
        return "⚠️ Needs action"
    return "🚫 Blocked"


def render_module_preflight_summary(module_preflights: list[dict[str, Any]]) -> None:
    """Render per-module preflight summaries for active modules."""
    active_rows = [
        row
        for row in module_preflights
        if is_active_testing_level(row.get("testing_level_required") or get_module_testing_level(row["module_id"]))
    ]
    if not active_rows:
        return

    st.markdown("**Active module preflight**")
    for row in active_rows:
        label = row.get("display_name") or row.get("module_id")
        st.markdown(f"**{label}** — {_result_badge(row.get('result', 'blocked'))}")
        if row.get("blocked_reason"):
            st.caption(row["blocked_reason"])
        for item in row.get("items") or []:
            if item.get("status") == "fail" and item.get("fix"):
                st.markdown(f"- Fix: {item['fix']}")


def render_operating_preflight_panel(
    *,
    operating_context: str,
    operating_context_label: str,
    target: str,
    target_type_label: str,
    module_preflights: list[dict[str, Any]],
    selected_module_ids: list[str],
) -> None:
    """Render aggregate preflight status for the operation."""
    if not target.strip() or not selected_module_ids:
        return

    st.markdown("#### Preflight")
    st.markdown(f"**Operating context:** {operating_context_label}")
    st.markdown(f"**Target type:** {target_type_label}")

    any_active = False
    for module_id in selected_module_ids:
        module = get_module(module_id)
        if module is None:
            continue
        if is_active_testing_level(get_module_testing_level(module_id)):
            any_active = True
            preflight = next((row for row in module_preflights if row.get("module_id") == module_id), None)
            if preflight is None:
                continue
            st.markdown(
                f"**{module.display_name}:** {_result_badge(preflight.get('result', 'blocked'))} · "
                f"Scope: {(preflight.get('scope_status') or '—').replace('_', ' ')} · "
                f"Required: {preflight.get('testing_level_required_label', '—')} · "
                f"Permitted: {(preflight.get('testing_level_permitted') or '—').replace('_', ' ')}"
            )
            if preflight.get("emergency_stop_active"):
                st.error("Emergency stop is active — active modules are blocked.")
            for item in preflight.get("items") or []:
                icon = "✅" if item.get("status") == "ok" else "❌"
                value = f" ({item['value']})" if item.get("value") else ""
                st.markdown(f"{icon} {item.get('label')}{value}")
                if item.get("status") == "fail" and item.get("fix"):
                    st.caption(f"→ {item['fix']}")

    if not any_active:
        st.caption("No active modules selected — preflight checks are minimal for passive modules.")

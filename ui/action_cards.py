"""Render actionable next-step cards with one-click buttons."""

from __future__ import annotations

from typing import Any

import streamlit as st

from ui.styles import render_empty_state
from ui.workspace_actions import apply_workspace_action

_PRIORITY_BADGE = {
    "high": "🔴",
    "medium": "🟡",
    "low": "⚪",
}


def render_action_card(
    action: dict[str, Any],
    *,
    case_id: int,
    key_prefix: str = "ws",
) -> None:
    """Render a single concise action card with optional button."""
    action_id = action.get("id", "action")
    priority = action.get("priority", "medium")
    badge = _PRIORITY_BADGE.get(priority, "○")

    with st.container(border=True):
        st.markdown(f"{badge} **{action.get('title', 'Action')}**")
        st.caption((action.get("reason") or "")[:120])
        if action.get("why_detail") and action.get("why_detail") != action.get("reason"):
            with st.expander("Why am I seeing this?", expanded=False):
                st.caption(action["why_detail"])

        if not action.get("enabled"):
            if action.get("blocked_reason"):
                st.caption(f"Blocked: {action['blocked_reason']}")
            return

        action_type = action.get("action_type")
        if action_type == "no_action":
            return

        if st.button(
            action.get("button_label", "Go"),
            key=f"{key_prefix}_btn_{action_id}",
            width="stretch",
        ):
            message = apply_workspace_action(action, case_id)
            st.session_state.workspace_action_message = message
            st.rerun()


def render_action_cards(
    actions: list[dict[str, Any]],
    *,
    case_id: int,
    title: str = "Next steps",
    limit: int = 3,
    key_prefix: str = "ws",
) -> None:
    """Render top action cards with optional show-more expander."""
    st.markdown(f"#### {title}")
    if st.session_state.get("workspace_action_message"):
        st.success(st.session_state.workspace_action_message)
        if st.button("Dismiss", key=f"{key_prefix}_dismiss_msg"):
            del st.session_state["workspace_action_message"]
            st.rerun()

    if not actions:
        render_empty_state("No recommended next actions yet.")
        return

    for action in actions[:limit]:
        render_action_card(action, case_id=case_id, key_prefix=key_prefix)

    if len(actions) > limit:
        with st.expander(f"Show more suggestions ({len(actions) - limit})", expanded=False):
            for action in actions[limit:]:
                render_action_card(action, case_id=case_id, key_prefix=f"{key_prefix}_more")


def render_pivot_cards(
    pivots: list[dict[str, Any]],
    *,
    case_id: int,
    key_prefix: str = "pivot",
) -> None:
    """Render discovered pivot cards with queue and entity actions."""
    st.markdown("**New pivots**")
    if not pivots:
        render_empty_state("No new pivots found from this run.")
        return

    from utils.next_actions import enrich_action_readiness, make_action

    for index, pivot in enumerate(pivots[:6]):
        module_id = (pivot.get("suggested_checks") or [None])[0]
        entity_type = pivot.get("entity_type") or pivot.get("pivot_type", "unknown")
        queue_action = enrich_action_readiness(
            make_action(
                title=f"Queue {pivot['value']}",
                reason=f"From {pivot.get('source_module', 'run')}.",
                action_type="add_to_queue",
                priority="medium",
                target=pivot["value"],
                module_id=module_id,
                button_label="Add to queue",
                action_id=f"pivot_queue_{index}_{pivot['value']}",
            ),
            case_id=case_id,
            operating_context=st.session_state.get("operating_context", "passive_research"),
            personal_lab_confirmed=bool(st.session_state.get("personal_lab_confirmed")),
            authorisation_confirmed=bool(st.session_state.get("authorisation_confirmed")),
        )
        open_action = make_action(
            title=f"Open {pivot['value']}",
            reason="Inspect entity in Entity Workspace.",
            action_type="open_entity",
            priority="low",
            target=pivot["value"],
            button_label="Open entity",
            action_id=f"pivot_open_{index}_{pivot['value']}",
        )

        with st.container(border=True):
            st.markdown(f"**{entity_type}** — `{pivot['value']}`")
            st.caption(f"Source: {pivot.get('source_module', '—')}")
            c1, c2 = st.columns(2)
            with c1:
                if queue_action.get("enabled"):
                    if st.button(
                        queue_action.get("button_label", "Add to queue"),
                        key=f"{key_prefix}_q_{index}",
                        width="stretch",
                    ):
                        st.session_state.workspace_action_message = apply_workspace_action(
                            queue_action, case_id
                        )
                        st.rerun()
                elif queue_action.get("blocked_reason"):
                    st.caption(queue_action["blocked_reason"])
            with c2:
                if st.button("Open entity", key=f"{key_prefix}_o_{index}", width="stretch"):
                    st.session_state.workspace_action_message = apply_workspace_action(
                        open_action, case_id
                    )
                    st.rerun()

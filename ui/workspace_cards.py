"""Reusable card components for the assessment workspace."""

from __future__ import annotations

from typing import Any

import streamlit as st

from modules.module_registry import get_module
from ui.constants import MODULE_CARD_TITLES
from ui.module_config_compact import render_module_info_expanders
from ui.styles import render_empty_state, render_status_chip, status_chip
from utils.assessment_goals import goal_description, goal_label
from utils.module_compatibility import module_short_help
from utils.operating_context import (
    CLIENT_ENGAGEMENT,
    OPERATING_CONTEXT_DESCRIPTIONS,
    PASSIVE_RESEARCH,
    PERSONAL_LAB,
    operating_context_label,
)


def render_target_profile_card(profile: dict[str, Any], *, suggested_goals: list[str] | None = None) -> None:
    """Compact target profile card."""
    with st.container(border=True):
        if not profile.get("target"):
            render_empty_state("Enter a domain, URL, IP address or email to begin.")
            return

        target = profile.get("target", "")
        st.markdown(f"**{target}**")
        chips = st.columns(4)
        chips[0].caption(status_chip("passive", label=profile.get("target_type_label", "Unknown")))
        chips[1].caption(f"In case: **{'Yes' if profile.get('known_in_case') else 'No'}**")
        chips[2].caption(f"Prior runs: **{profile.get('operations_count', 0)}**")
        chips[3].caption(f"Open findings: **{profile.get('open_findings_count', 0)}**")

        if profile.get("is_private_ipv4"):
            st.markdown("**Local target detected**")
            if profile.get("has_service_data"):
                st.caption(
                    "Path: review discovered services → HTTP/TLS on known ports → findings & evidence"
                )
            else:
                st.caption(
                    "Path: Network Service Check → review web/TLS services → findings & evidence"
                )

        if profile.get("triage_message") and not profile.get("is_private_ipv4"):
            st.caption(profile["triage_message"][:200])

        if suggested_goals:
            st.caption(
                "Suggested goals: "
                + ", ".join(goal_label(goal_id) for goal_id in suggested_goals[:3])
            )


def render_local_target_route_card(profile: dict[str, Any]) -> None:
    """Clear route for local/private IP targets."""
    with st.container(border=True):
        st.markdown("**Local target detected**")
        if profile.get("has_service_data"):
            st.caption("Recommended path:")
            st.markdown(
                "1. Review discovered web/TLS services  \n"
                "2. Run HTTP/TLS on known ports  \n"
                "3. Review findings and evidence"
            )
        else:
            st.caption(
                "This looks like a local/private IP. Start with Network Service Check "
                "to discover open ports."
            )
            st.markdown(
                "1. Discover open services  \n"
                "2. Review discovered web/TLS services  \n"
                "3. Review findings and evidence"
            )


def render_goal_card(goal_id: str) -> None:
    """Compact goal summary card."""
    with st.container(border=True):
        st.markdown(f"**{goal_label(goal_id)}**")
        st.caption(goal_description(goal_id))


def render_mode_explainer(operating_context: str) -> None:
    """Short collapsible operating context explanation."""
    short = {
        PASSIVE_RESEARCH: "Passive lookups and enrichment. Minimal friction.",
        PERSONAL_LAB: "Your own systems and lab testing. Active checks require confirmation.",
        CLIENT_ENGAGEMENT: "Formal client work. Scope and ROE are enforced.",
    }
    with st.expander(f"About {operating_context_label(operating_context)} mode", expanded=False):
        st.caption(short.get(operating_context, OPERATING_CONTEXT_DESCRIPTIONS.get(operating_context, "")))


def render_module_check_card(
    row: dict[str, Any],
    *,
    target: str,
    selected: bool = True,
) -> None:
    """Compact module/check card for the recommended journey."""
    module_id = row.get("module_id", "")
    module = get_module(module_id)
    title = row.get("display_name") or MODULE_CARD_TITLES.get(module_id, module_id)
    mode = row.get("mode") or (module.mode if module else "unknown")
    mode_key = "passive" if mode == "passive" else "active"

    with st.container(border=True):
        head = st.columns([4, 1])
        with head[0]:
            st.markdown(f"**{title}**")
            reason = row.get("reason") or row.get("blocked_reason") or module_short_help(module) if module else ""
            if reason:
                st.caption(str(reason)[:140])
        with head[1]:
            render_status_chip(mode_key)

        if module and module.output_summary:
            st.caption(f"Output: {module.output_summary[:120]}")

        if row.get("blocked_reason"):
            st.caption(f"⛔ {row['blocked_reason']}")

        with st.expander("Why / what / safety", expanded=False):
            render_module_info_expanders(module_id, target)


def render_readiness_summary(
    *,
    selected_count: int,
    passive_count: int,
    active_count: int,
    preflight_result: str,
    operating_context: str,
    one_line_warning: str | None = None,
) -> None:
    """One-line readiness summary above the run button."""
    with st.container(border=True):
        st.markdown("**Readiness**")
        if selected_count == 0:
            render_empty_state("No checks selected yet.")
            return

        if preflight_result == "ready":
            if active_count:
                line = (
                    f"Ready to run: {passive_count} passive"
                    f"{' check' if passive_count == 1 else ' checks'}"
                    f" and {active_count} active"
                    f"{' check' if active_count == 1 else ' checks'}."
                )
            else:
                line = f"Ready to run: {passive_count} passive check(s)."
            render_status_chip("ready", label=line.replace("Ready to run: ", ""))
        elif preflight_result == "blocked":
            render_status_chip("blocked", label="Resolve blocked items before running.")
        else:
            if active_count and operating_context == PERSONAL_LAB:
                line = f"{active_count} active check(s) selected. Personal Lab confirmation required."
            elif active_count:
                line = f"{active_count} active check(s) selected. Confirmation required."
            else:
                line = "Review readiness before running."
            render_status_chip("needs_confirmation", label=line)

        st.caption(
            f"{selected_count} selected · {passive_count} passive · {active_count} active · "
            f"{operating_context_label(operating_context)}"
        )
        if one_line_warning:
            st.warning(one_line_warning)


def render_warning_card(title: str, message: str) -> None:
    """Short warning card."""
    with st.container(border=True):
        st.markdown(f"**{title}**")
        st.caption(message)


def render_report_journey_cards(
    actions: list[dict[str, Any]],
    *,
    case_id: int,
    apply_action,
) -> None:
    """Compact report journey buttons after results."""
    if not actions:
        return
    st.markdown("**Report journey**")
    cols = st.columns(min(len(actions), 4))
    labels = [
        ("Review findings", "open_finding"),
        ("Review evidence", "review_evidence"),
        ("Generate report", "create_report"),
        ("Add analyst note", "add_note"),
    ]
    for col, (label, action_type) in zip(cols, labels):
        action = next((a for a in actions if a.get("action_type") == action_type), None)
        if action is None:
            continue
        with col:
            if action.get("enabled") and st.button(
                action.get("button_label", label),
                key=f"rj_{action['id']}",
                width="stretch",
            ):
                st.session_state.workspace_action_message = apply_action(action, case_id)
                st.rerun()

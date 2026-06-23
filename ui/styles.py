"""Lightweight workspace styling helpers (Streamlit-native, no heavy CSS)."""

from __future__ import annotations

import streamlit as st

STATUS_CHIPS: dict[str, tuple[str, str]] = {
    "ready": ("✅", "Ready"),
    "needs_confirmation": ("⚠️", "Needs confirmation"),
    "needs_action": ("⚠️", "Needs action"),
    "blocked": ("⛔", "Blocked"),
    "passive": ("🟦", "Passive"),
    "active": ("🟧", "Active"),
    "lab": ("🧪", "Lab"),
    "client": ("📋", "Client"),
    "evidence": ("📄", "Evidence"),
    "warning": ("⚠️", "Warning"),
    "failed": ("❌", "Failed"),
    "complete": ("✅", "Complete"),
    "no_response": ("○", "No response"),
    "not_applicable": ("—", "Not applicable"),
    "partial": ("⚠️", "Partial"),
}


def apply_workspace_styles() -> None:
    """Inject minimal CSS for card spacing and muted helper text."""
    st.markdown(
        """
        <style>
        div[data-testid="stVerticalBlock"] > div.workspace-section-title {
            margin-top: 0.25rem;
            margin-bottom: 0.35rem;
        }
        .ow-muted {
            color: rgba(49, 51, 63, 0.65);
            font-size: 0.9rem;
        }
        </style>
        """,
        unsafe_allow_html=True,
    )


def section_heading(title: str) -> None:
    """Consistent section heading with reduced vertical noise."""
    st.markdown(f"#### {title}")


def status_chip(status_key: str, *, label: str | None = None) -> str:
    """Return formatted status chip text."""
    icon, default_label = STATUS_CHIPS.get(status_key, ("•", status_key.replace("_", " ").title()))
    return f"{icon} {label or default_label}"


def render_status_chip(status_key: str, *, label: str | None = None) -> None:
    """Render a one-line status chip."""
    st.caption(status_chip(status_key, label=label))


def render_empty_state(message: str, *, icon: str = "○") -> None:
    """Friendly empty-state message."""
    with st.container(border=True):
        st.caption(f"{icon} {message}")

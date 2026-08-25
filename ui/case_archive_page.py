"""Combined case archive — Graph, Relationships, Observations, Operations."""

from __future__ import annotations

import streamlit as st

from ui.archive_pages import (
    render_graph_page,
    render_observations_page,
    render_operations_page,
    render_relationships_page,
)
from ui.constants import CASE_ARCHIVE_TABS


def render_case_archive_page(case_id: int, metrics: dict) -> None:
    """Single Investigate destination for secondary archive views."""
    st.title("Case Archive")
    st.caption("Graph, relationships, observations, and operation history for this case.")

    default_tab = st.session_state.get("case_archive_tab", "Graph")
    if default_tab not in CASE_ARCHIVE_TABS:
        default_tab = "Graph"
    if st.session_state.get("case_archive_tab_control") != default_tab:
        st.session_state.case_archive_tab_control = default_tab

    picked = st.segmented_control(
        "Archive view",
        options=list(CASE_ARCHIVE_TABS),
        key="case_archive_tab_control",
        label_visibility="collapsed",
    )
    tab = picked or default_tab
    st.session_state.case_archive_tab = tab

    if tab == "Graph":
        render_graph_page(case_id, metrics)
    elif tab == "Relationships":
        render_relationships_page(case_id, metrics)
    elif tab == "Observations":
        render_observations_page(case_id, metrics)
    else:
        render_operations_page(case_id, metrics)

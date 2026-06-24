"""Cross-page navigation helpers (avoids circular imports)."""

from __future__ import annotations

import streamlit as st

ENTITY_WORKSPACE_SELECTED_KEY = "entity_workspace_selected_id"


def open_entity_in_workspace(entity_id: int) -> None:
    """Navigate to Entity Workspace with a pre-selected entity."""
    st.session_state[ENTITY_WORKSPACE_SELECTED_KEY] = entity_id
    st.session_state.nav_page = "Entity Workspace"

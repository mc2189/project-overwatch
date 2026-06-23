"""Sidebar layout for Project Overwatch."""

from __future__ import annotations

import streamlit as st

from database.db_setup import create_case, list_cases
from ui.constants import NAV_PAGES
from utils.operating_context import operating_context_label
from version import PROJECT_VERSION


def render_sidebar() -> str:
    st.title("Project Overwatch")
    st.caption(f"v{PROJECT_VERSION}")

    st.subheader("Case")
    cases = list_cases()
    case_labels = {f"{case['name']} (#{case['id']})": case["id"] for case in cases}
    selected_case_label = st.selectbox(
        "Active case",
        options=list(case_labels.keys()),
        index=list(case_labels.values()).index(st.session_state.case_id)
        if st.session_state.case_id in case_labels.values()
        else 0,
        label_visibility="collapsed",
    )
    st.session_state.case_id = case_labels[selected_case_label]

    if st.session_state.get("operation_target", "").strip():
        st.caption(f"Target: `{st.session_state.operation_target.strip()}`")
    if st.session_state.get("operating_context"):
        st.caption(f"Mode: {operating_context_label(st.session_state.operating_context)}")

    with st.expander("Create new case", expanded=False):
        new_case_name = st.text_input("Case name", placeholder="e.g. Acme Corp assessment")
        new_case_description = st.text_area("Description", placeholder="Optional notes")
        if st.button("Create case", width="stretch"):
            if not new_case_name.strip():
                st.warning("Enter a case name.")
            else:
                created = create_case(new_case_name.strip(), new_case_description.strip() or None)
                st.session_state.case_id = created["id"]
                st.success(f"Case '{created['name']}' created.")
                st.rerun()

    st.divider()
    st.subheader("Navigation")
    if st.session_state.get("nav_page") == "Entities":
        st.session_state.nav_page = "Entity Workspace"
    default_index = NAV_PAGES.index(st.session_state.get("nav_page", "Run Operation"))
    nav_page = st.radio(
        "Go to",
        options=NAV_PAGES,
        index=default_index,
        label_visibility="collapsed",
    )
    st.session_state.nav_page = nav_page
    return nav_page

"""Sidebar layout for Project Overwatch."""

from __future__ import annotations

import streamlit as st

from database.db_setup import create_case, list_cases
from ui.constants import NAV_GROUP_BY_PAGE, NAV_PAGES, normalize_nav_page
from ui.case_workflow_banner import render_case_workflow_strip
from utils.case_session import ensure_case_session, switch_case_session
from utils.operating_context import operating_context_label
from version import PROJECT_VERSION


def render_sidebar() -> str:
    st.title("Project Overwatch")
    st.caption(f"v{PROJECT_VERSION}")

    st.subheader("Case")
    cases = list_cases()
    case_labels = {f"{case['name']} (#{case['id']})": case["id"] for case in cases}
    previous_case_id = st.session_state.get("case_id")
    selected_case_label = st.selectbox(
        "Active case",
        options=list(case_labels.keys()),
        index=list(case_labels.values()).index(st.session_state.case_id)
        if st.session_state.case_id in case_labels.values()
        else 0,
        label_visibility="collapsed",
    )
    new_case_id = case_labels[selected_case_label]
    if previous_case_id != new_case_id:
        switch_case_session(previous_case_id, new_case_id)
    st.session_state.case_id = new_case_id
    ensure_case_session(new_case_id)

    render_case_workflow_strip(new_case_id, compact=True)

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
                switch_case_session(st.session_state.case_id, created["id"])
                st.session_state.case_id = created["id"]
                st.success(f"Case '{created['name']}' created.")
                st.rerun()

    st.divider()
    st.subheader("Navigation")
    current_nav = normalize_nav_page(st.session_state.get("nav_page"))
    if current_nav not in NAV_PAGES:
        current_nav = "Assessment Workspace"

    nav_index = NAV_PAGES.index(current_nav)
    nav_page = st.selectbox(
        "Go to",
        options=list(NAV_PAGES),
        index=nav_index,
        format_func=lambda page: f"{NAV_GROUP_BY_PAGE.get(page, '')} · {page}",
        label_visibility="collapsed",
        key="sidebar_nav_select",
    )
    st.session_state.nav_page = nav_page
    return nav_page

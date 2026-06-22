"""Project Overwatch — local intelligence and defensive analysis dashboard."""

from __future__ import annotations

import streamlit as st

from database.db_setup import get_or_create_default_case, list_cases
from ui.archive_pages import (
    render_backup_page,
    render_graph_page,
    render_observations_page,
    render_operations_page,
    render_relationships_page,
    render_report_page,
)
from ui.settings_page import render_settings_page
from ui.batch_queue_page import render_batch_queue_page
from ui.entity_workspace import render_entity_workspace_page
from ui.findings_page import render_findings_page
from ui.metrics import load_case_metrics
from ui.roadmap import render_roadmap_page
from ui.run_operation import render_run_operation_page
from ui.sidebar import render_sidebar
from utils.local_auth import render_local_auth_gate
from utils.report_scheduler import maybe_run_scheduled_exports

st.set_page_config(
    page_title="Project Overwatch",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

if "case_id" not in st.session_state:
    st.session_state.case_id = get_or_create_default_case()["id"]

if "nav_page" not in st.session_state:
    st.session_state.nav_page = "Run Operation"

render_local_auth_gate()

if "startup_tasks_done" not in st.session_state:
    _scheduled_paths, scheduled_message = maybe_run_scheduled_exports()
    if scheduled_message:
        st.session_state.startup_notice = scheduled_message
    st.session_state.startup_tasks_done = True


def get_current_case() -> dict:
    cases = list_cases()
    for case in cases:
        if case["id"] == st.session_state.case_id:
            return case
    default_case = get_or_create_default_case()
    st.session_state.case_id = default_case["id"]
    return default_case


with st.sidebar:
    nav_page = render_sidebar()

current_case = get_current_case()
metrics = load_case_metrics(st.session_state.case_id)

if nav_page == "Run Operation":
    render_run_operation_page(current_case, metrics)
elif nav_page == "Findings":
    render_findings_page(st.session_state.case_id, metrics)
elif nav_page == "Entity Workspace":
    render_entity_workspace_page(
        st.session_state.case_id,
        metrics,
        case_name=current_case.get("name") or "",
    )
elif nav_page == "Batch Queue":
    render_batch_queue_page(st.session_state.case_id, metrics)
elif nav_page == "Relationships":
    render_relationships_page(st.session_state.case_id, metrics)
elif nav_page == "Observations":
    render_observations_page(st.session_state.case_id, metrics)
elif nav_page == "Operations":
    render_operations_page(st.session_state.case_id, metrics)
elif nav_page == "Graph":
    render_graph_page(st.session_state.case_id, metrics)
elif nav_page == "Report":
    render_report_page(st.session_state.case_id, metrics)
elif nav_page == "Backup":
    render_backup_page(st.session_state.case_id, metrics)
elif nav_page == "Settings":
    render_settings_page(metrics)
elif nav_page == "Roadmap":
    render_roadmap_page()

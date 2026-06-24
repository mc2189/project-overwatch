"""Render case workflow progress chips."""

from __future__ import annotations

import streamlit as st

from utils.case_workflow import STAGE_NAV_HINTS, WORKFLOW_STAGES, assess_case_workflow


def render_case_workflow_strip(case_id: int, *, compact: bool = False) -> None:
    """Show Target → Baseline → Triage → Report progress for the active case."""
    workflow = assess_case_workflow(case_id)
    completed = workflow["completed"]
    suggested = workflow["suggested_stage"]

    if compact:
        labels = []
        for stage_id, label, _ in WORKFLOW_STAGES:
            mark = "✓" if completed[stage_id] else ("→" if stage_id == suggested else "○")
            labels.append(f"{mark} {label}")
        st.caption(" · ".join(labels))
        return

    cols = st.columns(len(WORKFLOW_STAGES))
    for col, (stage_id, label, description) in zip(cols, WORKFLOW_STAGES):
        with col:
            if completed[stage_id]:
                st.success(label)
            elif stage_id == suggested:
                st.info(f"**{label}**")
            else:
                st.caption(label)
            st.caption(description[:48] + ("…" if len(description) > 48 else ""))

    hint_page = STAGE_NAV_HINTS.get(suggested)
    if hint_page:
        st.caption(f"Suggested next: **{hint_page}**")

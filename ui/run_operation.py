"""Run Operation workflow page — delegates to the guided assessment workspace."""

from __future__ import annotations

from ui.assessment_workspace import render_assessment_workspace


def render_run_operation_page(current_case: dict, metrics: dict) -> None:
    render_assessment_workspace(current_case, metrics)

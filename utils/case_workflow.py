"""Case investigation workflow stages."""

from __future__ import annotations

from typing import Any

from database.db_setup import TERMINAL_FINDING_STATUSES, finding_status_counts, get_db_conn, normalize_finding_status

STAGE_TARGET = "target"
STAGE_BASELINE = "baseline"
STAGE_TRIAGE = "triage"
STAGE_REPORT = "report"

WORKFLOW_STAGES: tuple[tuple[str, str, str], ...] = (
    (STAGE_TARGET, "Target", "Set a target and run initial checks"),
    (STAGE_BASELINE, "Baseline", "Build entities, observations, and evidence"),
    (STAGE_TRIAGE, "Triage", "Review findings and linked evidence"),
    (STAGE_REPORT, "Report", "Summarise and export the case"),
)

STAGE_NAV_HINTS: dict[str, str] = {
    STAGE_TARGET: "Assessment Workspace",
    STAGE_BASELINE: "Entity Workspace",
    STAGE_TRIAGE: "Findings",
    STAGE_REPORT: "Report",
}


def assess_case_workflow(case_id: int, *, conn=None) -> dict[str, Any]:
    """Return workflow stage completion and the suggested next stage."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        entity_count = conn.execute(
            "SELECT count(*) FROM entities WHERE case_id = ?",
            (case_id,),
        ).fetchone()[0]
        operation_count = conn.execute(
            "SELECT count(*) FROM operations WHERE case_id = ?",
            (case_id,),
        ).fetchone()[0]
        observation_count = conn.execute(
            "SELECT count(*) FROM observations WHERE case_id = ?",
            (case_id,),
        ).fetchone()[0]
        finding_counts = finding_status_counts(case_id, conn=conn)
        total_findings = sum(finding_counts.values())
        open_findings = sum(
            count
            for status, count in finding_counts.items()
            if normalize_finding_status(status) not in TERMINAL_FINDING_STATUSES
        )
    finally:
        if own_conn:
            conn.close()

    completed = {
        STAGE_TARGET: entity_count > 0 or operation_count > 0,
        STAGE_BASELINE: operation_count > 0 and (entity_count > 0 or observation_count > 0),
        STAGE_TRIAGE: total_findings > 0 and open_findings == 0,
        STAGE_REPORT: False,
    }

    suggested = STAGE_REPORT
    for stage_id, _, _ in WORKFLOW_STAGES:
        if not completed[stage_id]:
            suggested = stage_id
            break

    return {
        "completed": completed,
        "suggested_stage": suggested,
        "counts": {
            "entities": entity_count,
            "operations": operation_count,
            "observations": observation_count,
            "open_findings": open_findings,
            "total_findings": total_findings,
        },
    }

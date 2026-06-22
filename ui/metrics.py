"""Case metrics helpers for the Streamlit UI."""

from __future__ import annotations

import streamlit as st

from database.db_setup import count_evidence_items, finding_status_counts, get_db_conn


def load_case_metrics(case_id: int) -> dict[str, int]:
    conn = get_db_conn()
    try:
        entity_count = conn.execute(
            "SELECT count(*) FROM entities WHERE case_id = ?",
            (case_id,),
        ).fetchone()[0]
        relationship_count = conn.execute(
            "SELECT count(*) FROM relationships WHERE case_id = ?",
            (case_id,),
        ).fetchone()[0]
        observation_count = conn.execute(
            "SELECT count(*) FROM observations WHERE case_id = ?",
            (case_id,),
        ).fetchone()[0]
        operation_count = conn.execute(
            "SELECT count(*) FROM operations WHERE case_id = ?",
            (case_id,),
        ).fetchone()[0]
        finding_counts = finding_status_counts(case_id, conn=conn)
        evidence_count = count_evidence_items(case_id, conn=conn)
    finally:
        conn.close()

    return {
        "entities": entity_count,
        "relationships": relationship_count,
        "observations": observation_count,
        "operations": operation_count,
        "evidence_items": evidence_count,
        "open_findings": finding_counts.get("open", 0),
        "in_review": finding_counts.get("in_review", 0),
        "action_required": finding_counts.get("action_required", 0),
        "closed": finding_counts.get("closed", 0),
        "total_findings": sum(finding_counts.values()),
    }


def render_compact_metrics(metrics: dict[str, int], *, minimal: bool = False) -> None:
    """Render a compact metrics row for archive pages."""
    if minimal:
        c1, c2, c3, c4 = st.columns(4)
        c1.metric("Entities", metrics["entities"])
        c2.metric("Observations", metrics["observations"])
        c3.metric("Open findings", metrics["open_findings"])
        c4.metric("Operations", metrics["operations"])
        return

    row1 = st.columns(6)
    row1[0].metric("Entities", metrics["entities"])
    row1[1].metric("Relationships", metrics["relationships"])
    row1[2].metric("Observations", metrics["observations"])
    row1[3].metric("Evidence", metrics.get("evidence_items", 0))
    row1[4].metric("Operations", metrics["operations"])
    row1[5].metric("Open findings", metrics["open_findings"])

    row2 = st.columns(4)
    row2[0].metric("In review", metrics["in_review"])
    row2[1].metric("Action required", metrics["action_required"])
    row2[2].metric("Closed", metrics["closed"])
    row2[3].metric("Total findings", metrics["total_findings"])

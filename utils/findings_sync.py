"""Synchronise interpreter findings with the database on module completion."""

from __future__ import annotations

import sqlite3
from typing import Any

from database.db_setup import close_superseded_findings, upsert_finding
from utils.finding_interpreter import risk_findings


def sync_module_findings(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int | None,
    observation_id: int | None,
    module_id: str,
    interpreter_findings: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    Persist module findings: close superseded open/reviewed items, then upsert current set.
    Returns the stored finding rows.
    """
    active_titles = [finding.get("title", "Finding") for finding in risk_findings(interpreter_findings)]
    close_superseded_findings(
        case_id,
        entity_id,
        module_id,
        active_titles,
        conn=conn,
    )

    stored: list[dict[str, Any]] = []
    for finding in risk_findings(interpreter_findings):
        stored.append(
            upsert_finding(
                case_id,
                module_id,
                finding.get("title", "Finding"),
                finding.get("severity", "info"),
                int(finding.get("confidence", 50)),
                finding.get("explanation", ""),
                finding.get("suggested_actions") or [],
                entity_id=entity_id,
                observation_id=observation_id,
                evidence_type=finding.get("evidence_type"),
                source_name=finding.get("source_name"),
                reliability=finding.get("reliability"),
                conn=conn,
            )
        )
    return stored

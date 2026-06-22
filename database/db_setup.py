"""SQLite database setup and investigation model helpers for Project Overwatch."""

from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DB_PATH = PROJECT_ROOT / "database" / "overwatch.db"

TARGETS_SCHEMA = """
CREATE TABLE IF NOT EXISTS targets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain_or_ip TEXT UNIQUE,
    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

RECON_DATA_SCHEMA = """
CREATE TABLE IF NOT EXISTS recon_data (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_id INTEGER,
    open_ports TEXT,
    date_added TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(target_id) REFERENCES targets(id)
)
"""

CASES_SCHEMA = """
CREATE TABLE IF NOT EXISTS cases (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'open',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

ENTITIES_SCHEMA = """
CREATE TABLE IF NOT EXISTS entities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    entity_type TEXT NOT NULL,
    value TEXT NOT NULL,
    label TEXT,
    notes TEXT,
    source TEXT,
    confidence INTEGER DEFAULT 50,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(case_id) REFERENCES cases(id)
)
"""

RELATIONSHIPS_SCHEMA = """
CREATE TABLE IF NOT EXISTS relationships (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    source_entity_id INTEGER,
    relationship_type TEXT NOT NULL,
    target_entity_id INTEGER,
    source_module TEXT,
    confidence INTEGER DEFAULT 50,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(case_id) REFERENCES cases(id),
    FOREIGN KEY(source_entity_id) REFERENCES entities(id),
    FOREIGN KEY(target_entity_id) REFERENCES entities(id)
)
"""

OBSERVATIONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS observations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    entity_id INTEGER,
    module_id TEXT,
    observation_type TEXT,
    title TEXT,
    summary TEXT,
    data_json TEXT,
    raw_output TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(case_id) REFERENCES cases(id),
    FOREIGN KEY(entity_id) REFERENCES entities(id)
)
"""

OPERATIONS_SCHEMA = """
CREATE TABLE IF NOT EXISTS operations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    module_id TEXT,
    target TEXT,
    status TEXT,
    authorisation_confirmed INTEGER DEFAULT 0,
    summary TEXT,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    FOREIGN KEY(case_id) REFERENCES cases(id)
)
"""

FINDINGS_SCHEMA = """
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    entity_id INTEGER,
    observation_id INTEGER,
    module_id TEXT,
    title TEXT NOT NULL,
    severity TEXT,
    confidence INTEGER DEFAULT 50,
    explanation TEXT,
    suggested_actions_json TEXT,
    status TEXT DEFAULT 'open',
    analyst_notes TEXT,
    user_severity TEXT,
    reviewed_at TIMESTAMP,
    closed_at TIMESTAMP,
    updated_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(case_id) REFERENCES cases(id),
    FOREIGN KEY(entity_id) REFERENCES entities(id),
    FOREIGN KEY(observation_id) REFERENCES observations(id)
)
"""

FINDING_STATUSES: tuple[str, ...] = (
    "open",
    "in_review",
    "action_required",
    "accepted",
    "false_positive",
    "closed",
)
ACTIVE_FINDING_STATUSES: tuple[str, ...] = ("open", "in_review", "action_required")
TERMINAL_FINDING_STATUSES: tuple[str, ...] = ("closed", "accepted", "false_positive")
REPORT_EXCLUDED_STATUSES: tuple[str, ...] = TERMINAL_FINDING_STATUSES

FINDING_COLUMN_MIGRATIONS: tuple[tuple[str, str], ...] = (
    ("analyst_notes", "TEXT"),
    ("user_severity", "TEXT"),
    ("reviewed_at", "TIMESTAMP"),
    ("closed_at", "TIMESTAMP"),
    ("updated_at", "TIMESTAMP"),
)

ALL_SCHEMAS = (
    TARGETS_SCHEMA,
    RECON_DATA_SCHEMA,
    CASES_SCHEMA,
    ENTITIES_SCHEMA,
    RELATIONSHIPS_SCHEMA,
    OBSERVATIONS_SCHEMA,
    OPERATIONS_SCHEMA,
    FINDINGS_SCHEMA,
)


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return dict(row)


def _rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def get_db_conn() -> sqlite3.Connection:
    """Open the Overwatch database, creating the folder and tables if needed."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    for schema in ALL_SCHEMAS:
        conn.execute(schema)
    _migrate_findings_table(conn)
    return conn


def normalize_finding_status(status: str | None) -> str:
    """Map legacy statuses to the current workflow vocabulary."""
    if status == "reviewed":
        return "in_review"
    if status in FINDING_STATUSES:
        return status
    return "open"


def effective_finding_severity(finding: dict[str, Any]) -> str:
    return finding.get("user_severity") or finding.get("severity") or "info"


def _migrate_findings_table(conn: sqlite3.Connection) -> None:
    """Add new finding columns safely and migrate legacy status values."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
    for column_name, column_type in FINDING_COLUMN_MIGRATIONS:
        if column_name not in columns:
            conn.execute(f"ALTER TABLE findings ADD COLUMN {column_name} {column_type}")
    conn.execute("UPDATE findings SET status = 'in_review' WHERE status = 'reviewed'")
    conn.commit()


def infer_entity_type(value: str) -> str:
    """Infer a basic entity type from user input."""
    cleaned = value.strip()

    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", cleaned):
        return "ip_address"
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", cleaned):
        return "email"
    if re.match(
        r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$",
        cleaned,
    ):
        return "domain"
    return "unknown"


def list_cases(conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        rows = conn.execute("SELECT * FROM cases ORDER BY created_at ASC, id ASC").fetchall()
        return _rows_to_dicts(rows)
    finally:
        if own_conn:
            conn.close()


def get_case(case_id: int, conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        return _row_to_dict(conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone())
    finally:
        if own_conn:
            conn.close()


def create_case(
    name: str,
    description: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO cases (name, description) VALUES (?, ?)",
            (name.strip(), description),
        )
        conn.commit()
        case = _row_to_dict(conn.execute("SELECT * FROM cases WHERE id = ?", (cursor.lastrowid,)).fetchone())
        if case is None:
            raise RuntimeError("Failed to create case.")
        return case
    finally:
        if own_conn:
            conn.close()


def get_or_create_default_case(conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        cases = list_cases(conn)
        if cases:
            for case in cases:
                if case["name"] == "Default Case":
                    return case
            return cases[0]
        return create_case(
            "Default Case",
            "Auto-created default investigation case.",
            conn=conn,
        )
    finally:
        if own_conn:
            conn.close()


def create_or_get_entity(
    case_id: int,
    entity_type: str,
    value: str,
    label: str | None = None,
    source: str | None = None,
    confidence: int = 50,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        cleaned_value = value.strip()
        existing = conn.execute(
            "SELECT * FROM entities WHERE case_id = ? AND value = ?",
            (case_id, cleaned_value),
        ).fetchone()
        if existing:
            return dict(existing)

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO entities (case_id, entity_type, value, label, source, confidence)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (case_id, entity_type, cleaned_value, label, source, confidence),
        )
        conn.commit()
        entity = _row_to_dict(conn.execute("SELECT * FROM entities WHERE id = ?", (cursor.lastrowid,)).fetchone())
        if entity is None:
            raise RuntimeError("Failed to create entity.")
        return entity
    finally:
        if own_conn:
            conn.close()


def list_entities(case_id: int | None = None, conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        if case_id is None:
            rows = conn.execute("SELECT * FROM entities ORDER BY created_at DESC, id DESC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM entities WHERE case_id = ? ORDER BY created_at DESC, id DESC",
                (case_id,),
            ).fetchall()
        return _rows_to_dicts(rows)
    finally:
        if own_conn:
            conn.close()


def create_observation(
    case_id: int,
    entity_id: int,
    module_id: str,
    observation_type: str,
    title: str,
    summary: str | None = None,
    data_json: str | None = None,
    raw_output: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        if data_json is not None and not isinstance(data_json, str):
            data_json = json.dumps(data_json)

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO observations (
                case_id, entity_id, module_id, observation_type, title, summary, data_json, raw_output
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (case_id, entity_id, module_id, observation_type, title, summary, data_json, raw_output),
        )
        conn.commit()
        observation = _row_to_dict(
            conn.execute("SELECT * FROM observations WHERE id = ?", (cursor.lastrowid,)).fetchone()
        )
        if observation is None:
            raise RuntimeError("Failed to create observation.")
        return observation
    finally:
        if own_conn:
            conn.close()


def list_observations(
    case_id: int | None = None,
    entity_id: int | None = None,
    conn: sqlite3.Connection | None = None,
) -> list[dict[str, Any]]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        query = "SELECT * FROM observations"
        params: list[Any] = []
        filters: list[str] = []

        if case_id is not None:
            filters.append("case_id = ?")
            params.append(case_id)
        if entity_id is not None:
            filters.append("entity_id = ?")
            params.append(entity_id)

        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY created_at DESC, id DESC"

        rows = conn.execute(query, params).fetchall()
        return _rows_to_dicts(rows)
    finally:
        if own_conn:
            conn.close()


def create_operation_log(
    case_id: int,
    module_id: str,
    target: str,
    status: str,
    authorisation_confirmed: bool = False,
    summary: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        completed_at = datetime.now(timezone.utc).isoformat()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO operations (
                case_id, module_id, target, status, authorisation_confirmed, summary, completed_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                module_id,
                target,
                status,
                1 if authorisation_confirmed else 0,
                summary,
                completed_at,
            ),
        )
        conn.commit()
        operation = _row_to_dict(conn.execute("SELECT * FROM operations WHERE id = ?", (cursor.lastrowid,)).fetchone())
        if operation is None:
            raise RuntimeError("Failed to create operation log.")
        return operation
    finally:
        if own_conn:
            conn.close()


def list_operations(case_id: int | None = None, conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        if case_id is None:
            rows = conn.execute("SELECT * FROM operations ORDER BY started_at DESC, id DESC").fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM operations WHERE case_id = ? ORDER BY started_at DESC, id DESC",
                (case_id,),
            ).fetchall()
        return _rows_to_dicts(rows)
    finally:
        if own_conn:
            conn.close()


def relationship_exists(
    case_id: int,
    source_entity_id: int,
    relationship_type: str,
    target_entity_id: int,
    conn: sqlite3.Connection | None = None,
) -> bool:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        row = conn.execute(
            """
            SELECT 1 FROM relationships
            WHERE case_id = ? AND source_entity_id = ? AND relationship_type = ? AND target_entity_id = ?
            """,
            (case_id, source_entity_id, relationship_type, target_entity_id),
        ).fetchone()
        return row is not None
    finally:
        if own_conn:
            conn.close()


def create_relationship(
    case_id: int,
    source_entity_id: int,
    relationship_type: str,
    target_entity_id: int,
    source_module: str | None = None,
    confidence: int = 50,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """Create a relationship, returning the existing row if it already exists."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        existing = conn.execute(
            """
            SELECT * FROM relationships
            WHERE case_id = ? AND source_entity_id = ? AND relationship_type = ? AND target_entity_id = ?
            """,
            (case_id, source_entity_id, relationship_type, target_entity_id),
        ).fetchone()
        if existing:
            return dict(existing)

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO relationships (
                case_id, source_entity_id, relationship_type, target_entity_id, source_module, confidence
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (case_id, source_entity_id, relationship_type, target_entity_id, source_module, confidence),
        )
        conn.commit()
        relationship = _row_to_dict(
            conn.execute("SELECT * FROM relationships WHERE id = ?", (cursor.lastrowid,)).fetchone()
        )
        if relationship is None:
            raise RuntimeError("Failed to create relationship.")
        return relationship
    finally:
        if own_conn:
            conn.close()


def list_relationships(case_id: int | None = None, conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        if case_id is None:
            rows = conn.execute(
                "SELECT * FROM relationships ORDER BY created_at DESC, id DESC"
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM relationships WHERE case_id = ? ORDER BY created_at DESC, id DESC",
                (case_id,),
            ).fetchall()
        return _rows_to_dicts(rows)
    finally:
        if own_conn:
            conn.close()


def _finding_exists(
    case_id: int,
    entity_id: int | None,
    module_id: str,
    title: str,
    conn: sqlite3.Connection,
) -> dict[str, Any] | None:
    if entity_id is None:
        row = conn.execute(
            """
            SELECT * FROM findings
            WHERE case_id = ? AND entity_id IS NULL AND module_id = ? AND title = ?
            """,
            (case_id, module_id, title),
        ).fetchone()
    else:
        row = conn.execute(
            """
            SELECT * FROM findings
            WHERE case_id = ? AND entity_id = ? AND module_id = ? AND title = ?
            """,
            (case_id, entity_id, module_id, title),
        ).fetchone()
    return _row_to_dict(row)


def create_finding(
    case_id: int,
    module_id: str,
    title: str,
    severity: str,
    confidence: int,
    explanation: str,
    suggested_actions: list[str] | None = None,
    entity_id: int | None = None,
    observation_id: int | None = None,
    status: str = "open",
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """Create a finding, returning the existing row when a duplicate should not be recreated."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        existing = _finding_exists(case_id, entity_id, module_id, title, conn)
        if existing:
            existing_status = normalize_finding_status(existing.get("status"))
            # Do not duplicate active or terminal findings; do not auto-reopen terminal items.
            if existing_status in ACTIVE_FINDING_STATUSES or existing_status in TERMINAL_FINDING_STATUSES:
                return existing
            return existing

        actions_json = json.dumps(suggested_actions or [])
        now = datetime.now(timezone.utc).isoformat()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO findings (
                case_id, entity_id, observation_id, module_id, title, severity,
                confidence, explanation, suggested_actions_json, status, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                entity_id,
                observation_id,
                module_id,
                title,
                severity,
                confidence,
                explanation,
                actions_json,
                normalize_finding_status(status),
                now,
            ),
        )
        conn.commit()
        finding = _row_to_dict(conn.execute("SELECT * FROM findings WHERE id = ?", (cursor.lastrowid,)).fetchone())
        if finding is None:
            raise RuntimeError("Failed to create finding.")
        return finding
    finally:
        if own_conn:
            conn.close()


def upsert_finding(
    case_id: int,
    module_id: str,
    title: str,
    severity: str,
    confidence: int,
    explanation: str,
    suggested_actions: list[str] | None = None,
    entity_id: int | None = None,
    observation_id: int | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """Create or refresh a finding without changing analyst-closed terminal status."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        existing = _finding_exists(case_id, entity_id, module_id, title, conn)
        actions_json = json.dumps(suggested_actions or [])
        now = datetime.now(timezone.utc).isoformat()
        if existing:
            existing_status = normalize_finding_status(existing.get("status"))
            conn.execute(
                """
                UPDATE findings
                SET observation_id = ?, severity = ?, confidence = ?, explanation = ?,
                    suggested_actions_json = ?, updated_at = ?
                WHERE id = ?
                """,
                (
                    observation_id,
                    severity,
                    confidence,
                    explanation,
                    actions_json,
                    now,
                    existing["id"],
                ),
            )
            conn.commit()
            updated = _row_to_dict(
                conn.execute("SELECT * FROM findings WHERE id = ?", (existing["id"],)).fetchone()
            )
            if updated is None:
                raise RuntimeError("Failed to update finding.")
            # TODO(v1.2): stale finding handling — optionally reopen terminal findings when re-observed.
            if existing_status in TERMINAL_FINDING_STATUSES:
                return updated
            if existing_status in ACTIVE_FINDING_STATUSES:
                return updated
            return updated

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO findings (
                case_id, entity_id, observation_id, module_id, title, severity,
                confidence, explanation, suggested_actions_json, status, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?)
            """,
            (
                case_id,
                entity_id,
                observation_id,
                module_id,
                title,
                severity,
                confidence,
                explanation,
                actions_json,
                now,
            ),
        )
        conn.commit()
        finding = _row_to_dict(conn.execute("SELECT * FROM findings WHERE id = ?", (cursor.lastrowid,)).fetchone())
        if finding is None:
            raise RuntimeError("Failed to create finding.")
        return finding
    finally:
        if own_conn:
            conn.close()


def close_superseded_findings(
    case_id: int,
    entity_id: int | None,
    module_id: str,
    active_titles: list[str],
    conn: sqlite3.Connection | None = None,
) -> int:
    """Close active findings for a module run that are no longer present."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        active_status_sql = ", ".join(f"'{status}'" for status in ACTIVE_FINDING_STATUSES)
        if entity_id is None:
            rows = conn.execute(
                f"""
                SELECT id, title, explanation FROM findings
                WHERE case_id = ? AND entity_id IS NULL AND module_id = ?
                  AND status IN ({active_status_sql})
                """,
                (case_id, module_id),
            ).fetchall()
        else:
            rows = conn.execute(
                f"""
                SELECT id, title, explanation FROM findings
                WHERE case_id = ? AND entity_id = ? AND module_id = ?
                  AND status IN ({active_status_sql})
                """,
                (case_id, entity_id, module_id),
            ).fetchall()

        closed = 0
        active_set = set(active_titles)
        suffix = " [Superseded: not observed in latest module run.]"
        now = datetime.now(timezone.utc).isoformat()
        for row in rows:
            finding = dict(row)
            if finding["title"] in active_set:
                continue
            explanation = (finding.get("explanation") or "") + suffix
            conn.execute(
                """
                UPDATE findings
                SET status = 'closed', explanation = ?, closed_at = ?, updated_at = ?
                WHERE id = ?
                """,
                (explanation, now, now, finding["id"]),
            )
            closed += 1
        if closed:
            conn.commit()
        return closed
    finally:
        if own_conn:
            conn.close()


def list_findings(
    case_id: int | None = None,
    entity_id: int | None = None,
    module_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> list[dict[str, Any]]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        query = "SELECT * FROM findings"
        params: list[Any] = []
        filters: list[str] = []

        if case_id is not None:
            filters.append("case_id = ?")
            params.append(case_id)
        if entity_id is not None:
            filters.append("entity_id = ?")
            params.append(entity_id)
        if module_id is not None:
            filters.append("module_id = ?")
            params.append(module_id)
        if severity is not None:
            filters.append("severity = ?")
            params.append(severity)
        if status is not None:
            filters.append("status = ?")
            params.append(status)

        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY created_at DESC, id DESC"

        rows = conn.execute(query, params).fetchall()
        return _rows_to_dicts(rows)
    finally:
        if own_conn:
            conn.close()


def get_finding(finding_id: int, conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        return _row_to_dict(conn.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone())
    finally:
        if own_conn:
            conn.close()


def update_finding(
    finding_id: int,
    *,
    status: str | None = None,
    analyst_notes: str | None = None,
    user_severity: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any] | None:
    """Update analyst workflow fields on a finding."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        existing = get_finding(finding_id, conn=conn)
        if existing is None:
            return None

        now = datetime.now(timezone.utc).isoformat()
        fields: list[str] = ["updated_at = ?"]
        params: list[Any] = [now]

        if status is not None:
            normalized = normalize_finding_status(status)
            fields.append("status = ?")
            params.append(normalized)
            if normalized == "in_review" and not existing.get("reviewed_at"):
                fields.append("reviewed_at = ?")
                params.append(now)
            if normalized in TERMINAL_FINDING_STATUSES and not existing.get("closed_at"):
                fields.append("closed_at = ?")
                params.append(now)
            if normalized in ACTIVE_FINDING_STATUSES:
                fields.append("closed_at = ?")
                params.append(None)

        if analyst_notes is not None:
            fields.append("analyst_notes = ?")
            params.append(analyst_notes)

        if user_severity is not None:
            fields.append("user_severity = ?")
            params.append(user_severity or None)

        params.append(finding_id)
        conn.execute(f"UPDATE findings SET {', '.join(fields)} WHERE id = ?", params)
        conn.commit()
        return get_finding(finding_id, conn=conn)
    finally:
        if own_conn:
            conn.close()


def close_finding(
    finding_id: int,
    analyst_notes: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any] | None:
    notes = analyst_notes
    if notes is None:
        existing = get_finding(finding_id, conn=conn)
        notes = existing.get("analyst_notes") if existing else None
    return update_finding(
        finding_id,
        status="closed",
        analyst_notes=notes,
        conn=conn,
    )


def reopen_finding(finding_id: int, conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    return update_finding(finding_id, status="open", conn=conn)


def list_findings_by_entity(
    entity_id: int,
    conn: sqlite3.Connection | None = None,
) -> list[dict[str, Any]]:
    return list_findings(entity_id=entity_id, conn=conn)


def finding_status_counts(case_id: int, conn: sqlite3.Connection | None = None) -> dict[str, int]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        rows = conn.execute(
            "SELECT status, COUNT(*) AS count FROM findings WHERE case_id = ? GROUP BY status",
            (case_id,),
        ).fetchall()
        counts = {normalize_finding_status(row["status"]): row["count"] for row in rows}
        for status in FINDING_STATUSES:
            counts.setdefault(status, 0)
        return counts
    finally:
        if own_conn:
            conn.close()


def update_finding_status(
    finding_id: int,
    status: str,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any] | None:
    """Backward-compatible status update wrapper."""
    return update_finding(finding_id, status=status, conn=conn)

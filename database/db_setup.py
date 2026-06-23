"""SQLite database setup and investigation model helpers for Project Overwatch."""

from __future__ import annotations

import hashlib
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

PIVOT_QUEUE_SCHEMA = """
CREATE TABLE IF NOT EXISTS pivot_queue_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    entity_id INTEGER NOT NULL,
    position INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(case_id) REFERENCES cases(id),
    FOREIGN KEY(entity_id) REFERENCES entities(id),
    UNIQUE(case_id, entity_id)
)
"""

BATCH_QUEUE_ITEMS_SCHEMA = """
CREATE TABLE IF NOT EXISTS batch_queue_items (
    queue_id TEXT PRIMARY KEY,
    case_id INTEGER NOT NULL,
    entity_id INTEGER NOT NULL,
    entity_value TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    execution_target TEXT,
    module_id TEXT NOT NULL,
    module_display_name TEXT,
    mode TEXT,
    compatibility_status TEXT,
    status TEXT DEFAULT 'queued',
    position INTEGER DEFAULT 0,
    summary TEXT,
    recent_run_warning TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    FOREIGN KEY(case_id) REFERENCES cases(id),
    FOREIGN KEY(entity_id) REFERENCES entities(id)
)
"""

BATCH_QUEUE_RUNS_SCHEMA = """
CREATE TABLE IF NOT EXISTS batch_queue_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMP,
    items_processed INTEGER DEFAULT 0,
    items_completed INTEGER DEFAULT 0,
    items_warnings INTEGER DEFAULT 0,
    items_failed INTEGER DEFAULT 0,
    run_summary TEXT,
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

CASE_COLUMN_MIGRATIONS: tuple[tuple[str, str], ...] = (
    ("default_run_mode", "TEXT"),
)

OPERATION_COLUMN_MIGRATIONS: tuple[tuple[str, str], ...] = (
    ("run_mode_id", "TEXT"),
    ("run_mode_label", "TEXT"),
)

OBSERVATION_EVIDENCE_MIGRATIONS: tuple[tuple[str, str], ...] = (
    ("evidence_type", "TEXT"),
    ("source_name", "TEXT"),
    ("source_url", "TEXT"),
    ("reliability", "TEXT"),
    ("collection_method", "TEXT"),
    ("collected_at", "TIMESTAMP"),
    ("module_version", "TEXT"),
)

FINDING_EVIDENCE_MIGRATIONS: tuple[tuple[str, str], ...] = (
    ("evidence_type", "TEXT"),
    ("source_name", "TEXT"),
    ("reliability", "TEXT"),
)

RELATIONSHIP_EVIDENCE_MIGRATIONS: tuple[tuple[str, str], ...] = (
    ("evidence_type", "TEXT"),
    ("reliability", "TEXT"),
)

EVIDENCE_ITEMS_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    entity_id INTEGER,
    observation_id INTEGER,
    finding_id INTEGER,
    module_id TEXT,
    evidence_type TEXT,
    source_name TEXT,
    source_url TEXT,
    collection_method TEXT,
    title TEXT,
    summary TEXT,
    content_type TEXT,
    content_text TEXT,
    content_hash TEXT,
    storage_path TEXT,
    reliability TEXT,
    confidence INTEGER,
    captured_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(case_id) REFERENCES cases(id),
    FOREIGN KEY(entity_id) REFERENCES entities(id),
    FOREIGN KEY(observation_id) REFERENCES observations(id),
    FOREIGN KEY(finding_id) REFERENCES findings(id)
)
"""

EVIDENCE_FINDING_LINKS_SCHEMA = """
CREATE TABLE IF NOT EXISTS evidence_finding_links (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    evidence_id INTEGER NOT NULL,
    finding_id INTEGER NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(evidence_id) REFERENCES evidence_items(id),
    FOREIGN KEY(finding_id) REFERENCES findings(id),
    UNIQUE(evidence_id, finding_id)
)
"""

RDAP_LOOKUP_CACHE_SCHEMA = """
CREATE TABLE IF NOT EXISTS rdap_lookup_cache (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    query_key TEXT NOT NULL,
    target_type TEXT NOT NULL,
    source TEXT NOT NULL,
    response_json TEXT NOT NULL,
    rdap_url TEXT,
    whois_server TEXT,
    fetched_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(case_id) REFERENCES cases(id),
    UNIQUE(case_id, query_key)
)
"""

ALL_SCHEMAS = (
    TARGETS_SCHEMA,
    RECON_DATA_SCHEMA,
    CASES_SCHEMA,
    ENTITIES_SCHEMA,
    RELATIONSHIPS_SCHEMA,
    OBSERVATIONS_SCHEMA,
    OPERATIONS_SCHEMA,
    FINDINGS_SCHEMA,
    PIVOT_QUEUE_SCHEMA,
    BATCH_QUEUE_ITEMS_SCHEMA,
    BATCH_QUEUE_RUNS_SCHEMA,
    EVIDENCE_ITEMS_SCHEMA,
    EVIDENCE_FINDING_LINKS_SCHEMA,
    RDAP_LOOKUP_CACHE_SCHEMA,
)


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return dict(row)


def _rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


STALE_REOPEN_NOTE = "[Reopened automatically: same issue re-observed on module re-scan.]"


def get_db_conn() -> sqlite3.Connection:
    """Open the Overwatch database, creating the folder and tables if needed."""
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    for schema in ALL_SCHEMAS:
        conn.execute(schema)
    _migrate_findings_table(conn)
    _migrate_cases_table(conn)
    _migrate_operations_table(conn)
    ensure_evidence_columns(conn)
    from database.engagements import ensure_engagement_tables

    ensure_engagement_tables(conn)
    from database.personal_lab import ensure_personal_lab_tables

    ensure_personal_lab_tables(conn)
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


def _migrate_cases_table(conn: sqlite3.Connection) -> None:
    """Add optional case columns safely."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
    for column_name, column_type in CASE_COLUMN_MIGRATIONS:
        if column_name not in columns:
            conn.execute(f"ALTER TABLE cases ADD COLUMN {column_name} {column_type}")
    conn.commit()


def _migrate_operations_table(conn: sqlite3.Connection) -> None:
    """Add optional operation columns safely."""
    columns = {row[1] for row in conn.execute("PRAGMA table_info(operations)").fetchall()}
    for column_name, column_type in OPERATION_COLUMN_MIGRATIONS:
        if column_name not in columns:
            conn.execute(f"ALTER TABLE operations ADD COLUMN {column_name} {column_type}")
    conn.commit()


def _add_missing_columns(
    conn: sqlite3.Connection,
    table_name: str,
    migrations: tuple[tuple[str, str], ...],
) -> None:
    columns = {row[1] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()}
    for column_name, column_type in migrations:
        if column_name not in columns:
            conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")


def ensure_evidence_columns(conn: sqlite3.Connection | None = None) -> None:
    """Add evidence metadata columns to observations, findings, and relationships."""
    own_conn = conn is None
    if own_conn:
        conn = sqlite3.connect(str(DB_PATH), timeout=5.0)
    try:
        _add_missing_columns(conn, "observations", OBSERVATION_EVIDENCE_MIGRATIONS)
        _add_missing_columns(conn, "findings", FINDING_EVIDENCE_MIGRATIONS)
        _add_missing_columns(conn, "relationships", RELATIONSHIP_EVIDENCE_MIGRATIONS)
        conn.commit()
    finally:
        if own_conn:
            conn.close()


def normalise_evidence_type(value: str | None) -> str | None:
    from utils.evidence_model import normalise_evidence_type as _normalise_evidence_type

    return _normalise_evidence_type(value)


def normalise_reliability(value: str | None) -> str | None:
    from utils.evidence_model import normalise_reliability as _normalise_reliability

    return _normalise_reliability(value)


def default_evidence_for_module(module_id: str) -> dict[str, Any]:
    from utils.evidence_model import default_evidence_for_module as _default_evidence_for_module

    return _default_evidence_for_module(module_id)


def attach_evidence_metadata(
    record_data: dict[str, Any],
    module_id: str,
    source_name: str | None = None,
    source_url: str | None = None,
) -> dict[str, Any]:
    from utils.evidence_model import attach_evidence_metadata as _attach_evidence_metadata

    return _attach_evidence_metadata(record_data, module_id, source_name, source_url)


def update_case_run_mode(
    case_id: int,
    run_mode_id: str,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any] | None:
    """Persist the last-used run mode for a case."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        conn.execute(
            """
            UPDATE cases
            SET default_run_mode = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            """,
            (run_mode_id, case_id),
        )
        conn.commit()
        return get_case(case_id, conn=conn)
    finally:
        if own_conn:
            conn.close()


def operation_run_mode_counts(
    case_id: int,
    conn: sqlite3.Connection | None = None,
) -> dict[str, int]:
    """Count operations grouped by run mode label for a case."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        rows = conn.execute(
            """
            SELECT COALESCE(run_mode_label, 'Unknown') AS mode_label, COUNT(*) AS total
            FROM operations
            WHERE case_id = ?
            GROUP BY COALESCE(run_mode_label, 'Unknown')
            ORDER BY total DESC, mode_label ASC
            """,
            (case_id,),
        ).fetchall()
        return {str(row["mode_label"]): int(row["total"]) for row in rows}
    finally:
        if own_conn:
            conn.close()


def infer_entity_type(value: str) -> str:
    """Infer a basic entity type from user input."""
    from utils.target_detection import get_target_type, target_type_to_entity_type

    return target_type_to_entity_type(get_target_type(value))


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


def get_entity(entity_id: int, conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    """Return a single entity row by id."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        return _row_to_dict(conn.execute("SELECT * FROM entities WHERE id = ?", (entity_id,)).fetchone())
    finally:
        if own_conn:
            conn.close()


def update_entity_notes(
    entity_id: int,
    notes: str | None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any] | None:
    """Update analyst notes on an entity."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        existing = get_entity(entity_id, conn=conn)
        if existing is None:
            return None
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE entities SET notes = ?, updated_at = ? WHERE id = ?",
            (notes, now, entity_id),
        )
        conn.commit()
        return get_entity(entity_id, conn=conn)
    finally:
        if own_conn:
            conn.close()


def update_entity_label(
    entity_id: int,
    label: str | None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any] | None:
    """Update the display label on an entity."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        existing = get_entity(entity_id, conn=conn)
        if existing is None:
            return None
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE entities SET label = ?, updated_at = ? WHERE id = ?",
            (label, now, entity_id),
        )
        conn.commit()
        return get_entity(entity_id, conn=conn)
    finally:
        if own_conn:
            conn.close()


def update_entity_confidence(
    entity_id: int,
    confidence: int,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any] | None:
    """Update confidence score on an entity."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        existing = get_entity(entity_id, conn=conn)
        if existing is None:
            return None
        bounded = max(0, min(100, int(confidence)))
        now = datetime.now(timezone.utc).isoformat()
        conn.execute(
            "UPDATE entities SET confidence = ?, updated_at = ? WHERE id = ?",
            (bounded, now, entity_id),
        )
        conn.commit()
        return get_entity(entity_id, conn=conn)
    finally:
        if own_conn:
            conn.close()


def list_pivot_queue(
    case_id: int,
    conn: sqlite3.Connection | None = None,
) -> list[dict[str, Any]]:
    """Return pivot queue rows for a case, ordered by position then created_at."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        rows = conn.execute(
            """
            SELECT * FROM pivot_queue_items
            WHERE case_id = ?
            ORDER BY position ASC, created_at ASC, id ASC
            """,
            (case_id,),
        ).fetchall()
        return _rows_to_dicts(rows)
    finally:
        if own_conn:
            conn.close()


def list_pivot_queue_entity_ids(
    case_id: int,
    conn: sqlite3.Connection | None = None,
) -> list[int]:
    """Return entity ids in the case pivot queue."""
    return [row["entity_id"] for row in list_pivot_queue(case_id, conn=conn)]


def pivot_queue_contains(
    case_id: int,
    entity_id: int,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Return True when the entity is already queued for the case."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        row = conn.execute(
            "SELECT 1 FROM pivot_queue_items WHERE case_id = ? AND entity_id = ? LIMIT 1",
            (case_id, entity_id),
        ).fetchone()
        return row is not None
    finally:
        if own_conn:
            conn.close()


def add_to_pivot_queue(
    case_id: int,
    entity_id: int,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any] | None:
    """Add an entity to the case pivot queue. Returns the queue row or existing row."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        entity = get_entity(entity_id, conn=conn)
        if entity is None or entity.get("case_id") != case_id:
            return None

        existing = conn.execute(
            "SELECT * FROM pivot_queue_items WHERE case_id = ? AND entity_id = ?",
            (case_id, entity_id),
        ).fetchone()
        if existing:
            return dict(existing)

        position_row = conn.execute(
            "SELECT COALESCE(MAX(position), -1) + 1 AS next_pos FROM pivot_queue_items WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        next_position = int(position_row["next_pos"]) if position_row else 0

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO pivot_queue_items (case_id, entity_id, position)
            VALUES (?, ?, ?)
            """,
            (case_id, entity_id, next_position),
        )
        conn.commit()
        return _row_to_dict(
            conn.execute(
                "SELECT * FROM pivot_queue_items WHERE id = ?",
                (cursor.lastrowid,),
            ).fetchone()
        )
    finally:
        if own_conn:
            conn.close()


def remove_from_pivot_queue(
    case_id: int,
    entity_id: int,
    conn: sqlite3.Connection | None = None,
) -> bool:
    """Remove an entity from the case pivot queue."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        cursor = conn.execute(
            "DELETE FROM pivot_queue_items WHERE case_id = ? AND entity_id = ?",
            (case_id, entity_id),
        )
        conn.commit()
        return cursor.rowcount > 0
    finally:
        if own_conn:
            conn.close()


def clear_pivot_queue(
    case_id: int,
    conn: sqlite3.Connection | None = None,
) -> int:
    """Clear all pivot queue items for a case. Returns rows removed."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        cursor = conn.execute("DELETE FROM pivot_queue_items WHERE case_id = ?", (case_id,))
        conn.commit()
        return cursor.rowcount
    finally:
        if own_conn:
            conn.close()


def list_batch_queue_items(
    case_id: int,
    conn: sqlite3.Connection | None = None,
) -> list[dict[str, Any]]:
    """Return batch queue items for a case ordered by position."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        rows = conn.execute(
            """
            SELECT * FROM batch_queue_items
            WHERE case_id = ?
            ORDER BY position ASC, created_at ASC
            """,
            (case_id,),
        ).fetchall()
        return _rows_to_dicts(rows)
    finally:
        if own_conn:
            conn.close()


def sync_batch_queue_items(
    case_id: int,
    items: list[dict[str, Any]],
    conn: sqlite3.Connection | None = None,
) -> None:
    """Replace persisted batch queue items for a case with the provided list."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        conn.execute("DELETE FROM batch_queue_items WHERE case_id = ?", (case_id,))
        for index, item in enumerate(items):
            conn.execute(
                """
                INSERT INTO batch_queue_items (
                    queue_id, case_id, entity_id, entity_value, entity_type, execution_target,
                    module_id, module_display_name, mode, compatibility_status, status,
                    position, summary, recent_run_warning, created_at, completed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item["queue_id"],
                    case_id,
                    item["entity_id"],
                    item.get("entity_value") or "",
                    item.get("entity_type") or "unknown",
                    item.get("execution_target"),
                    item["module_id"],
                    item.get("module_display_name"),
                    item.get("mode"),
                    item.get("compatibility_status"),
                    item.get("status", "queued"),
                    item.get("position", index),
                    item.get("summary"),
                    item.get("recent_run_warning"),
                    item.get("created_at") or datetime.now(timezone.utc).isoformat(),
                    item.get("completed_at"),
                ),
            )
        conn.commit()
    finally:
        if own_conn:
            conn.close()


def batch_queue_item_counts(
    conn: sqlite3.Connection | None = None,
) -> dict[int, dict[str, int]]:
    """Return per-case batch queue counts: total and queued items."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        rows = conn.execute(
            """
            SELECT case_id,
                   COUNT(*) AS total,
                   SUM(CASE WHEN status = 'queued' THEN 1 ELSE 0 END) AS queued
            FROM batch_queue_items
            GROUP BY case_id
            """
        ).fetchall()
        return {
            int(row["case_id"]): {"total": int(row["total"]), "queued": int(row["queued"] or 0)}
            for row in rows
        }
    finally:
        if own_conn:
            conn.close()


def create_batch_queue_run(
    case_id: int,
    *,
    items_processed: int,
    items_completed: int,
    items_warnings: int,
    items_failed: int,
    run_summary: str,
    started_at: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """Persist a batch queue run summary for reporting."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        completed_at = datetime.now(timezone.utc).isoformat()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO batch_queue_runs (
                case_id, started_at, completed_at,
                items_processed, items_completed, items_warnings, items_failed, run_summary
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                started_at or completed_at,
                completed_at,
                items_processed,
                items_completed,
                items_warnings,
                items_failed,
                run_summary,
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT * FROM batch_queue_runs WHERE id = ?",
            (cursor.lastrowid,),
        ).fetchone()
        result = _row_to_dict(row)
        if result is None:
            raise RuntimeError("Failed to create batch queue run record.")
        return result
    finally:
        if own_conn:
            conn.close()


def list_batch_queue_runs(
    case_id: int,
    *,
    limit: int = 10,
    conn: sqlite3.Connection | None = None,
) -> list[dict[str, Any]]:
    """Return recent batch queue runs for a case."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        rows = conn.execute(
            """
            SELECT * FROM batch_queue_runs
            WHERE case_id = ?
            ORDER BY completed_at DESC, id DESC
            LIMIT ?
            """,
            (case_id, limit),
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
    evidence_type: str | None = None,
    source_name: str | None = None,
    source_url: str | None = None,
    reliability: str | None = None,
    collection_method: str | None = None,
    collected_at: str | None = None,
    module_version: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        if data_json is not None and not isinstance(data_json, str):
            data_json = json.dumps(data_json)

        from utils.security import redact_secrets_from_text, sanitize_json_for_storage

        title = redact_secrets_from_text(title)
        if summary is not None:
            summary = redact_secrets_from_text(summary)
        if raw_output is not None:
            raw_output = redact_secrets_from_text(raw_output)
        if data_json is not None:
            data_json = sanitize_json_for_storage(data_json)

        evidence = attach_evidence_metadata({}, module_id, source_name, source_url)
        if evidence_type is not None:
            evidence["evidence_type"] = normalise_evidence_type(evidence_type)
        if reliability is not None:
            evidence["reliability"] = normalise_reliability(reliability)
        if collection_method is not None:
            evidence["collection_method"] = collection_method
        if collected_at is not None:
            evidence["collected_at"] = collected_at
        if module_version is not None:
            evidence["module_version"] = module_version

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO observations (
                case_id, entity_id, module_id, observation_type, title, summary, data_json,
                raw_output, evidence_type, source_name, source_url, reliability,
                collection_method, collected_at, module_version
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                entity_id,
                module_id,
                observation_type,
                title,
                summary,
                data_json,
                raw_output,
                evidence.get("evidence_type"),
                evidence.get("source_name"),
                evidence.get("source_url"),
                evidence.get("reliability"),
                evidence.get("collection_method"),
                evidence.get("collected_at"),
                evidence.get("module_version"),
            ),
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
    run_mode_id: str | None = None,
    run_mode_label: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        from utils.security import redact_secrets_from_text

        if summary is not None:
            summary = redact_secrets_from_text(summary)

        completed_at = datetime.now(timezone.utc).isoformat()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO operations (
                case_id, module_id, target, status, authorisation_confirmed,
                summary, completed_at, run_mode_id, run_mode_label
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                module_id,
                target,
                status,
                1 if authorisation_confirmed else 0,
                summary,
                completed_at,
                run_mode_id,
                run_mode_label,
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
    evidence_type: str | None = None,
    reliability: str | None = None,
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

        rel_evidence_type = normalise_evidence_type(evidence_type)
        rel_reliability = normalise_reliability(reliability)
        if source_module and (rel_evidence_type is None or rel_reliability is None):
            from utils.evidence_model import default_relationship_evidence

            defaults = default_relationship_evidence(source_module, relationship_type)
            rel_evidence_type = rel_evidence_type or defaults.get("evidence_type")
            rel_reliability = rel_reliability or defaults.get("reliability")

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO relationships (
                case_id, source_entity_id, relationship_type, target_entity_id,
                source_module, confidence, evidence_type, reliability
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                source_entity_id,
                relationship_type,
                target_entity_id,
                source_module,
                confidence,
                rel_evidence_type,
                rel_reliability,
            ),
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
    evidence_type: str | None = None,
    source_name: str | None = None,
    reliability: str | None = None,
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

        from utils.evidence_model import default_finding_evidence

        finding_evidence = default_finding_evidence(module_id)
        resolved_evidence_type = normalise_evidence_type(evidence_type) or finding_evidence.get("evidence_type")
        resolved_source_name = source_name or finding_evidence.get("source_name")
        resolved_reliability = normalise_reliability(reliability) or finding_evidence.get("reliability")

        from utils.security import redact_secrets_from_dict, redact_secrets_from_text

        title = redact_secrets_from_text(title)
        explanation = redact_secrets_from_text(explanation)
        actions_json = json.dumps(redact_secrets_from_dict(suggested_actions or []))
        now = datetime.now(timezone.utc).isoformat()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO findings (
                case_id, entity_id, observation_id, module_id, title, severity,
                confidence, explanation, suggested_actions_json, status, updated_at,
                evidence_type, source_name, reliability
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                resolved_evidence_type,
                resolved_source_name,
                resolved_reliability,
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
    evidence_type: str | None = None,
    source_name: str | None = None,
    reliability: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """Create or refresh a finding without changing analyst-closed terminal status."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        from utils.evidence_model import default_finding_evidence

        finding_evidence = default_finding_evidence(
            module_id,
            {
                "evidence_type": evidence_type,
                "source_name": source_name,
                "reliability": reliability,
            },
        )
        resolved_evidence_type = normalise_evidence_type(evidence_type) or finding_evidence.get("evidence_type")
        resolved_source_name = source_name or finding_evidence.get("source_name")
        resolved_reliability = normalise_reliability(reliability) or finding_evidence.get("reliability")

        existing = _finding_exists(case_id, entity_id, module_id, title, conn)
        actions_json = json.dumps(suggested_actions or [])
        now = datetime.now(timezone.utc).isoformat()
        if existing:
            existing_status = normalize_finding_status(existing.get("status"))
            reopen_terminal = existing_status in TERMINAL_FINDING_STATUSES
            analyst_notes = existing.get("analyst_notes") or ""
            if reopen_terminal and STALE_REOPEN_NOTE not in analyst_notes:
                analyst_notes = (
                    f"{analyst_notes}\n{STALE_REOPEN_NOTE}".strip()
                    if analyst_notes
                    else STALE_REOPEN_NOTE
                )

            if reopen_terminal:
                conn.execute(
                    """
                    UPDATE findings
                    SET status = 'open', observation_id = ?, severity = ?, confidence = ?,
                        explanation = ?, suggested_actions_json = ?, analyst_notes = ?,
                        evidence_type = ?, source_name = ?, reliability = ?,
                        closed_at = NULL, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        observation_id,
                        severity,
                        confidence,
                        explanation,
                        actions_json,
                        analyst_notes,
                        resolved_evidence_type,
                        resolved_source_name,
                        resolved_reliability,
                        now,
                        existing["id"],
                    ),
                )
            else:
                conn.execute(
                    """
                    UPDATE findings
                    SET observation_id = ?, severity = ?, confidence = ?, explanation = ?,
                        suggested_actions_json = ?, evidence_type = ?, source_name = ?,
                        reliability = ?, updated_at = ?
                    WHERE id = ?
                    """,
                    (
                        observation_id,
                        severity,
                        confidence,
                        explanation,
                        actions_json,
                        resolved_evidence_type,
                        resolved_source_name,
                        resolved_reliability,
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
            return updated

        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO findings (
                case_id, entity_id, observation_id, module_id, title, severity,
                confidence, explanation, suggested_actions_json, status, updated_at,
                evidence_type, source_name, reliability
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open', ?, ?, ?, ?)
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
                resolved_evidence_type,
                resolved_source_name,
                resolved_reliability,
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

        if analyst_notes is not None:
            from utils.security import redact_secrets_from_text

            analyst_notes = redact_secrets_from_text(analyst_notes)

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


def _content_looks_like_secret(content_text: str) -> bool:
    from utils.security import looks_like_secret

    return looks_like_secret(content_text)


def calculate_content_hash(content_text: str | None) -> str | None:
    """Return a SHA-256 hash for text content, or None when empty or secret-like."""
    if content_text is None:
        return None
    text = str(content_text)
    if not text.strip():
        return None
    if _content_looks_like_secret(text):
        return None
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def calculate_content_hash_bytes(content_bytes: bytes | None) -> str | None:
    """Return a SHA-256 hash for binary content, or None when empty."""
    if not content_bytes:
        return None
    return hashlib.sha256(content_bytes).hexdigest()


def create_evidence_item(
    case_id: int,
    module_id: str,
    title: str,
    *,
    summary: str | None = None,
    content_text: str | None = None,
    content_bytes: bytes | None = None,
    content_type: str = "text/plain",
    entity_id: int | None = None,
    observation_id: int | None = None,
    finding_id: int | None = None,
    evidence_type: str | None = None,
    source_name: str | None = None,
    source_url: str | None = None,
    collection_method: str | None = None,
    reliability: str | None = None,
    confidence: int | None = None,
    storage_path: str | None = None,
    captured_at: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    """Create a text or binary artefact in the evidence locker."""
    from utils.evidence_storage import (
        inline_binary_preview,
        inline_evidence_content,
        should_spill_bytes,
        should_spill_content,
        spill_binary_content,
        spill_evidence_content,
    )

    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        from utils.security import redact_secrets_from_text

        raw_content = redact_secrets_from_text(content_text) if content_text else None
        if summary is not None:
            summary = redact_secrets_from_text(summary)
        if title is not None:
            title = redact_secrets_from_text(title)
        raw_bytes = content_bytes if content_bytes else None
        spill = storage_path is None and (
            should_spill_bytes(raw_bytes) if raw_bytes else should_spill_content(raw_content)
        )
        if raw_bytes:
            content_hash = calculate_content_hash_bytes(raw_bytes)
            stored_text = inline_binary_preview(raw_bytes, spilled=spill)
            if raw_content and not spill:
                stored_text = raw_content
            elif raw_content and spill:
                stored_text = inline_evidence_content(raw_content, spilled=True)
        else:
            hash_source = raw_content if raw_content else None
            content_hash = calculate_content_hash(hash_source)
            stored_text = inline_evidence_content(raw_content or "", spilled=spill) if raw_content else None
        now = captured_at or datetime.now(timezone.utc).isoformat()
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO evidence_items (
                case_id, entity_id, observation_id, finding_id, module_id,
                evidence_type, source_name, source_url, collection_method,
                title, summary, content_type, content_text, content_hash,
                storage_path, reliability, confidence, captured_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                entity_id,
                observation_id,
                finding_id,
                module_id,
                normalise_evidence_type(evidence_type),
                source_name,
                source_url,
                collection_method,
                title,
                summary,
                content_type,
                stored_text,
                content_hash,
                storage_path,
                normalise_reliability(reliability),
                confidence,
                now,
            ),
        )
        evidence_id = cursor.lastrowid
        if spill and evidence_id is not None:
            if raw_bytes:
                spilled_path = spill_binary_content(
                    case_id,
                    int(evidence_id),
                    raw_bytes,
                    content_type=content_type,
                )
            elif raw_content:
                spilled_path = spill_evidence_content(
                    case_id,
                    int(evidence_id),
                    raw_content,
                    content_type=content_type,
                )
            else:
                spilled_path = None
            if spilled_path:
                conn.execute(
                    "UPDATE evidence_items SET storage_path = ? WHERE id = ?",
                    (spilled_path, evidence_id),
                )
        if finding_id is not None and evidence_id is not None:
            conn.execute(
                """
                INSERT OR IGNORE INTO evidence_finding_links (evidence_id, finding_id)
                VALUES (?, ?)
                """,
                (evidence_id, finding_id),
            )
        conn.commit()
        item = _row_to_dict(
            conn.execute("SELECT * FROM evidence_items WHERE id = ?", (evidence_id,)).fetchone()
        )
        if item is None:
            raise RuntimeError("Failed to create evidence item.")
        return item
    finally:
        if own_conn:
            conn.close()


def get_evidence_item(evidence_id: int, conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        row = conn.execute("SELECT * FROM evidence_items WHERE id = ?", (evidence_id,)).fetchone()
        return _row_to_dict(row)
    finally:
        if own_conn:
            conn.close()


def list_evidence_items(
    case_id: int | None = None,
    entity_id: int | None = None,
    observation_id: int | None = None,
    finding_id: int | None = None,
    conn: sqlite3.Connection | None = None,
) -> list[dict[str, Any]]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        query = "SELECT * FROM evidence_items"
        params: list[Any] = []
        filters: list[str] = []
        if case_id is not None:
            filters.append("case_id = ?")
            params.append(case_id)
        if entity_id is not None:
            filters.append("entity_id = ?")
            params.append(entity_id)
        if observation_id is not None:
            filters.append("observation_id = ?")
            params.append(observation_id)
        if finding_id is not None:
            filters.append("finding_id = ?")
            params.append(finding_id)
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY captured_at DESC, id DESC"
        rows = conn.execute(query, params).fetchall()
        return _rows_to_dicts(rows)
    finally:
        if own_conn:
            conn.close()


def count_evidence_items(case_id: int, conn: sqlite3.Connection | None = None) -> int:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM evidence_items WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        return int(row[0]) if row else 0
    finally:
        if own_conn:
            conn.close()


def link_evidence_to_observation(
    evidence_id: int,
    observation_id: int,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any] | None:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        conn.execute(
            "UPDATE evidence_items SET observation_id = ? WHERE id = ?",
            (observation_id, evidence_id),
        )
        conn.commit()
        return get_evidence_item(evidence_id, conn=conn)
    finally:
        if own_conn:
            conn.close()


def link_evidence_to_finding(
    evidence_id: int,
    finding_id: int,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any] | None:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        conn.execute(
            """
            INSERT OR IGNORE INTO evidence_finding_links (evidence_id, finding_id)
            VALUES (?, ?)
            """,
            (evidence_id, finding_id),
        )
        conn.execute(
            """
            UPDATE evidence_items
            SET finding_id = COALESCE(finding_id, ?)
            WHERE id = ?
            """,
            (finding_id, evidence_id),
        )
        conn.commit()
        return get_evidence_item(evidence_id, conn=conn)
    finally:
        if own_conn:
            conn.close()


def list_evidence_finding_links(
    *,
    case_id: int | None = None,
    evidence_id: int | None = None,
    finding_id: int | None = None,
    conn: sqlite3.Connection | None = None,
) -> list[dict[str, Any]]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        query = """
            SELECT l.*, e.case_id AS evidence_case_id
            FROM evidence_finding_links l
            INNER JOIN evidence_items e ON e.id = l.evidence_id
        """
        params: list[Any] = []
        filters: list[str] = []
        if case_id is not None:
            filters.append("e.case_id = ?")
            params.append(case_id)
        if evidence_id is not None:
            filters.append("l.evidence_id = ?")
            params.append(evidence_id)
        if finding_id is not None:
            filters.append("l.finding_id = ?")
            params.append(finding_id)
        if filters:
            query += " WHERE " + " AND ".join(filters)
        query += " ORDER BY l.created_at DESC, l.id DESC"
        rows = conn.execute(query, params).fetchall()
        return _rows_to_dicts(rows)
    finally:
        if own_conn:
            conn.close()


def list_evidence_for_finding(
    finding: dict[str, Any],
    conn: sqlite3.Connection | None = None,
) -> list[dict[str, Any]]:
    """Return evidence items linked to a finding via junction table or observation."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        finding_id = finding.get("id")
        if finding_id is None:
            return []
        rows = conn.execute(
            """
            SELECT e.* FROM evidence_items e
            INNER JOIN evidence_finding_links l ON l.evidence_id = e.id
            WHERE l.finding_id = ?
            ORDER BY e.captured_at DESC, e.id DESC
            """,
            (finding_id,),
        ).fetchall()
        linked = _rows_to_dicts(rows)
        seen = {item["id"] for item in linked}
        observation_id = finding.get("observation_id")
        if observation_id is not None:
            for item in list_evidence_items(observation_id=observation_id, conn=conn):
                if item["id"] not in seen:
                    linked.append(item)
                    seen.add(item["id"])
        legacy_id = finding_id
        legacy_rows = conn.execute(
            """
            SELECT * FROM evidence_items
            WHERE finding_id = ? AND id NOT IN (
                SELECT evidence_id FROM evidence_finding_links WHERE finding_id = ?
            )
            ORDER BY captured_at DESC, id DESC
            """,
            (legacy_id, legacy_id),
        ).fetchall()
        for item in _rows_to_dicts(legacy_rows):
            if item["id"] not in seen:
                linked.append(item)
        return linked
    finally:
        if own_conn:
            conn.close()


def entity_ids_with_evidence(
    case_id: int,
    *,
    evidence_types: tuple[str, ...] | None = None,
    conn: sqlite3.Connection | None = None,
) -> set[int]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        query = """
            SELECT DISTINCT entity_id FROM evidence_items
            WHERE case_id = ? AND entity_id IS NOT NULL
        """
        params: list[Any] = [case_id]
        if evidence_types:
            placeholders = ", ".join("?" for _ in evidence_types)
            query += f" AND evidence_type IN ({placeholders})"
            params.extend(evidence_types)
        rows = conn.execute(query, params).fetchall()
        return {int(row["entity_id"]) for row in rows if row["entity_id"] is not None}
    finally:
        if own_conn:
            conn.close()

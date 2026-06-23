"""Personal Lab scope and confirmation logging (not client engagements)."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any

from utils.target_detection import get_target_type

PERSONAL_LAB_SCOPE_SCHEMA = """
CREATE TABLE IF NOT EXISTS personal_lab_scope (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER NOT NULL,
    asset_type TEXT NOT NULL,
    asset_value TEXT NOT NULL,
    scope_status TEXT DEFAULT 'in_scope',
    permitted_testing_level TEXT DEFAULT 'safe_active',
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(case_id) REFERENCES cases(id)
)
"""

LAB_TESTING_LOG_SCHEMA = """
CREATE TABLE IF NOT EXISTS lab_testing_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    case_id INTEGER,
    target TEXT NOT NULL,
    module_id TEXT,
    operating_context TEXT NOT NULL,
    confirmation_text TEXT,
    confirmation_version TEXT,
    logged_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(case_id) REFERENCES cases(id)
)
"""

DEFAULT_LAB_SCOPE_NOTES = "Added from Personal Lab quick authorisation"


def ensure_personal_lab_tables(conn: sqlite3.Connection) -> None:
    conn.executescript(PERSONAL_LAB_SCOPE_SCHEMA + ";\n" + LAB_TESTING_LOG_SCHEMA)
    _migrate_lab_testing_log(conn)
    conn.commit()


def _migrate_lab_testing_log(conn: sqlite3.Connection) -> None:
    columns = {row[1] for row in conn.execute("PRAGMA table_info(lab_testing_log)").fetchall()}
    if "auto_scope_created" not in columns:
        conn.execute(
            "ALTER TABLE lab_testing_log ADD COLUMN auto_scope_created INTEGER NOT NULL DEFAULT 0"
        )


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return dict(row)


def _scope_asset_type_for_target(target: str) -> str:
    target_type = get_target_type(target)
    if target_type == "url":
        return "url"
    if target_type == "ipv4":
        return "ipv4"
    if target_type == "domain":
        return "domain"
    return "other"


def list_personal_lab_scope(case_id: int, *, conn: sqlite3.Connection) -> list[dict[str, Any]]:
    ensure_personal_lab_tables(conn)
    rows = conn.execute(
        """
        SELECT id, case_id, asset_type, asset_value, scope_status, permitted_testing_level, notes, created_at
        FROM personal_lab_scope
        WHERE case_id = ?
        ORDER BY created_at DESC, id DESC
        """,
        (case_id,),
    ).fetchall()
    return [_row_to_dict(row) for row in rows if row is not None]


def add_personal_lab_scope_item(
    case_id: int,
    target: str,
    *,
    notes: str | None = None,
    conn: sqlite3.Connection,
) -> dict[str, Any]:
    ensure_personal_lab_tables(conn)
    asset_type = _scope_asset_type_for_target(target)
    cleaned = target.strip()
    cursor = conn.execute(
        """
        INSERT INTO personal_lab_scope (
            case_id, asset_type, asset_value, scope_status, permitted_testing_level, notes
        ) VALUES (?, ?, ?, 'in_scope', 'safe_active', ?)
        """,
        (case_id, asset_type, cleaned, notes or DEFAULT_LAB_SCOPE_NOTES),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM personal_lab_scope WHERE id = ?", (cursor.lastrowid,)).fetchone()
    item = _row_to_dict(row)
    if item is None:
        raise RuntimeError("Failed to create personal lab scope item")
    return item


def log_lab_testing_confirmation(
    *,
    case_id: int | None,
    target: str,
    module_id: str | None,
    operating_context: str,
    confirmation_text: str,
    confirmation_version: str,
    conn: sqlite3.Connection,
    auto_scope_created: bool = False,
) -> dict[str, Any]:
    ensure_personal_lab_tables(conn)
    cursor = conn.execute(
        """
        INSERT INTO lab_testing_log (
            case_id, target, module_id, operating_context, confirmation_text,
            confirmation_version, logged_at, auto_scope_created
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            case_id,
            target,
            module_id,
            operating_context,
            confirmation_text,
            confirmation_version,
            datetime.now(timezone.utc).isoformat(),
            1 if auto_scope_created else 0,
        ),
    )
    conn.commit()
    row = conn.execute("SELECT * FROM lab_testing_log WHERE id = ?", (cursor.lastrowid,)).fetchone()
    item = _row_to_dict(row)
    if item is None:
        raise RuntimeError("Failed to log lab testing confirmation")
    return item

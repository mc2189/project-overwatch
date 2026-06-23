"""Client engagement, scope, and rules-of-engagement persistence."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from typing import Any

ENGAGEMENT_STATUSES: tuple[str, ...] = (
    "draft",
    "active",
    "paused",
    "completed",
    "archived",
)

ENGAGEMENT_TYPES: tuple[str, ...] = (
    "OSINT / External Exposure Review",
    "External Attack Surface Review",
    "Web Application Assessment",
    "Infrastructure Vulnerability Review",
    "Email / Domain Security Review",
    "Operational Resilience Review",
    "Incident Readiness / Tabletop Support",
    "Custom Assessment",
)

SCOPE_ASSET_TYPES: tuple[str, ...] = (
    "domain",
    "url",
    "ipv4",
    "cidr",
    "hostname",
    "email-domain",
    "organisation",
    "other",
)

SCOPE_STATUSES: tuple[str, ...] = (
    "in_scope",
    "out_of_scope",
    "restricted",
    "pending_approval",
)

PERMITTED_TESTING_LEVELS: tuple[str, ...] = (
    "passive_only",
    "safe_active",
    "intrusive_active",
    "manual_only",
)

ENGAGEMENTS_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagements (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    client_name TEXT,
    engagement_type TEXT,
    start_date TEXT,
    end_date TEXT,
    status TEXT DEFAULT 'draft',
    primary_contact TEXT,
    emergency_contact TEXT,
    authorisation_reference TEXT,
    statement_of_work_reference TEXT,
    notes TEXT,
    emergency_stop_active INTEGER DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
"""

ENGAGEMENT_SCOPE_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagement_scope (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    engagement_id INTEGER NOT NULL,
    asset_value TEXT NOT NULL,
    asset_type TEXT NOT NULL,
    scope_status TEXT DEFAULT 'pending_approval',
    permitted_testing_level TEXT DEFAULT 'passive_only',
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(engagement_id) REFERENCES engagements(id)
)
"""

ENGAGEMENT_ROE_SCHEMA = """
CREATE TABLE IF NOT EXISTS engagement_roe (
    engagement_id INTEGER PRIMARY KEY,
    permitted_test_windows TEXT,
    prohibited_actions TEXT,
    rate_limits TEXT,
    maximum_request_rate INTEGER,
    active_scanning_allowed INTEGER DEFAULT 0,
    intrusive_testing_allowed INTEGER DEFAULT 0,
    denial_of_service_allowed INTEGER DEFAULT 0,
    credential_testing_allowed INTEGER DEFAULT 0,
    social_engineering_allowed INTEGER DEFAULT 0,
    malware_handling_allowed INTEGER DEFAULT 0,
    client_notification_requirements TEXT,
    emergency_stop_procedure TEXT,
    evidence_handling_notes TEXT,
    data_retention_notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY(engagement_id) REFERENCES engagements(id)
)
"""

ENGAGEMENT_SCHEMAS: tuple[str, ...] = (
    ENGAGEMENTS_SCHEMA,
    ENGAGEMENT_SCOPE_SCHEMA,
    ENGAGEMENT_ROE_SCHEMA,
)

CASE_ENGAGEMENT_COLUMN = ("engagement_id", "INTEGER")


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    return dict(row)


def _rows_to_dicts(rows: list[sqlite3.Row]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows]


def ensure_engagement_tables(conn: sqlite3.Connection) -> None:
    for schema in ENGAGEMENT_SCHEMAS:
        conn.execute(schema)
    columns = {row[1] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
    column_name, column_type = CASE_ENGAGEMENT_COLUMN
    if column_name not in columns:
        conn.execute(f"ALTER TABLE cases ADD COLUMN {column_name} {column_type}")
    conn.commit()


def default_roe_payload() -> dict[str, Any]:
    return {
        "permitted_test_windows": "",
        "prohibited_actions": "No denial-of-service, credential attacks, social engineering, malware handling, or destructive testing.",
        "rate_limits": "Respect provider rate limits and client-agreed courtesy delays.",
        "maximum_request_rate": None,
        "active_scanning_allowed": False,
        "intrusive_testing_allowed": False,
        "denial_of_service_allowed": False,
        "credential_testing_allowed": False,
        "social_engineering_allowed": False,
        "malware_handling_allowed": False,
        "client_notification_requirements": "",
        "emergency_stop_procedure": "Contact emergency contact and pause active testing immediately.",
        "evidence_handling_notes": "Store evidence locally; redact secrets before sharing.",
        "data_retention_notes": "",
    }


def _normalise_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, int):
        return value != 0
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _engagement_from_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    data = _row_to_dict(row)
    if data is None:
        return None
    data["emergency_stop_active"] = bool(data.get("emergency_stop_active"))
    return data


def _roe_from_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    data = _row_to_dict(row)
    if data is None:
        return None
    for key in (
        "active_scanning_allowed",
        "intrusive_testing_allowed",
        "denial_of_service_allowed",
        "credential_testing_allowed",
        "social_engineering_allowed",
        "malware_handling_allowed",
    ):
        data[key] = bool(data.get(key))
    return data


def create_engagement(
    *,
    name: str,
    client_name: str = "",
    engagement_type: str = ENGAGEMENT_TYPES[0],
    start_date: str = "",
    end_date: str = "",
    status: str = "draft",
    primary_contact: str = "",
    emergency_contact: str = "",
    authorisation_reference: str = "",
    statement_of_work_reference: str = "",
    notes: str = "",
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    own_conn = conn is None
    if own_conn:
        from database.db_setup import get_db_conn

        conn = get_db_conn()
    ensure_engagement_tables(conn)
    now = _now_iso()
    cursor = conn.execute(
        """
        INSERT INTO engagements (
            name, client_name, engagement_type, start_date, end_date, status,
            primary_contact, emergency_contact, authorisation_reference,
            statement_of_work_reference, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            name.strip(),
            client_name.strip(),
            engagement_type,
            start_date.strip() or None,
            end_date.strip() or None,
            status if status in ENGAGEMENT_STATUSES else "draft",
            primary_contact.strip(),
            emergency_contact.strip(),
            authorisation_reference.strip(),
            statement_of_work_reference.strip(),
            notes.strip(),
            now,
            now,
        ),
    )
    engagement_id = int(cursor.lastrowid)
    conn.execute(
        """
        INSERT INTO engagement_roe (
            engagement_id, permitted_test_windows, prohibited_actions, rate_limits,
            maximum_request_rate, active_scanning_allowed, intrusive_testing_allowed,
            denial_of_service_allowed, credential_testing_allowed, social_engineering_allowed,
            malware_handling_allowed, client_notification_requirements,
            emergency_stop_procedure, evidence_handling_notes, data_retention_notes,
            created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            default_roe_payload()["permitted_test_windows"],
            default_roe_payload()["prohibited_actions"],
            default_roe_payload()["rate_limits"],
            None,
            0,
            0,
            0,
            0,
            0,
            0,
            "",
            default_roe_payload()["emergency_stop_procedure"],
            default_roe_payload()["evidence_handling_notes"],
            "",
            now,
            now,
        ),
    )
    conn.commit()
    if own_conn:
        conn.close()
    return get_engagement(engagement_id, conn=conn if not own_conn else None) or {}


def list_engagements(conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    own_conn = conn is None
    if own_conn:
        from database.db_setup import get_db_conn

        conn = get_db_conn()
    ensure_engagement_tables(conn)
    rows = conn.execute("SELECT * FROM engagements ORDER BY updated_at DESC, id DESC").fetchall()
    if own_conn:
        conn.close()
    return [_engagement_from_row(row) for row in rows if row is not None]


def get_engagement(engagement_id: int, conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    own_conn = conn is None
    if own_conn:
        from database.db_setup import get_db_conn

        conn = get_db_conn()
    ensure_engagement_tables(conn)
    row = conn.execute("SELECT * FROM engagements WHERE id = ?", (engagement_id,)).fetchone()
    if own_conn:
        conn.close()
    return _engagement_from_row(row)


def update_engagement(engagement_id: int, fields: dict[str, Any], conn: sqlite3.Connection | None = None) -> None:
    own_conn = conn is None
    if own_conn:
        from database.db_setup import get_db_conn

        conn = get_db_conn()
    ensure_engagement_tables(conn)
    allowed = {
        "name",
        "client_name",
        "engagement_type",
        "start_date",
        "end_date",
        "status",
        "primary_contact",
        "emergency_contact",
        "authorisation_reference",
        "statement_of_work_reference",
        "notes",
        "emergency_stop_active",
    }
    updates: list[str] = []
    values: list[Any] = []
    for key, value in fields.items():
        if key not in allowed:
            continue
        if key == "emergency_stop_active":
            value = 1 if _normalise_bool(value) else 0
        if key == "status" and value not in ENGAGEMENT_STATUSES:
            continue
        updates.append(f"{key} = ?")
        values.append(value)
    if not updates:
        if own_conn:
            conn.close()
        return
    updates.append("updated_at = ?")
    values.append(_now_iso())
    values.append(engagement_id)
    conn.execute(f"UPDATE engagements SET {', '.join(updates)} WHERE id = ?", values)
    conn.commit()
    if own_conn:
        conn.close()


def get_engagement_for_case(case_id: int, conn: sqlite3.Connection | None = None) -> dict[str, Any] | None:
    own_conn = conn is None
    if own_conn:
        from database.db_setup import get_db_conn

        conn = get_db_conn()
    ensure_engagement_tables(conn)
    row = conn.execute("SELECT engagement_id FROM cases WHERE id = ?", (case_id,)).fetchone()
    engagement_id = row["engagement_id"] if row and row["engagement_id"] else None
    if own_conn:
        conn.close()
    if not engagement_id:
        return None
    return get_engagement(int(engagement_id), conn=conn if not own_conn else None)


def link_case_to_engagement(
    case_id: int,
    engagement_id: int | None,
    conn: sqlite3.Connection | None = None,
) -> None:
    own_conn = conn is None
    if own_conn:
        from database.db_setup import get_db_conn

        conn = get_db_conn()
    ensure_engagement_tables(conn)
    conn.execute(
        "UPDATE cases SET engagement_id = ?, updated_at = ? WHERE id = ?",
        (engagement_id, _now_iso(), case_id),
    )
    conn.commit()
    if own_conn:
        conn.close()


def get_roe(engagement_id: int, conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    own_conn = conn is None
    if own_conn:
        from database.db_setup import get_db_conn

        conn = get_db_conn()
    ensure_engagement_tables(conn)
    row = conn.execute("SELECT * FROM engagement_roe WHERE engagement_id = ?", (engagement_id,)).fetchone()
    if row is None:
        payload = default_roe_payload()
        payload["engagement_id"] = engagement_id
        if own_conn:
            conn.close()
        return payload
    if own_conn:
        conn.close()
    return _roe_from_row(row) or default_roe_payload()


def upsert_roe(engagement_id: int, fields: dict[str, Any], conn: sqlite3.Connection | None = None) -> None:
    own_conn = conn is None
    if own_conn:
        from database.db_setup import get_db_conn

        conn = get_db_conn()
    ensure_engagement_tables(conn)
    existing = conn.execute(
        "SELECT engagement_id FROM engagement_roe WHERE engagement_id = ?",
        (engagement_id,),
    ).fetchone()
    allowed = {
        "permitted_test_windows",
        "prohibited_actions",
        "rate_limits",
        "maximum_request_rate",
        "active_scanning_allowed",
        "intrusive_testing_allowed",
        "denial_of_service_allowed",
        "credential_testing_allowed",
        "social_engineering_allowed",
        "malware_handling_allowed",
        "client_notification_requirements",
        "emergency_stop_procedure",
        "evidence_handling_notes",
        "data_retention_notes",
    }
    payload = {key: fields[key] for key in allowed if key in fields}
    for key in (
        "active_scanning_allowed",
        "intrusive_testing_allowed",
        "denial_of_service_allowed",
        "credential_testing_allowed",
        "social_engineering_allowed",
        "malware_handling_allowed",
    ):
        if key in payload:
            payload[key] = 1 if _normalise_bool(payload[key]) else 0
    now = _now_iso()
    if existing is None:
        defaults = default_roe_payload()
        defaults.update(payload)
        conn.execute(
            """
            INSERT INTO engagement_roe (
                engagement_id, permitted_test_windows, prohibited_actions, rate_limits,
                maximum_request_rate, active_scanning_allowed, intrusive_testing_allowed,
                denial_of_service_allowed, credential_testing_allowed, social_engineering_allowed,
                malware_handling_allowed, client_notification_requirements,
                emergency_stop_procedure, evidence_handling_notes, data_retention_notes,
                created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                engagement_id,
                defaults.get("permitted_test_windows", ""),
                defaults.get("prohibited_actions", ""),
                defaults.get("rate_limits", ""),
                defaults.get("maximum_request_rate"),
                int(defaults.get("active_scanning_allowed", False)),
                int(defaults.get("intrusive_testing_allowed", False)),
                int(defaults.get("denial_of_service_allowed", False)),
                int(defaults.get("credential_testing_allowed", False)),
                int(defaults.get("social_engineering_allowed", False)),
                int(defaults.get("malware_handling_allowed", False)),
                defaults.get("client_notification_requirements", ""),
                defaults.get("emergency_stop_procedure", ""),
                defaults.get("evidence_handling_notes", ""),
                defaults.get("data_retention_notes", ""),
                now,
                now,
            ),
        )
    else:
        if not payload:
            if own_conn:
                conn.close()
            return
        updates = [f"{key} = ?" for key in payload]
        values = list(payload.values())
        updates.append("updated_at = ?")
        values.append(now)
        values.append(engagement_id)
        conn.execute(
            f"UPDATE engagement_roe SET {', '.join(updates)} WHERE engagement_id = ?",
            values,
        )
    conn.execute("UPDATE engagements SET updated_at = ? WHERE id = ?", (now, engagement_id))
    conn.commit()
    if own_conn:
        conn.close()


def list_scope_items(engagement_id: int, conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    own_conn = conn is None
    if own_conn:
        from database.db_setup import get_db_conn

        conn = get_db_conn()
    ensure_engagement_tables(conn)
    rows = conn.execute(
        "SELECT * FROM engagement_scope WHERE engagement_id = ? ORDER BY asset_type, asset_value",
        (engagement_id,),
    ).fetchall()
    if own_conn:
        conn.close()
    return _rows_to_dicts(rows)


def add_scope_item(
    engagement_id: int,
    *,
    asset_value: str,
    asset_type: str,
    scope_status: str = "pending_approval",
    permitted_testing_level: str = "passive_only",
    notes: str = "",
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any]:
    own_conn = conn is None
    if own_conn:
        from database.db_setup import get_db_conn

        conn = get_db_conn()
    ensure_engagement_tables(conn)
    now = _now_iso()
    cursor = conn.execute(
        """
        INSERT INTO engagement_scope (
            engagement_id, asset_value, asset_type, scope_status,
            permitted_testing_level, notes, created_at, updated_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            engagement_id,
            asset_value.strip().lower(),
            asset_type if asset_type in SCOPE_ASSET_TYPES else "other",
            scope_status if scope_status in SCOPE_STATUSES else "pending_approval",
            permitted_testing_level
            if permitted_testing_level in PERMITTED_TESTING_LEVELS
            else "passive_only",
            notes.strip(),
            now,
            now,
        ),
    )
    conn.commit()
    item_id = int(cursor.lastrowid)
    row = conn.execute("SELECT * FROM engagement_scope WHERE id = ?", (item_id,)).fetchone()
    if own_conn:
        conn.close()
    return _row_to_dict(row) or {}


def update_scope_item(scope_id: int, fields: dict[str, Any], conn: sqlite3.Connection | None = None) -> None:
    own_conn = conn is None
    if own_conn:
        from database.db_setup import get_db_conn

        conn = get_db_conn()
    ensure_engagement_tables(conn)
    allowed = {"asset_value", "asset_type", "scope_status", "permitted_testing_level", "notes"}
    updates: list[str] = []
    values: list[Any] = []
    for key, value in fields.items():
        if key not in allowed:
            continue
        if key == "asset_value":
            value = str(value).strip().lower()
        updates.append(f"{key} = ?")
        values.append(value)
    if not updates:
        if own_conn:
            conn.close()
        return
    updates.append("updated_at = ?")
    values.append(_now_iso())
    values.append(scope_id)
    conn.execute(f"UPDATE engagement_scope SET {', '.join(updates)} WHERE id = ?", values)
    conn.commit()
    if own_conn:
        conn.close()


def delete_scope_item(scope_id: int, conn: sqlite3.Connection | None = None) -> None:
    own_conn = conn is None
    if own_conn:
        from database.db_setup import get_db_conn

        conn = get_db_conn()
    ensure_engagement_tables(conn)
    conn.execute("DELETE FROM engagement_scope WHERE id = ?", (scope_id,))
    conn.commit()
    if own_conn:
        conn.close()


def engagement_summary_for_report(engagement_id: int, conn: sqlite3.Connection | None = None) -> dict[str, Any]:
    engagement = get_engagement(engagement_id, conn=conn)
    if engagement is None:
        return {}
    roe = get_roe(engagement_id, conn=conn)
    scope_items = list_scope_items(engagement_id, conn=conn)
    in_scope = [item for item in scope_items if item.get("scope_status") == "in_scope"]
    return {
        "engagement": engagement,
        "roe": roe,
        "scope_items": scope_items,
        "in_scope_count": len(in_scope),
        "scope_summary": ", ".join(
            f"{item['asset_value']} ({item['asset_type']})" for item in in_scope[:20]
        )
        + ("..." if len(in_scope) > 20 else ""),
    }

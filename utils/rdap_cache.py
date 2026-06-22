"""Per-case RDAP/WHOIS response cache."""

from __future__ import annotations

import sqlite3
from typing import Any

from database.db_setup import get_db_conn


def get_rdap_cache_entry(
    case_id: int,
    query_key: str,
    *,
    conn: sqlite3.Connection | None = None,
) -> dict[str, Any] | None:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        row = conn.execute(
            """
            SELECT case_id, query_key, target_type, source, response_json, rdap_url, whois_server, fetched_at
            FROM rdap_lookup_cache
            WHERE case_id = ? AND query_key = ?
            """,
            (case_id, query_key),
        ).fetchone()
        return dict(row) if row else None
    finally:
        if own_conn:
            conn.close()


def set_rdap_cache_entry(
    case_id: int,
    query_key: str,
    target_type: str,
    source: str,
    response_json: str,
    *,
    rdap_url: str | None = None,
    whois_server: str | None = None,
    conn: sqlite3.Connection | None = None,
) -> None:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        conn.execute(
            """
            INSERT INTO rdap_lookup_cache (
                case_id, query_key, target_type, source, response_json, rdap_url, whois_server
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(case_id, query_key) DO UPDATE SET
                target_type = excluded.target_type,
                source = excluded.source,
                response_json = excluded.response_json,
                rdap_url = excluded.rdap_url,
                whois_server = excluded.whois_server,
                fetched_at = CURRENT_TIMESTAMP
            """,
            (case_id, query_key, target_type, source, response_json, rdap_url, whois_server),
        )
        conn.commit()
    finally:
        if own_conn:
            conn.close()


def clear_rdap_cache_for_case(case_id: int, *, conn: sqlite3.Connection | None = None) -> int:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        cursor = conn.execute("DELETE FROM rdap_lookup_cache WHERE case_id = ?", (case_id,))
        conn.commit()
        return cursor.rowcount
    finally:
        if own_conn:
            conn.close()

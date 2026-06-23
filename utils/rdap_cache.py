"""Per-case RDAP/WHOIS response cache."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from typing import Any

from database.db_setup import get_db_conn


def rdap_cache_ttl_hours() -> int:
    """Return cache TTL in hours; 0 disables expiry."""
    try:
        from utils.settings_manager import get_int_env

        return max(0, get_int_env("PROJECT_OVERWATCH_RDAP_CACHE_TTL_HOURS", 0))
    except Exception:
        return 0


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def _is_expired(fetched_at: str | None) -> bool:
    ttl_hours = rdap_cache_ttl_hours()
    if ttl_hours <= 0:
        return False
    parsed = _parse_timestamp(fetched_at)
    if parsed is None:
        return False
    return datetime.now(timezone.utc) - parsed > timedelta(hours=ttl_hours)


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
        if row is None:
            return None
        entry = dict(row)
        if _is_expired(entry.get("fetched_at")):
            return None
        return entry
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


def count_rdap_cache_for_case(case_id: int, *, conn: sqlite3.Connection | None = None) -> int:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        row = conn.execute(
            "SELECT COUNT(*) AS count FROM rdap_lookup_cache WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        return int(row["count"]) if row else 0
    finally:
        if own_conn:
            conn.close()


def list_rdap_cache_for_case(
    case_id: int,
    *,
    conn: sqlite3.Connection | None = None,
) -> list[dict[str, Any]]:
    """Return cache row summaries without full response bodies."""
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        rows = conn.execute(
            """
            SELECT query_key, target_type, source, rdap_url, whois_server, fetched_at,
                   LENGTH(response_json) AS response_bytes
            FROM rdap_lookup_cache
            WHERE case_id = ?
            ORDER BY fetched_at DESC, query_key ASC
            """,
            (case_id,),
        ).fetchall()
        results: list[dict[str, Any]] = []
        for row in rows:
            item = dict(row)
            item["expired"] = _is_expired(item.get("fetched_at"))
            results.append(item)
        return results
    finally:
        if own_conn:
            conn.close()


def export_rdap_cache_for_case(case_id: int, *, conn: sqlite3.Connection | None = None) -> list[dict[str, Any]]:
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        rows = conn.execute(
            """
            SELECT query_key, target_type, source, response_json, rdap_url, whois_server, fetched_at
            FROM rdap_lookup_cache
            WHERE case_id = ?
            ORDER BY query_key ASC
            """,
            (case_id,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        if own_conn:
            conn.close()


def import_rdap_cache_entries(
    case_id: int,
    entries: list[dict[str, Any]],
    *,
    conn: sqlite3.Connection | None = None,
) -> int:
    imported = 0
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        for entry in entries:
            query_key = entry.get("query_key")
            response_json = entry.get("response_json")
            if not query_key or response_json is None:
                continue
            set_rdap_cache_entry(
                case_id,
                str(query_key),
                str(entry.get("target_type") or "unknown"),
                str(entry.get("source") or "rdap"),
                str(response_json),
                rdap_url=entry.get("rdap_url"),
                whois_server=entry.get("whois_server"),
                conn=conn,
            )
            imported += 1
        return imported
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

#!/usr/bin/env python3
"""Unit tests for batch queue summaries and case memory refresh."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db_setup import create_case, get_db_conn  # noqa: E402
from utils.batch_queue_runner import select_queue_ids  # noqa: E402
from utils.batch_queue_summary import summarize_batch_queue  # noqa: E402
from utils.case_memory_refresh import (
    CASE_MEMORY_REFRESH_SESSION_KEY,
    WORKSPACE_SCROLL_TO_CASE_MEMORY_KEY,
    build_case_memory_refresh,
    store_case_memory_refresh,
)  # noqa: E402


class BatchQueueSummaryTests(unittest.TestCase):
    def test_summarize_batch_queue_counts(self) -> None:
        items = [
            {"queue_id": "a", "status": "queued", "mode": "passive"},
            {"queue_id": "b", "status": "queued", "mode": "active"},
            {"queue_id": "c", "status": "completed", "mode": "passive"},
            {"queue_id": "d", "status": "error", "mode": "active"},
        ]
        summary = summarize_batch_queue(items)
        self.assertEqual(summary["total"], 4)
        self.assertEqual(summary["queued"], 2)
        self.assertEqual(summary["passive_queued"], 1)
        self.assertEqual(summary["active_queued"], 1)
        self.assertEqual(summary["completed"], 1)
        self.assertEqual(summary["failed"], 1)
        self.assertEqual(select_queue_ids(items, "passive"), ["a"])
        self.assertEqual(select_queue_ids(items, "active"), ["b"])

    def test_build_case_memory_refresh_empty_case(self) -> None:
        conn = get_db_conn()
        try:
            case = create_case("Memory refresh test", conn=conn)
            payload = build_case_memory_refresh(int(case["id"]), conn=conn)
            self.assertEqual(payload["device_count"], 0)
            self.assertFalse(payload["has_baseline"])
            self.assertEqual(payload["unexpected_count"], 0)
        finally:
            conn.close()

    def test_store_case_memory_refresh_session(self) -> None:
        conn = get_db_conn()
        try:
            case = create_case("Memory refresh session", conn=conn)
            session: dict = {}
            payload = store_case_memory_refresh(session, int(case["id"]), conn=conn, scroll_after=True)
            self.assertIn(str(case["id"]), session[CASE_MEMORY_REFRESH_SESSION_KEY])
            self.assertEqual(payload["case_id"], int(case["id"]))
            self.assertTrue(session.get(WORKSPACE_SCROLL_TO_CASE_MEMORY_KEY))
            self.assertTrue(session.get(f"case_memory_compare_{case['id']}"))
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()

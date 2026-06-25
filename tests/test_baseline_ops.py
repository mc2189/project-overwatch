#!/usr/bin/env python3
"""Unit tests for baseline snapshot operations."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db_setup import create_case, get_db_conn  # noqa: E402
from utils.baseline_compare import compare_case_to_latest_baseline  # noqa: E402
from utils.baseline_ops import (  # noqa: E402
    assess_baseline_snapshot,
    is_baseline_snapshot_ready,
    maybe_auto_snapshot_after_run,
    snapshot_and_replace_baseline,
)


class BaselineOpsTests(unittest.TestCase):
    def test_snapshot_create_then_update(self) -> None:
        conn = get_db_conn()
        try:
            case = create_case("Baseline ops test", conn=conn)
            case_id = int(case["id"])

            assessment = assess_baseline_snapshot(
                case_id,
                conn=conn,
                latest_results=[{"success": True, "module_id": "infra_nmap"}],
            )
            self.assertTrue(assessment["ready"])
            self.assertTrue(assessment["run_success"])

            created = snapshot_and_replace_baseline(case_id, name="Unit baseline", conn=conn)
            self.assertEqual(created["action"], "created")

            updated = snapshot_and_replace_baseline(case_id, name="Unit baseline", conn=conn)
            self.assertEqual(updated["action"], "updated")

            comparison = compare_case_to_latest_baseline(case_id, conn=conn)
            self.assertTrue(comparison.get("has_baseline"))
            self.assertTrue(is_baseline_snapshot_ready(comparison))
        finally:
            conn.close()

    @patch("utils.baseline_ops.auto_snapshot_after_clean_run", return_value=True)
    def test_maybe_auto_snapshot_after_clean_run(self, _mock_auto: MagicMock) -> None:
        conn = get_db_conn()
        try:
            case = create_case("Auto snapshot test", conn=conn)
            case_id = int(case["id"])
            latest = [{"success": True, "module_id": "infra_nmap"}]

            skipped = maybe_auto_snapshot_after_run(case_id, latest_results=latest, conn=conn)
            self.assertIsNotNone(skipped)
            self.assertIn(skipped["action"], {"created", "updated"})

            again = maybe_auto_snapshot_after_run(case_id, latest_results=latest, conn=conn)
            self.assertIsNotNone(again)
            self.assertEqual(again["action"], "updated")
        finally:
            conn.close()

    @patch("utils.baseline_ops.auto_snapshot_after_clean_run", return_value=False)
    def test_maybe_auto_snapshot_disabled(self, _mock_auto: MagicMock) -> None:
        conn = get_db_conn()
        try:
            case = create_case("Auto snapshot disabled", conn=conn)
            case_id = int(case["id"])
            result = maybe_auto_snapshot_after_run(
                case_id,
                latest_results=[{"success": True, "module_id": "infra_nmap"}],
                conn=conn,
            )
            self.assertIsNone(result)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()

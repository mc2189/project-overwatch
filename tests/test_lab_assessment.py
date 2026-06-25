#!/usr/bin/env python3
"""Unit tests for lab assessment orchestration."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db_setup import create_case, get_db_conn  # noqa: E402
from utils.autopilot_engine import (  # noqa: E402
    queue_autopilot_to_batch,
    set_case_autopilot_queue,
)
from utils.autopilot_queue import build_autopilot_item  # noqa: E402
from utils.autopilot_rules import make_autopilot_action  # noqa: E402
from utils.lab_assessment import apply_post_run_hooks, finalize_lab_assessment  # noqa: E402


class LabAssessmentTests(unittest.TestCase):
    @patch("utils.lab_assessment.maybe_auto_snapshot_after_run", return_value=None)
    @patch("utils.lab_assessment.update_autopilot_from_results")
    def test_finalize_lab_assessment_collects_autopilot_results(
        self,
        mock_update,
        _mock_snapshot,
    ) -> None:
        mock_update.return_value = {
            "auto_run_results": [
                {"result": {"module_id": "infra_tls_review", "success": True}},
            ],
        }
        conn = get_db_conn()
        try:
            case = create_case("Lab finalize test", conn=conn)
            outcome = finalize_lab_assessment(
                case_id=int(case["id"]),
                target="192.168.1.1",
                goal_id="quick_safety_check",
                primary_results=[{"module_id": "infra_nmap", "success": True}],
                session_state={},
                operating_context="personal_lab",
                personal_lab_confirmed=True,
                authorisation_confirmed=True,
                conn=conn,
            )
            self.assertEqual(len(outcome["results"]), 2)
            self.assertIn("Autopilot completed 1 follow-up", outcome["message"] or "")
        finally:
            conn.close()

    @patch("utils.lab_assessment.maybe_auto_snapshot_after_run")
    def test_apply_post_run_hooks_delegates_to_auto_snapshot(self, mock_snapshot) -> None:
        mock_snapshot.return_value = {"action": "created", "name": "Lab baseline"}
        conn = get_db_conn()
        try:
            case = create_case("Post run hooks", conn=conn)
            result = apply_post_run_hooks(
                case_id=int(case["id"]),
                latest_results=[{"module_id": "infra_nmap", "success": True}],
                conn=conn,
            )
            self.assertEqual(result["action"], "created")
            mock_snapshot.assert_called_once()
        finally:
            conn.close()

    def test_queue_autopilot_allows_confirmed_active(self) -> None:
        conn = get_db_conn()
        try:
            case = create_case("Lab queue test", conn=conn)
            case_id = int(case["id"])
            action = make_autopilot_action(
                title="SSH review",
                reason="SSH observed",
                action_type="run_module",
                target="192.168.1.10",
                module_id="infra_ssh_review",
            )
            item = build_autopilot_item(action, playbook_id="local_network_triage")
            item["status"] = "proposed"
            session: dict = {}
            set_case_autopilot_queue(session, case_id, [item])

            _, blocked_messages, _ = queue_autopilot_to_batch(
                case_id,
                session,
                operating_context="personal_lab",
                personal_lab_confirmed=True,
                authorisation_confirmed=True,
                allow_confirmed_active=False,
            )
            self.assertTrue(any("Skipped active" in message for message in blocked_messages))

            set_case_autopilot_queue(session, case_id, [{**item, "status": "proposed"}])
            _, allowed_messages, batch_items = queue_autopilot_to_batch(
                case_id,
                session,
                operating_context="personal_lab",
                personal_lab_confirmed=True,
                authorisation_confirmed=True,
                allow_confirmed_active=True,
            )
            self.assertFalse(any("Skipped active" in message for message in allowed_messages))
            self.assertTrue(
                any(row.get("module_id") == "infra_ssh_review" for row in batch_items),
            )
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()

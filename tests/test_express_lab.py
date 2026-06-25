#!/usr/bin/env python3
"""Unit tests for Express Lab auto-goal helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.assessment_goals import GOAL_LOCAL_NETWORK, GOAL_QUICK_SAFETY, GOAL_WEBSITE_POSTURE  # noqa: E402
from utils.express_lab import (  # noqa: E402
    EXPRESS_GOAL_LOCKED_KEY,
    EXPRESS_LAST_TARGET_KEY,
    default_goal_for_target,
    sync_express_goal,
)


class ExpressLabTests(unittest.TestCase):
    def test_default_goal_for_private_ip(self) -> None:
        goal = default_goal_for_target("ipv4", "192.168.1.10")
        self.assertEqual(goal, GOAL_LOCAL_NETWORK)

    def test_default_goal_for_domain(self) -> None:
        goal = default_goal_for_target("domain", "example.com")
        self.assertIn(goal, {GOAL_QUICK_SAFETY, GOAL_WEBSITE_POSTURE})

    def test_sync_express_goal_updates_on_target_change(self) -> None:
        session: dict = {}
        first = sync_express_goal(
            session,
            target="192.168.1.10",
            target_type="ipv4",
            goal_session_key="assessment_goal",
            prev_goal_key="workspace_prev_goal",
        )
        self.assertEqual(first, GOAL_LOCAL_NETWORK)
        second = sync_express_goal(
            session,
            target="example.com",
            target_type="domain",
            goal_session_key="assessment_goal",
            prev_goal_key="workspace_prev_goal",
        )
        self.assertNotEqual(second, GOAL_LOCAL_NETWORK)
        self.assertEqual(session.get(EXPRESS_LAST_TARGET_KEY), "example.com")

    def test_sync_express_goal_respects_manual_lock(self) -> None:
        session = {
            EXPRESS_GOAL_LOCKED_KEY: True,
            "assessment_goal": GOAL_QUICK_SAFETY,
            EXPRESS_LAST_TARGET_KEY: "old",
        }
        goal = sync_express_goal(
            session,
            target="192.168.1.20",
            target_type="ipv4",
            goal_session_key="assessment_goal",
            prev_goal_key="workspace_prev_goal",
        )
        self.assertEqual(goal, GOAL_QUICK_SAFETY)


if __name__ == "__main__":
    unittest.main()

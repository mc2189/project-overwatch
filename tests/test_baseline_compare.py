#!/usr/bin/env python3
"""Unit tests for baseline comparison helpers."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from database.db_setup import create_case, get_db_conn, mark_expected_item  # noqa: E402
from utils.baseline_compare import compare_baseline_to_current, compare_case_to_latest_baseline  # noqa: E402


class BaselineCompareTests(unittest.TestCase):
    def test_empty_case_has_no_baseline(self) -> None:
        conn = get_db_conn()
        try:
            case = create_case("Baseline compare empty", conn=conn)
            case_id = int(case["id"])
            comparison = compare_case_to_latest_baseline(case_id, conn=conn)
            self.assertFalse(comparison.get("has_baseline"))
            self.assertEqual(comparison.get("changes") or [], [])
        finally:
            conn.close()

    def test_detects_new_device_and_service(self) -> None:
        conn = get_db_conn()
        try:
            case = create_case("Baseline compare delta", conn=conn)
            case_id = int(case["id"])
            baseline_summary = {
                "name": "Unit baseline",
                "devices": [{"ip": "192.168.1.10"}],
                "services": [
                    {"host": "192.168.1.10", "port": 22, "protocol": "tcp", "service": "ssh"},
                ],
                "findings": [],
                "hostnames": [],
                "macs": [],
                "web_technologies": [],
                "web_paths": [],
                "remote_access_services": [],
                "public_contacts": [],
            }
            current_summary = {
                "devices": [
                    {"ip": "192.168.1.10"},
                    {"ip": "192.168.1.34", "hostname": "livingroom-tv.local"},
                ],
                "services": [
                    {"host": "192.168.1.10", "port": 22, "protocol": "tcp", "service": "ssh"},
                    {"host": "192.168.1.10", "port": 5900, "protocol": "tcp", "service": "vnc"},
                ],
                "findings": [],
                "hostnames": [],
                "macs": [],
                "web_technologies": [],
                "web_paths": [],
                "remote_access_services": [],
                "public_contacts": [],
            }
            comparison = compare_baseline_to_current(
                case_id,
                baseline_summary=baseline_summary,
                current_summary=current_summary,
                conn=conn,
            )
            new_devices = [
                row for row in comparison.get("changes") or [] if row.get("change_type") == "new_device"
            ]
            self.assertEqual(len(new_devices), 1)
            self.assertIn("192.168.1.34", new_devices[0].get("title") or "")

            new_services = [
                row for row in comparison.get("changes") or [] if row.get("change_type") == "new_service"
            ]
            self.assertTrue(any("5900" in (row.get("title") or "") for row in new_services))
        finally:
            conn.close()

    def test_expected_device_suppresses_change_flag(self) -> None:
        conn = get_db_conn()
        try:
            case = create_case("Baseline compare expected", conn=conn)
            case_id = int(case["id"])
            baseline_summary = {
                "name": "Unit baseline",
                "devices": [{"ip": "192.168.1.10"}],
                "services": [],
                "findings": [],
                "hostnames": [],
                "macs": [],
                "web_technologies": [],
                "web_paths": [],
                "remote_access_services": [],
                "public_contacts": [],
            }
            current_summary = {
                "devices": [{"ip": "192.168.1.10"}, {"ip": "192.168.1.34"}],
                "services": [],
                "findings": [],
                "hostnames": [],
                "macs": [],
                "web_technologies": [],
                "web_paths": [],
                "remote_access_services": [],
                "public_contacts": [],
            }
            mark_expected_item(case_id, item_type="device", item_key="192.168.1.34", conn=conn)
            comparison = compare_baseline_to_current(
                case_id,
                baseline_summary=baseline_summary,
                current_summary=current_summary,
                conn=conn,
            )
            expected_devices = [
                row
                for row in comparison.get("changes") or []
                if row.get("change_type") == "new_device" and row.get("expected")
            ]
            self.assertEqual(len(expected_devices), 1)
        finally:
            conn.close()


if __name__ == "__main__":
    unittest.main()

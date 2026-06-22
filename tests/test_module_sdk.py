#!/usr/bin/env python3
"""Unit tests for the Project Overwatch module SDK."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from utils.module_sdk import (  # noqa: E402
    STATUS_BLOCKED,
    STATUS_COMPLETED,
    STATUS_ERROR,
    add_error,
    add_finding,
    add_warning,
    build_module_result,
    is_successful_result,
    normalise_result,
    validate_implemented_modules,
    validate_module_metadata,
    validate_module_registry,
    validate_module_result,
)


class ModuleSdkTests(unittest.TestCase):
    def test_build_module_result_success(self) -> None:
        result = build_module_result(
            "unit_test",
            STATUS_COMPLETED,
            "Completed successfully",
            success=True,
            data={"key": "value"},
            evidence=[{"title": "Example"}],
        )
        self.assertTrue(is_successful_result(result))
        self.assertEqual(result["module_id"], "unit_test")
        self.assertEqual(result["data"]["key"], "value")
        self.assertEqual(len(result["evidence"]), 1)

    def test_normalise_result_syncs_parsed_data(self) -> None:
        normalized = normalise_result(
            {
                "module_id": "legacy",
                "status": "completed",
                "parsed_data": {"ports": [80]},
            }
        )
        self.assertEqual(normalized["data"]["ports"], [80])
        self.assertEqual(normalized["parsed_data"]["ports"], [80])

    def test_validate_module_result_flags_missing_module_id(self) -> None:
        validation = validate_module_result(normalise_result({"status": STATUS_COMPLETED, "summary": "ok"}))
        self.assertFalse(validation["ok"])
        self.assertIn("missing module_id", validation["errors"])

    def test_helpers_append_lists(self) -> None:
        result = build_module_result("unit_test", STATUS_COMPLETED, "ok")
        add_warning(result, "warn")
        add_error(result, "err")
        add_finding(result, "finding")
        self.assertEqual(result["warnings"], ["warn"])
        self.assertEqual(result["errors"], ["err"])
        self.assertEqual(result["findings"], ["finding"])

    def test_validate_module_registry(self) -> None:
        from modules.module_registry import MODULES

        check = validate_module_registry()
        self.assertTrue(check["module_count"] >= len(MODULES))

    def test_validate_implemented_modules(self) -> None:
        check = validate_implemented_modules()
        self.assertTrue(check["ok"], msg=str(check.get("errors")))

    def test_validate_module_metadata_for_nmap(self) -> None:
        from modules.module_registry import get_module

        module = get_module("infra_nmap")
        assert module is not None
        meta = validate_module_metadata(module)
        self.assertTrue(meta["ok"], msg=str(meta.get("errors")))

    def test_blocked_result_not_successful(self) -> None:
        result = build_module_result(
            "unit_test",
            STATUS_BLOCKED,
            "Blocked",
            success=False,
            errors=["blocked"],
        )
        self.assertFalse(is_successful_result(result))

    def test_error_status_with_success_flag_warns(self) -> None:
        result = normalise_result(
            {
                "module_id": "unit_test",
                "status": STATUS_ERROR,
                "summary": "failed",
                "success": True,
            }
        )
        validation = validate_module_result(result)
        self.assertTrue(any("success=True" in warning for warning in validation["warnings"]))


if __name__ == "__main__":
    unittest.main()

"""Tests for solo UX navigation and Personal Lab case defaults."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock


class SoloUxHelpersTests(unittest.TestCase):
    def test_normalize_nav_maps_archive_pages(self) -> None:
        from ui.constants import normalize_nav_page

        self.assertEqual(normalize_nav_page("Graph"), "Case Archive")
        self.assertEqual(normalize_nav_page("Operations"), "Case Archive")
        self.assertEqual(normalize_nav_page("Assessment Workspace"), "Assessment Workspace")
        self.assertEqual(normalize_nav_page(None), "Assessment Workspace")

    def test_solo_nav_constants(self) -> None:
        from ui.constants import NAV_PAGES, SOLO_MORE_NAV, SOLO_PRIMARY_PAGES

        self.assertIn("Case Archive", NAV_PAGES)
        self.assertNotIn("Graph", NAV_PAGES)
        self.assertIn("Assessment Workspace", SOLO_PRIMARY_PAGES)
        self.assertIn("Case Archive", SOLO_MORE_NAV)

    def test_get_or_create_lab_case(self) -> None:
        import database.db_setup as db

        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "lab.db"
            with mock.patch.object(db, "DB_PATH", db_path):
                first = db.get_or_create_lab_case()
                second = db.get_or_create_lab_case()
                self.assertEqual(first["name"], "Personal Lab")
                self.assertEqual(first["id"], second["id"])
                default = db.create_case("Default Case", "Separate default case.")
                found_default = db.get_or_create_default_case()
                self.assertEqual(found_default["name"], "Default Case")
                self.assertEqual(found_default["id"], default["id"])
                self.assertNotEqual(found_default["id"], first["id"])


if __name__ == "__main__":
    unittest.main()

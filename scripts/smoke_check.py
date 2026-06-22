#!/usr/bin/env python3
"""Lightweight smoke checks for Project Overwatch (no network required)."""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


def check(name: str, fn) -> None:
    try:
        fn()
    except Exception as exc:
        raise AssertionError(f"{name}: {exc}") from exc
    print(f"  OK  {name}")


def warn(name: str, detail: str) -> None:
    print(f"  WARN {name}: {detail}")


def main() -> int:
    print(f"Project Overwatch smoke check (root: {PROJECT_ROOT})")
    errors = 0

    def run(name: str, fn) -> None:
        nonlocal errors
        try:
            check(name, fn)
        except AssertionError as exc:
            print(f"  FAIL {exc}")
            errors += 1

    run("version", lambda: __import__("version", fromlist=["PROJECT_VERSION"]).PROJECT_VERSION)

    run("database setup", lambda: __import__("database.db_setup", fromlist=["get_db_conn"]).get_db_conn().close())

    run(
        "module registry",
        lambda: len(__import__("modules.module_registry", fromlist=["MODULES"]).MODULES) > 0,
    )

    run("executor", lambda: __import__("modules.executor", fromlist=["execute_module"]))

    run("report builder", lambda: __import__("utils.report_builder", fromlist=["build_case_report"]))

    run("findings registry", lambda: __import__("utils.findings_registry", fromlist=["MODULE_FINDING_INTERPRETERS"]))

    run("case backup", lambda: __import__("utils.case_backup", fromlist=["export_case_bundle"]))

    run("local auth", lambda: __import__("utils.local_auth", fromlist=["local_auth_enabled"]))

    run(
        "default case",
        lambda: __import__("database.db_setup", fromlist=["get_or_create_default_case"]).get_or_create_default_case(),
    )

    run(
        "report markdown",
        lambda: (
            __import__("utils.report_builder", fromlist=["build_case_report"]).build_case_report(
                __import__("database.db_setup", fromlist=["get_or_create_default_case"]).get_or_create_default_case()["id"]
            )
            or True
        ),
    )

    if shutil.which("nmap") is None:
        warn("Nmap binary", "not on PATH — Nmap scans will be unavailable until installed")
    else:
        print("  OK  Nmap binary on PATH")

    for optional_pkg, label in (("kaleido", "graph PNG"), ("weasyprint", "PDF export")):
        try:
            __import__(optional_pkg)
            print(f"  OK  optional {label} ({optional_pkg})")
        except (ImportError, OSError) as exc:
            warn(label, f"not ready — pip install -r requirements-optional.txt ({exc.__class__.__name__})")

    if errors:
        print(f"\n{errors} check(s) failed.")
        return 1

    print("\nAll smoke checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

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


def _check_finding_workflow_helpers() -> None:
    db = __import__(
        "database.db_setup",
        fromlist=[
            "create_finding",
            "get_finding",
            "update_finding",
            "close_finding",
            "reopen_finding",
            "list_findings_by_entity",
            "finding_status_counts",
            "get_or_create_default_case",
            "get_db_conn",
        ],
    )
    for name in (
        "get_finding",
        "update_finding",
        "close_finding",
        "reopen_finding",
        "list_findings_by_entity",
        "finding_status_counts",
    ):
        if not callable(getattr(db, name)):
            raise AssertionError(f"missing helper: {name}")

    case = db.get_or_create_default_case()
    conn = db.get_db_conn()
    try:
        finding = db.create_finding(
            case["id"],
            "smoke_test",
            "Smoke check finding workflow",
            "info",
            50,
            "Temporary finding created by smoke_check.py.",
            conn=conn,
        )
        updated = db.update_finding(
            finding["id"],
            status="in_review",
            analyst_notes="Reviewed during smoke check.",
            conn=conn,
        )
        if not updated or updated.get("analyst_notes") != "Reviewed during smoke check.":
            raise AssertionError("update_finding did not persist analyst notes")
        counts = db.finding_status_counts(case["id"], conn=conn)
        if not isinstance(counts, dict) or "in_review" not in counts:
            raise AssertionError("finding_status_counts returned unexpected data")
        fetched = db.get_finding(finding["id"], conn=conn)
        if fetched is None:
            raise AssertionError("get_finding returned None")
        closed = db.close_finding(finding["id"], conn=conn)
        if not closed or db.normalize_finding_status(closed.get("status")) != "closed":
            raise AssertionError("close_finding did not set closed status")
        reopened = db.reopen_finding(finding["id"], conn=conn)
        if not reopened or db.normalize_finding_status(reopened.get("status")) != "open":
            raise AssertionError("reopen_finding did not set open status")
        if finding.get("entity_id") is not None:
            by_entity = db.list_findings_by_entity(finding["entity_id"], conn=conn)
            if not isinstance(by_entity, list):
                raise AssertionError("list_findings_by_entity did not return a list")
    finally:
        conn.close()


def _check_target_compatibility() -> None:
    target_detection = __import__(
        "utils.target_detection",
        fromlist=["get_target_type"],
    )
    compatibility = __import__(
        "utils.module_compatibility",
        fromlist=[
            "get_compatible_modules",
            "get_incompatible_reason",
            "module_accepts_target",
            "build_operation_plan",
        ],
    )
    registry = __import__(
        "modules.module_registry",
        fromlist=["get_module", "MODULES"],
    )

    cases = {
        "192.168.68.124": "ipv4",
        "example.com": "domain",
        "https://example.com/path": "url",
        "analyst@example.com": "email",
        "johndoe": "username",
    }
    for value, expected in cases.items():
        if target_detection.get_target_type(value) != expected:
            raise AssertionError(f"get_target_type({value!r}) expected {expected}")

    nmap = registry.get_module("infra_nmap")
    domain_intel = registry.get_module("infra_domain_intel")
    if nmap is None or domain_intel is None:
        raise AssertionError("expected implemented modules missing from registry")

    for field in (
        "accepted_target_types",
        "short_help",
        "detailed_help",
        "example_inputs",
        "output_summary",
    ):
        if not getattr(nmap, field):
            raise AssertionError(f"infra_nmap missing registry metadata: {field}")
        if not getattr(domain_intel, field):
            raise AssertionError(f"infra_domain_intel missing registry metadata: {field}")

    if not compatibility.module_accepts_target(nmap, "ipv4"):
        raise AssertionError("Nmap should accept IPv4 targets")
    if compatibility.module_accepts_target(domain_intel, "ipv4"):
        raise AssertionError("Domain Intelligence should not accept IPv4 targets")
    if not compatibility.module_accepts_target(domain_intel, "url"):
        raise AssertionError("Domain Intelligence should accept URL targets")

    ip_reason = compatibility.get_incompatible_reason(domain_intel, "ipv4")
    if "domain" not in ip_reason.lower():
        raise AssertionError("expected domain requirement in incompatible reason")

    compatible = compatibility.get_compatible_modules("example.com")
    module_ids = {module.module_id for module in compatible}
    if "infra_nmap" not in module_ids or "infra_domain_intel" not in module_ids:
        raise AssertionError("example.com should be compatible with both implemented modules")

    plan = compatibility.build_operation_plan(
        case_name="Smoke",
        case_id=1,
        target="example.com",
        selected_module_ids=["infra_domain_intel"],
        authorisation_confirmed=False,
    )
    if plan["target_type"] != "domain" or not plan["expected_outputs"]:
        raise AssertionError("operation plan missing expected fields")

    executor = __import__("modules.executor", fromlist=["execute_module"])
    blocked = executor.execute_module("infra_domain_intel", "192.168.68.124")
    if blocked.get("status") != "blocked":
        raise AssertionError("executor should block incompatible domain intel on IPv4")


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
        "finding workflow helpers",
        lambda: _check_finding_workflow_helpers(),
    )

    run(
        "target compatibility",
        lambda: _check_target_compatibility(),
    )

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

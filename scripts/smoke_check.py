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


def _check_cert_subdomain_module() -> None:
    registry = __import__("modules.module_registry", fromlist=["get_module"])
    module = registry.get_module("infra_cert_subdomain")
    if module is None or not module.implemented:
        raise AssertionError("infra_cert_subdomain registry entry missing or not implemented")
    for field in (
        "accepted_target_types",
        "short_help",
        "detailed_help",
        "example_inputs",
        "output_summary",
        "caution_notes",
    ):
        if not getattr(module, field):
            raise AssertionError(f"infra_cert_subdomain missing registry metadata: {field}")

    import importlib.util
    from pathlib import Path

    module_path = Path(PROJECT_ROOT) / "modules" / "2_infrastructure" / "infra_cert_subdomain.py"
    spec = importlib.util.spec_from_file_location("infra_cert_subdomain", module_path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load infra_cert_subdomain module spec")
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    if not callable(getattr(loaded, "run_cert_subdomain_intel", None)):
        raise AssertionError("run_cert_subdomain_intel missing")

    executor = __import__("modules.executor", fromlist=["is_runtime_ready", "get_module"])
    if not executor.is_runtime_ready("infra_cert_subdomain"):
        raise AssertionError("executor cannot load infra_cert_subdomain backend")

    findings = __import__(
        "utils.cert_subdomain_interpreter",
        fromlist=["interpret_cert_subdomain_results"],
    )
    sample_findings = findings.interpret_cert_subdomain_results(
        {
            "domain": "example.com",
            "subdomains": ["www.example.com", "api.example.com"],
            "wildcard_observed": True,
            "source": "crt.sh",
        }
    )
    if not sample_findings:
        raise AssertionError("cert subdomain interpreter returned no findings for sample data")

    registry_pipeline = __import__(
        "utils.findings_registry",
        fromlist=["module_has_findings_pipeline"],
    )
    if not registry_pipeline.module_has_findings_pipeline("infra_cert_subdomain"):
        raise AssertionError("findings pipeline not registered for infra_cert_subdomain")


def _check_stale_finding_reopen() -> None:
    db = __import__(
        "database.db_setup",
        fromlist=[
            "create_finding",
            "upsert_finding",
            "close_finding",
            "normalize_finding_status",
            "get_or_create_default_case",
            "get_db_conn",
            "STALE_REOPEN_NOTE",
        ],
    )
    case = db.get_or_create_default_case()
    conn = db.get_db_conn()
    try:
        finding = db.create_finding(
            case["id"],
            "smoke_test",
            "Stale reopen smoke finding",
            "low",
            60,
            "Original explanation.",
            conn=conn,
        )
        db.close_finding(finding["id"], conn=conn)
        reopened = db.upsert_finding(
            case["id"],
            "smoke_test",
            "Stale reopen smoke finding",
            "medium",
            70,
            "Re-observed explanation.",
            conn=conn,
        )
        if db.normalize_finding_status(reopened.get("status")) != "open":
            raise AssertionError("upsert_finding did not reopen terminal finding")
        if db.STALE_REOPEN_NOTE not in (reopened.get("analyst_notes") or ""):
            raise AssertionError("stale reopen note missing from analyst_notes")
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
    cert_subdomain = registry.get_module("infra_cert_subdomain")
    if nmap is None or domain_intel is None or cert_subdomain is None:
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
    if not compatibility.module_accepts_target(cert_subdomain, "domain"):
        raise AssertionError("Certificate & Subdomain Intelligence should accept domain targets")
    if compatibility.module_accepts_target(cert_subdomain, "ipv4"):
        raise AssertionError("Certificate & Subdomain Intelligence should not accept IPv4 targets")

    ip_reason = compatibility.get_incompatible_reason(domain_intel, "ipv4")
    if "domain" not in ip_reason.lower():
        raise AssertionError("expected domain requirement in incompatible reason")

    compatible = compatibility.get_compatible_modules("example.com")
    module_ids = {module.module_id for module in compatible}
    if (
        "infra_nmap" not in module_ids
        or "infra_domain_intel" not in module_ids
        or "infra_cert_subdomain" not in module_ids
        or "infra_website_metadata" not in module_ids
    ):
        raise AssertionError("example.com should be compatible with all implemented domain modules")

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


def _check_run_modes() -> None:
    run_modes = __import__(
        "utils.run_modes",
        fromlist=[
            "list_run_modes",
            "get_recommended_modules_for_mode",
            "get_run_mode_description",
            "get_run_mode_expected_outputs",
            "get_recommendation_reason",
            "QUICK_CHECK",
            "WEBSITE_FOOTPRINT",
            "LOCAL_IP_CHECK",
            "CUSTOM",
        ],
    )
    modes = run_modes.list_run_modes()
    if len(modes) < 4:
        raise AssertionError("expected at least four run modes")
    for mode_id, label in modes:
        if not label or not run_modes.get_run_mode_description(mode_id):
            raise AssertionError(f"missing description for run mode {mode_id}")

    ip_recommended = run_modes.get_recommended_modules_for_mode(
        run_modes.LOCAL_IP_CHECK, "ipv4"
    )
    if ip_recommended != ["infra_nmap"]:
        raise AssertionError(f"IPv4 local check should recommend Nmap only, got {ip_recommended}")

    domain_quick = run_modes.get_recommended_modules_for_mode(
        run_modes.QUICK_CHECK, "domain"
    )
    if set(domain_quick) != {"infra_domain_intel", "infra_cert_subdomain", "infra_website_metadata"}:
        raise AssertionError(f"domain quick check recommendations unexpected: {domain_quick}")

    url_footprint = run_modes.get_recommended_modules_for_mode(
        run_modes.WEBSITE_FOOTPRINT, "url"
    )
    if set(url_footprint) != {"infra_domain_intel", "infra_cert_subdomain", "infra_website_metadata"}:
        raise AssertionError(f"URL footprint recommendations unexpected: {url_footprint}")

    for unsupported in ("email", "username", "unknown"):
        quick = run_modes.get_recommended_modules_for_mode(run_modes.QUICK_CHECK, unsupported)
        if quick:
            raise AssertionError(f"Quick Check should not recommend modules for {unsupported}")
        custom = run_modes.get_recommended_modules_for_mode(run_modes.CUSTOM, unsupported)
        if custom:
            raise AssertionError("Custom mode should not auto-recommend modules")

    outputs = run_modes.get_run_mode_expected_outputs(run_modes.QUICK_CHECK, "domain")
    if not outputs or "Domain Intelligence" not in outputs[0]:
        raise AssertionError("expected domain module output in quick check plan")

    reason = run_modes.get_recommendation_reason(run_modes.LOCAL_IP_CHECK, "ipv4")
    if "authorisation" not in reason.lower():
        raise AssertionError("local IP check reason should mention authorisation")

    with_port_scan = run_modes.resolve_recommended_modules_for_mode(
        run_modes.QUICK_CHECK,
        "domain",
        quick_check_include_port_scan=True,
    )
    if "infra_nmap" not in with_port_scan:
        raise AssertionError("Quick Check port scan option should include Nmap for domains")

    presets = __import__(
        "utils.report_presets",
        fromlist=["suggest_preset_for_run_mode", "presets_for_run_mode"],
    )
    if not presets.suggest_preset_for_run_mode(run_modes.WEBSITE_FOOTPRINT):
        raise AssertionError("expected report preset for website footprint mode")
    if "domain_footprint_summary" not in presets.presets_for_run_mode(run_modes.WEBSITE_FOOTPRINT):
        raise AssertionError("domain footprint preset missing")

    db = __import__(
        "database.db_setup",
        fromlist=[
            "create_case",
            "get_case",
            "update_case_run_mode",
            "create_operation_log",
            "operation_run_mode_counts",
            "get_or_create_default_case",
            "get_db_conn",
        ],
    )
    case = db.create_case("Smoke run mode case", "temporary")
    updated = db.update_case_run_mode(case["id"], run_modes.LOCAL_IP_CHECK)
    if not updated or updated.get("default_run_mode") != run_modes.LOCAL_IP_CHECK:
        raise AssertionError("update_case_run_mode did not persist default_run_mode")
    conn = db.get_db_conn()
    try:
        db.create_operation_log(
            case["id"],
            "infra_nmap",
            "192.168.1.1",
            "completed",
            run_mode_id=run_modes.LOCAL_IP_CHECK,
            run_mode_label="Local Device / IP Check",
            conn=conn,
        )
        counts = db.operation_run_mode_counts(case["id"], conn=conn)
        if counts.get("Local Device / IP Check") != 1:
            raise AssertionError("operation_run_mode_counts unexpected")
    finally:
        conn.close()


def _check_website_metadata_module() -> None:
    registry = __import__("modules.module_registry", fromlist=["get_module"])
    module = registry.get_module("infra_website_metadata")
    if module is None or not module.implemented:
        raise AssertionError("infra_website_metadata registry entry missing or not implemented")
    for field in (
        "accepted_target_types",
        "short_help",
        "detailed_help",
        "example_inputs",
        "output_summary",
        "caution_notes",
    ):
        if not getattr(module, field):
            raise AssertionError(f"infra_website_metadata missing registry metadata: {field}")

    import importlib.util
    from pathlib import Path

    module_path = Path(PROJECT_ROOT) / "modules" / "2_infrastructure" / "infra_website_metadata.py"
    spec = importlib.util.spec_from_file_location("infra_website_metadata", module_path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load infra_website_metadata module spec")
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    if not callable(getattr(loaded, "run_website_metadata_review", None)):
        raise AssertionError("run_website_metadata_review missing")

    sample_html = """
    <html><head>
    <title>Example Domain</title>
    <meta name="description" content="Example public site">
    <link rel="canonical" href="https://example.com/">
    </head><body><a href="/about">About</a><form></form></body></html>
    """
    metadata = loaded._parse_homepage_metadata(sample_html, "https://example.com/")
    if metadata.get("page_title") != "Example Domain":
        raise AssertionError("homepage metadata parser failed on sample HTML")
    if metadata.get("link_count") != 1 or metadata.get("form_count") != 1:
        raise AssertionError("link/form counts unexpected in sample HTML")

    robots = loaded._parse_robots_txt("User-agent: *\nDisallow: /admin\nSitemap: https://example.com/sitemap.xml\n")
    if robots.get("disallow_count") != 1 or not robots.get("sitemap_urls"):
        raise AssertionError("robots.txt parser failed")

    findings = __import__(
        "utils.website_metadata_interpreter",
        fromlist=["interpret_website_metadata_results"],
    )
    sample_findings = findings.interpret_website_metadata_results(
        {
            "domain": "example.com",
            "homepage": {
                "page_title": "Example Domain",
                "meta_description": "Example public site",
                "canonical_url": "https://example.com/",
                "link_count": 3,
                "form_count": 1,
            },
            "robots_txt": {"available": True, "summary": "1 disallow rule(s); 1 sitemap reference(s)"},
            "sitemap_hints": {"reachable_count": 1, "entries": [{"url": "https://example.com/sitemap.xml"}]},
        }
    )
    if not sample_findings:
        raise AssertionError("website metadata interpreter returned no findings for sample data")

    registry_pipeline = __import__(
        "utils.findings_registry",
        fromlist=["module_has_findings_pipeline"],
    )
    if not registry_pipeline.module_has_findings_pipeline("infra_website_metadata"):
        raise AssertionError("findings pipeline not registered for infra_website_metadata")

    executor = __import__("modules.executor", fromlist=["is_runtime_ready", "get_module"])
    if not executor.is_runtime_ready("infra_website_metadata"):
        raise AssertionError("executor cannot load infra_website_metadata backend")


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
        "stale finding reopen",
        lambda: _check_stale_finding_reopen(),
    )

    run(
        "target compatibility",
        lambda: _check_target_compatibility(),
    )

    run(
        "run modes",
        lambda: _check_run_modes(),
    )

    run(
        "website metadata module",
        lambda: _check_website_metadata_module(),
    )

    run(
        "cert subdomain module",
        lambda: _check_cert_subdomain_module(),
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

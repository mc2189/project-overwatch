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


def _check_entity_helpers() -> None:
    db = __import__(
        "database.db_setup",
        fromlist=[
            "create_or_get_entity",
            "get_entity",
            "update_entity_notes",
            "update_entity_label",
            "update_entity_confidence",
            "get_or_create_default_case",
            "get_db_conn",
        ],
    )
    for name in (
        "get_entity",
        "update_entity_notes",
        "update_entity_label",
        "update_entity_confidence",
    ):
        if not callable(getattr(db, name)):
            raise AssertionError(f"missing helper: {name}")

    case = db.get_or_create_default_case()
    conn = db.get_db_conn()
    try:
        entity = db.create_or_get_entity(
            case["id"],
            "domain",
            "smoke-entity.example",
            label="Smoke entity",
            source="smoke_check",
            conn=conn,
        )
        updated_notes = db.update_entity_notes(entity["id"], "Pivot smoke notes", conn=conn)
        if not updated_notes or updated_notes.get("notes") != "Pivot smoke notes":
            raise AssertionError("update_entity_notes did not persist")
        updated_label = db.update_entity_label(entity["id"], "Smoke label", conn=conn)
        if not updated_label or updated_label.get("label") != "Smoke label":
            raise AssertionError("update_entity_label did not persist")
        updated_conf = db.update_entity_confidence(entity["id"], 88, conn=conn)
        if not updated_conf or updated_conf.get("confidence") != 88:
            raise AssertionError("update_entity_confidence did not persist")
        fetched = db.get_entity(entity["id"], conn=conn)
        if fetched is None:
            raise AssertionError("get_entity returned None")
    finally:
        conn.close()

    pivot = __import__(
        "utils.entity_pivot",
        fromlist=[
            "build_pivot_recommendations",
            "parse_service_entity_details",
            "entity_execution_target",
        ],
    )
    domain_entity = {"entity_type": "domain", "value": "example.com"}
    rec = pivot.build_pivot_recommendations(domain_entity)
    module_ids = {row["module_id"] for row in rec.get("module_rows", []) if row.get("compatible")}
    expected = {"infra_domain_intel", "infra_cert_subdomain", "infra_website_metadata"}
    if not expected.issubset(module_ids):
        raise AssertionError(f"domain pivot missing modules: {module_ids}")

    service_entity = {
        "entity_type": "service",
        "value": "192.0.2.1:443/tcp",
        "label": "443/tcp https Example",
    }
    service_rec = pivot.build_pivot_recommendations(service_entity)
    if service_rec.get("compatible_modules"):
        raise AssertionError("service entity should not recommend direct modules")
    details = pivot.parse_service_entity_details(service_entity)
    if not details or details.get("port") != "443":
        raise AssertionError("service entity parse failed")

    email_entity = {"entity_type": "email", "value": "user@example.com"}
    email_rec = pivot.build_pivot_recommendations(email_entity)
    if email_rec.get("compatible_modules"):
        raise AssertionError("email entity should not recommend modules yet")


def _check_settings_manager() -> None:
    settings = __import__(
        "utils.settings_manager",
        fromlist=[
            "mask_api_key",
            "has_api_key",
            "validate_module_settings",
            "list_api_provider_status",
            "list_module_config_status",
            "env_example_exists",
            "env_ignored_by_git",
            "rate_limit_seconds",
        ],
    )
    if not settings.env_example_exists():
        raise AssertionError(".env.example is missing")
    if not settings.env_ignored_by_git():
        raise AssertionError(".env is not listed in .gitignore")

    masked = settings.mask_api_key("vt_test_secret_key_abcd")
    if "secret" in masked or masked.count("*") < 4:
        raise AssertionError("mask_api_key did not mask sufficiently")
    if not masked.startswith("vt_"):
        raise AssertionError("mask_api_key should preserve short prefix")

    registry = __import__("modules.module_registry", fromlist=["get_module"])
    domain = registry.get_module("infra_domain_intel")
    if domain is None:
        raise AssertionError("infra_domain_intel missing")
    domain_validation = settings.validate_module_settings("infra_domain_intel")
    if not domain_validation["ok"]:
        raise AssertionError("domain intel should pass settings validation without API keys")

    vt = registry.get_module("intel_virustotal")
    if vt is None or not vt.requires_api_key:
        raise AssertionError("intel_virustotal should require API key")
    if vt.api_key_names != ("VIRUSTOTAL_API_KEY",):
        raise AssertionError("intel_virustotal api_key_names mismatch")
    vt_validation = settings.validate_module_settings("intel_virustotal")
    if vt_validation["ok"]:
        raise AssertionError("intel_virustotal should fail validation without API key")

    providers = settings.list_api_provider_status()
    if len(providers) < 8:
        raise AssertionError("expected at least 8 API provider definitions")
    modules = settings.list_module_config_status()
    if not any(row["module_id"] == "infra_nmap" for row in modules):
        raise AssertionError("list_module_config_status missing infra_nmap")

    if settings.rate_limit_seconds() <= 0:
        raise AssertionError("rate_limit_seconds should be positive")


def _check_batch_queue_helpers() -> None:
    bq = __import__(
        "utils.batch_queue",
        fromlist=[
            "build_queue_item",
            "add_queue_item",
            "add_passive_modules_for_entity",
            "is_duplicate_queue_item",
            "find_recent_operation",
            "map_result_to_queue_status",
            "passive_queued_items",
            "clear_completed_items",
            "PASSIVE_BATCH_MODULE_IDS",
        ],
    )
    db = __import__(
        "database.db_setup",
        fromlist=["get_or_create_default_case", "create_or_get_entity", "get_db_conn"],
    )

    case = db.get_or_create_default_case()
    entity = {
        "id": 1,
        "entity_type": "domain",
        "value": "batch-queue.example",
        "label": "Batch queue smoke",
    }
    module = __import__("modules.module_registry", fromlist=["get_module"]).get_module(
        "infra_domain_intel"
    )
    if module is None:
        raise AssertionError("infra_domain_intel missing")

    item = bq.build_queue_item(case["id"], entity, module)
    for field in (
        "case_id",
        "entity_id",
        "entity_value",
        "entity_type",
        "module_id",
        "module_display_name",
        "mode",
        "compatibility_status",
        "status",
        "created_at",
    ):
        if field not in item:
            raise AssertionError(f"queue item missing field: {field}")
    if item["compatibility_status"] != "compatible":
        raise AssertionError("domain should be compatible with domain intel")
    if item["mode"] != "passive":
        raise AssertionError("domain intel should be passive")

    items: list = []
    items, added, reason = bq.add_queue_item(items, case["id"], entity, "infra_domain_intel")
    if not added or reason:
        raise AssertionError("first add_queue_item failed")
    items, dup, dup_reason = bq.add_queue_item(items, case["id"], entity, "infra_domain_intel")
    if dup or not dup_reason:
        raise AssertionError("duplicate queue item should be skipped")

    items, added_list, skipped = bq.add_passive_modules_for_entity(items, case["id"], entity)
    if not isinstance(added_list, list):
        raise AssertionError("add_passive_modules_for_entity did not return added list")
    passive = bq.passive_queued_items(items)
    if not all(row.get("mode") == "passive" for row in passive):
        raise AssertionError("passive_queued_items included non-passive row")

    recent = bq.find_recent_operation(
        [
            {
                "module_id": "infra_domain_intel",
                "target": "batch-queue.example",
                "started_at": "2099-01-01T00:00:00+00:00",
            }
        ],
        module_id="infra_domain_intel",
        target="batch-queue.example",
    )
    if recent is None:
        raise AssertionError("find_recent_operation should match future-dated operation")

    status = bq.map_result_to_queue_status({"status": "completed_with_warnings", "success": True})
    if status != "completed_with_warnings":
        raise AssertionError("map_result_to_queue_status failed")
    blocked = bq.map_result_to_queue_status({"status": "blocked", "success": False})
    if blocked != "blocked":
        raise AssertionError("blocked status mapping failed")

    cleared = bq.clear_completed_items(
        [{"status": "completed"}, {"status": "queued"}, {"status": "error"}]
    )
    if len(cleared) != 1 or cleared[0]["status"] != "queued":
        raise AssertionError("clear_completed_items failed")

    if "infra_nmap" in bq.PASSIVE_BATCH_MODULE_IDS:
        raise AssertionError("Nmap must not be in passive batch defaults")


def _check_batch_queue_persistence() -> None:
    db = __import__(
        "database.db_setup",
        fromlist=[
            "get_or_create_default_case",
            "create_or_get_entity",
            "get_db_conn",
            "list_batch_queue_items",
            "sync_batch_queue_items",
            "create_batch_queue_run",
            "list_batch_queue_runs",
            "batch_queue_item_counts",
        ],
    )
    store = __import__(
        "utils.batch_queue_store",
        fromlist=["move_queue_item", "record_batch_queue_run"],
    )
    case = db.get_or_create_default_case()
    conn = db.get_db_conn()
    try:
        entity = db.create_or_get_entity(
            case["id"],
            "domain",
            "batch-persist.example",
            label="Persist smoke",
            source="smoke_check",
            conn=conn,
        )
        items = [
            {
                "queue_id": "smoke-q1",
                "case_id": case["id"],
                "entity_id": entity["id"],
                "entity_value": entity["value"],
                "entity_type": "domain",
                "execution_target": entity["value"],
                "module_id": "infra_domain_intel",
                "module_display_name": "Domain Intelligence",
                "mode": "passive",
                "compatibility_status": "compatible",
                "status": "queued",
                "position": 0,
                "summary": "",
                "recent_run_warning": None,
                "created_at": "2026-01-01T00:00:00+00:00",
                "completed_at": None,
            },
            {
                "queue_id": "smoke-q2",
                "case_id": case["id"],
                "entity_id": entity["id"],
                "entity_value": entity["value"],
                "entity_type": "domain",
                "execution_target": entity["value"],
                "module_id": "infra_cert_subdomain",
                "module_display_name": "Certificate & Subdomain Intelligence",
                "mode": "passive",
                "compatibility_status": "compatible",
                "status": "queued",
                "position": 1,
                "summary": "",
                "recent_run_warning": None,
                "created_at": "2026-01-01T00:00:01+00:00",
                "completed_at": None,
            },
        ]
        db.sync_batch_queue_items(case["id"], items, conn=conn)
        loaded = db.list_batch_queue_items(case["id"], conn=conn)
        if len(loaded) != 2:
            raise AssertionError("list_batch_queue_items did not persist items")
        moved = store.move_queue_item(loaded, "smoke-q2", "up")
        if moved[0].get("queue_id") != "smoke-q2":
            raise AssertionError("move_queue_item up failed")
        run = db.create_batch_queue_run(
            case["id"],
            items_processed=1,
            items_completed=1,
            items_warnings=0,
            items_failed=0,
            run_summary="Smoke batch run",
            conn=conn,
        )
        if not run or not run.get("id"):
            raise AssertionError("create_batch_queue_run failed")
        runs = db.list_batch_queue_runs(case["id"], limit=5, conn=conn)
        if not runs:
            raise AssertionError("list_batch_queue_runs empty")
        counts = db.batch_queue_item_counts(conn=conn)
        if case["id"] not in counts:
            raise AssertionError("batch_queue_item_counts missing case")
        conn.execute("DELETE FROM batch_queue_items WHERE case_id = ?", (case["id"],))
        conn.execute("DELETE FROM batch_queue_runs WHERE case_id = ?", (case["id"],))
        conn.commit()
    finally:
        conn.close()


def _check_pivot_queue_helpers() -> None:
    db = __import__(
        "database.db_setup",
        fromlist=[
            "add_to_pivot_queue",
            "remove_from_pivot_queue",
            "clear_pivot_queue",
            "list_pivot_queue_entity_ids",
            "pivot_queue_contains",
            "create_or_get_entity",
            "get_or_create_default_case",
            "get_db_conn",
        ],
    )
    for name in (
        "add_to_pivot_queue",
        "remove_from_pivot_queue",
        "clear_pivot_queue",
        "list_pivot_queue_entity_ids",
        "pivot_queue_contains",
    ):
        if not callable(getattr(db, name)):
            raise AssertionError(f"missing helper: {name}")

    case = db.get_or_create_default_case()
    conn = db.get_db_conn()
    try:
        entity = db.create_or_get_entity(
            case["id"],
            "domain",
            "pivot-queue.example",
            label="Pivot queue smoke",
            source="smoke_check",
            conn=conn,
        )
        row = db.add_to_pivot_queue(case["id"], entity["id"], conn=conn)
        if row is None:
            raise AssertionError("add_to_pivot_queue returned None")
        if not db.pivot_queue_contains(case["id"], entity["id"], conn=conn):
            raise AssertionError("pivot_queue_contains false after add")
        ids = db.list_pivot_queue_entity_ids(case["id"], conn=conn)
        if entity["id"] not in ids:
            raise AssertionError("entity missing from list_pivot_queue_entity_ids")
        if not db.remove_from_pivot_queue(case["id"], entity["id"], conn=conn):
            raise AssertionError("remove_from_pivot_queue failed")
        if db.pivot_queue_contains(case["id"], entity["id"], conn=conn):
            raise AssertionError("entity still queued after remove")
        db.add_to_pivot_queue(case["id"], entity["id"], conn=conn)
        cleared = db.clear_pivot_queue(case["id"], conn=conn)
        if cleared < 1:
            raise AssertionError("clear_pivot_queue removed no rows")
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


def _check_whois_rdap_module() -> None:
    registry = __import__("modules.module_registry", fromlist=["get_module"])
    module = registry.get_module("infra_whois_rdap")
    if module is None or not module.implemented:
        raise AssertionError("infra_whois_rdap registry entry missing or not implemented")
    for field in (
        "accepted_target_types",
        "short_help",
        "detailed_help",
        "example_inputs",
        "output_summary",
        "caution_notes",
    ):
        if not getattr(module, field):
            raise AssertionError(f"infra_whois_rdap missing registry metadata: {field}")
    if module.accepted_target_types != ("domain", "url", "ipv4"):
        raise AssertionError("infra_whois_rdap accepted_target_types mismatch")

    import importlib.util

    module_path = PROJECT_ROOT / "modules" / "2_infrastructure" / "infra_whois_rdap.py"
    spec = importlib.util.spec_from_file_location("infra_whois_rdap", module_path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load infra_whois_rdap module spec")
    loaded = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(loaded)
    if not callable(getattr(loaded, "run_whois_rdap_lookup", None)):
        raise AssertionError("run_whois_rdap_lookup missing")

    executor = __import__("modules.executor", fromlist=["is_runtime_ready"])
    if not executor.is_runtime_ready("infra_whois_rdap"):
        raise AssertionError("executor cannot load infra_whois_rdap backend")

    mock_payload = {
        "objectClassName": "domain",
        "handle": "EXAMPLE-DOM",
        "ldhName": "example.com",
        "status": ["client transfer prohibited"],
        "events": [
            {"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
            {"eventAction": "expiration", "eventDate": "2026-08-13T04:00:00Z"},
        ],
        "nameservers": [{"ldhName": "ns1.example.com"}, {"ldhName": "ns2.example.com"}],
        "entities": [
            {
                "roles": ["registrar"],
                "handle": "REG-EXAMPLE",
                "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar Inc"]]],
            }
        ],
    }
    lookup = loaded.run_whois_rdap_lookup(
        "example.com",
        options={"mock_rdap_response": mock_payload},
    )
    if not lookup.get("success"):
        raise AssertionError("mock WHOIS/RDAP lookup should succeed")
    parsed = lookup.get("data") or lookup.get("parsed_data") or {}
    if not parsed.get("rdap_summary"):
        raise AssertionError("mock WHOIS/RDAP lookup missing rdap_summary")

    private = loaded.run_whois_rdap_lookup("192.168.1.10")
    if not private.get("success"):
        raise AssertionError("private IP lookup should succeed as informational result")
    private_data = private.get("data") or private.get("parsed_data") or {}
    if not private_data.get("private_local_ip"):
        raise AssertionError("private IP should be flagged as private_local_ip")

    interpreter = __import__(
        "utils.whois_rdap_interpreter",
        fromlist=["interpret_whois_rdap_results"],
    )
    findings = interpreter.interpret_whois_rdap_results(parsed)
    if not findings:
        raise AssertionError("whois rdap interpreter returned no findings for sample data")

    registry_pipeline = __import__(
        "utils.findings_registry",
        fromlist=["module_has_findings_pipeline"],
    )
    if not registry_pipeline.module_has_findings_pipeline("infra_whois_rdap"):
        raise AssertionError("findings pipeline not registered for infra_whois_rdap")

    sdk = __import__("utils.module_sdk", fromlist=["normalise_result", "validate_module_result"])
    normalized = sdk.normalise_result(lookup)
    validation = sdk.validate_module_result(normalized)
    if not validation["ok"] and validation["errors"]:
        raise AssertionError(f"WHOIS/RDAP result failed SDK validation: {validation['errors']}")

    whois_text = (
        "Domain Name: example.com\n"
        "Registrar: Example Registrar Inc\n"
        "Creation Date: 1995-08-14T04:00:00Z\n"
        "Registry Expiry Date: 2026-08-13T04:00:00Z\n"
        "Name Server: ns1.example.com\n"
        "Name Server: ns2.example.com\n"
        "Abuse Email: abuse@example.com\n"
    )
    whois_lookup = loaded.run_whois_rdap_lookup(
        "example.com",
        options={"mock_whois_text": whois_text},
    )
    if not whois_lookup.get("success"):
        raise AssertionError("mock WHOIS fallback lookup should succeed")
    whois_data = whois_lookup.get("data") or whois_lookup.get("parsed_data") or {}
    if whois_data.get("source") != "whois":
        raise AssertionError("mock WHOIS fallback should set source=whois")
    if not whois_data.get("rdap_summary", {}).get("nameservers"):
        raise AssertionError("WHOIS parser should extract nameservers")

    parser = __import__("utils.whois_rdap_parser", fromlist=["parse_whois_text"])
    summary = parser.parse_whois_text(whois_text, query_value="example.com", target_type="domain")
    if not (summary.get("registrar") or {}).get("name"):
        raise AssertionError("parse_whois_text should extract registrar")

    cache = __import__("utils.rdap_cache", fromlist=["get_rdap_cache_entry", "set_rdap_cache_entry"])
    db = __import__("database.db_setup", fromlist=["get_or_create_default_case", "get_db_conn"])
    case = db.get_or_create_default_case()
    conn = db.get_db_conn()
    try:
        cache.set_rdap_cache_entry(
            case["id"],
            "domain:cache-smoke.example",
            "domain",
            "rdap",
            '{"objectClassName":"domain","ldhName":"cache-smoke.example"}',
            rdap_url="mock://cache",
            conn=conn,
        )
        cached = cache.get_rdap_cache_entry(case["id"], "domain:cache-smoke.example", conn=conn)
        if not cached or cached.get("source") != "rdap":
            raise AssertionError("rdap cache get/set failed")
        cached_lookup = loaded.run_whois_rdap_lookup(
            "cache-smoke.example",
            options={"case_id": case["id"], "use_cache": True, "skip_bootstrap": True},
        )
        cached_data = cached_lookup.get("data") or cached_lookup.get("parsed_data") or {}
        if not cached_data.get("from_cache"):
            raise AssertionError("lookup should reuse case cache when available")
    finally:
        conn.close()


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
    expected_domain_modules = {
        "infra_whois_rdap",
        "infra_domain_intel",
        "infra_cert_subdomain",
        "infra_website_metadata",
    }
    if set(domain_quick) != expected_domain_modules:
        raise AssertionError(f"domain quick check recommendations unexpected: {domain_quick}")

    url_footprint = run_modes.get_recommended_modules_for_mode(
        run_modes.WEBSITE_FOOTPRINT, "url"
    )
    if set(url_footprint) != expected_domain_modules:
        raise AssertionError(f"URL footprint recommendations unexpected: {url_footprint}")

    public_ip_modules = run_modes.resolve_recommended_modules_for_mode(
        run_modes.LOCAL_IP_CHECK,
        "ipv4",
        target="8.8.8.8",
    )
    if "infra_whois_rdap" not in public_ip_modules:
        raise AssertionError("public IPv4 local check should recommend WHOIS/RDAP")
    private_ip_modules = run_modes.resolve_recommended_modules_for_mode(
        run_modes.LOCAL_IP_CHECK,
        "ipv4",
        target="192.168.1.10",
    )
    if "infra_whois_rdap" in private_ip_modules:
        raise AssertionError("private IPv4 local check should not recommend WHOIS/RDAP")

    for unsupported in ("email", "username", "unknown"):
        quick = run_modes.get_recommended_modules_for_mode(run_modes.QUICK_CHECK, unsupported)
        if quick:
            raise AssertionError(f"Quick Check should not recommend modules for {unsupported}")
        custom = run_modes.get_recommended_modules_for_mode(run_modes.CUSTOM, unsupported)
        if custom:
            raise AssertionError("Custom mode should not auto-recommend modules")

    outputs = run_modes.get_run_mode_expected_outputs(run_modes.QUICK_CHECK, "domain")
    if not outputs:
        raise AssertionError("expected domain module outputs in quick check plan")
    output_text = " ".join(outputs)
    if "Domain Intelligence" not in output_text or "WHOIS / RDAP Intelligence" not in output_text:
        raise AssertionError("expected domain and WHOIS/RDAP outputs in quick check plan")

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


def _check_evidence_model() -> None:
    evidence = __import__(
        "utils.evidence_model",
        fromlist=[
            "EVIDENCE_TYPES",
            "RELIABILITY_LEVELS",
            "CONFIDENCE_GUIDANCE",
            "EVIDENCE_DIRECT_OBSERVATION",
            "EVIDENCE_THIRD_PARTY_SOURCE",
            "EVIDENCE_PARSER_INFERRED",
            "EVIDENCE_ANALYST_NOTE",
            "EVIDENCE_USER_SUPPLIED",
            "EVIDENCE_UNAVAILABLE_SOURCE",
            "EVIDENCE_SYSTEM_GENERATED",
            "RELIABILITY_HIGH",
            "RELIABILITY_MEDIUM",
            "RELIABILITY_LOW",
            "RELIABILITY_UNKNOWN",
            "default_evidence_for_module",
            "attach_evidence_metadata",
            "observation_evidence_for_module",
            "default_relationship_evidence",
        ],
    )
    expected_types = {
        "direct_observation",
        "third_party_source",
        "parser_inferred",
        "analyst_note",
        "user_supplied",
        "unavailable_source",
        "system_generated",
    }
    if set(evidence.EVIDENCE_TYPES) != expected_types:
        raise AssertionError(f"EVIDENCE_TYPES mismatch: {evidence.EVIDENCE_TYPES}")
    expected_reliability = {"high", "medium", "low", "unknown"}
    if set(evidence.RELIABILITY_LEVELS) != expected_reliability:
        raise AssertionError(f"RELIABILITY_LEVELS mismatch: {evidence.RELIABILITY_LEVELS}")
    if len(evidence.CONFIDENCE_GUIDANCE) < 4:
        raise AssertionError("CONFIDENCE_GUIDANCE should define four bands")

    nmap_defaults = evidence.default_evidence_for_module("infra_nmap")
    if nmap_defaults.get("evidence_type") != evidence.EVIDENCE_DIRECT_OBSERVATION:
        raise AssertionError("Nmap evidence defaults unexpected")
    if nmap_defaults.get("reliability") != evidence.RELIABILITY_HIGH:
        raise AssertionError("Nmap reliability should be high")

    attached = evidence.attach_evidence_metadata({}, "infra_cert_subdomain")
    if attached.get("source_name") != "crt.sh":
        raise AssertionError("attach_evidence_metadata did not apply crt.sh defaults")

    rel = evidence.default_relationship_evidence("infra_nmap", "exposes_service")
    if rel.get("evidence_type") != evidence.EVIDENCE_DIRECT_OBSERVATION:
        raise AssertionError("Nmap exposes_service relationship evidence unexpected")

    db = __import__(
        "database.db_setup",
        fromlist=[
            "ensure_evidence_columns",
            "create_observation",
            "create_relationship",
            "create_finding",
            "create_or_get_entity",
            "get_or_create_default_case",
            "get_db_conn",
            "normalise_evidence_type",
            "normalise_reliability",
        ],
    )
    if not callable(db.ensure_evidence_columns):
        raise AssertionError("ensure_evidence_columns missing")
    conn = db.get_db_conn()
    try:
        db.ensure_evidence_columns(conn)
        obs_columns = {row[1] for row in conn.execute("PRAGMA table_info(observations)").fetchall()}
        for column in (
            "evidence_type",
            "source_name",
            "source_url",
            "reliability",
            "collection_method",
            "collected_at",
            "module_version",
        ):
            if column not in obs_columns:
                raise AssertionError(f"observations missing column: {column}")
        finding_columns = {row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()}
        for column in ("evidence_type", "source_name", "reliability"):
            if column not in finding_columns:
                raise AssertionError(f"findings missing column: {column}")
        rel_columns = {row[1] for row in conn.execute("PRAGMA table_info(relationships)").fetchall()}
        for column in ("evidence_type", "reliability"):
            if column not in rel_columns:
                raise AssertionError(f"relationships missing column: {column}")

        if db.normalise_evidence_type("direct_lookup") != "third_party_source":
            raise AssertionError("normalise_evidence_type alias failed")
        if db.normalise_reliability("HIGH") != "high":
            raise AssertionError("normalise_reliability failed")

        case = db.get_or_create_default_case()
        entity = db.create_or_get_entity(
            case["id"],
            "domain",
            "evidence-smoke.example",
            source="smoke_check",
            conn=conn,
        )
        observation = db.create_observation(
            case["id"],
            entity["id"],
            "infra_nmap",
            "network_scan",
            "Evidence smoke observation",
            summary="Smoke test",
            conn=conn,
        )
        if not observation.get("evidence_type"):
            raise AssertionError("create_observation did not store evidence_type")
        relationship = db.create_relationship(
            case["id"],
            entity["id"],
            "exposes_service",
            entity["id"],
            source_module="infra_nmap",
            conn=conn,
        )
        if relationship.get("evidence_type") != "direct_observation":
            raise AssertionError("create_relationship did not store evidence defaults")
        finding = db.create_finding(
            case["id"],
            "infra_cert_subdomain",
            "Evidence smoke finding",
            "info",
            55,
            "Smoke test finding with evidence defaults.",
            entity_id=entity["id"],
            conn=conn,
        )
        if not finding.get("source_name"):
            raise AssertionError("create_finding did not store source_name")
    finally:
        conn.close()

    registry = __import__("modules.module_registry", fromlist=["MODULES", "get_module"])
    if not registry.MODULES:
        raise AssertionError("module registry empty")
    if registry.get_module("infra_domain_intel") is None:
        raise AssertionError("infra_domain_intel missing from registry")

    __import__("modules.executor", fromlist=["execute_module"])
    __import__("utils.report_builder", fromlist=["build_case_report"])


def _check_evidence_locker() -> None:
    db = __import__(
        "database.db_setup",
        fromlist=[
            "calculate_content_hash",
            "calculate_content_hash_bytes",
            "create_evidence_item",
            "create_finding",
            "create_observation",
            "create_or_get_entity",
            "get_evidence_item",
            "get_db_conn",
            "get_or_create_default_case",
            "link_evidence_to_finding",
            "link_evidence_to_observation",
            "list_evidence_finding_links",
            "list_evidence_for_finding",
            "list_evidence_items",
        ],
    )
    storage = __import__(
        "utils.evidence_storage",
        fromlist=["should_spill_content", "should_spill_bytes", "EVIDENCE_INLINE_MAX_BYTES"],
    )
    capture = __import__(
        "utils.evidence_capture",
        fromlist=[
            "capture_module_evidence",
            "capture_nmap_evidence",
            "capture_result_evidence_hints",
        ],
    )
    backup = __import__(
        "utils.case_backup",
        fromlist=["export_case_bundle"],
    )

    sample_hash = db.calculate_content_hash("evidence locker smoke")
    if not sample_hash or len(sample_hash) != 64:
        raise AssertionError("calculate_content_hash should return SHA-256 hex digest")
    if db.calculate_content_hash("") is not None:
        raise AssertionError("empty content should not produce a hash")
    if db.calculate_content_hash("api_key=super_secret_value_12345") is not None:
        raise AssertionError("secret-like content should not be hashed")

    case = db.get_or_create_default_case()
    conn = db.get_db_conn()
    try:
        columns = {row[1] for row in conn.execute("PRAGMA table_info(evidence_items)").fetchall()}
        required = {
            "id",
            "case_id",
            "entity_id",
            "observation_id",
            "finding_id",
            "module_id",
            "content_text",
            "content_hash",
            "captured_at",
        }
        if not required.issubset(columns):
            raise AssertionError(f"evidence_items missing columns: {required - columns}")
        link_columns = {
            row[1] for row in conn.execute("PRAGMA table_info(evidence_finding_links)").fetchall()
        }
        if "evidence_id" not in link_columns or "finding_id" not in link_columns:
            raise AssertionError("evidence_finding_links table missing")

        if not storage.should_spill_content("x" * (storage.EVIDENCE_INLINE_MAX_BYTES + 1)):
            raise AssertionError("should_spill_content threshold failed")

        entity = db.create_or_get_entity(
            case["id"],
            "domain",
            "locker-smoke.example",
            source="smoke_check",
            conn=conn,
        )
        observation = db.create_observation(
            case["id"],
            entity["id"],
            "infra_nmap",
            "network_scan",
            "Locker smoke observation",
            summary="Smoke test",
            conn=conn,
        )
        item = db.create_evidence_item(
            case["id"],
            "infra_nmap",
            "Smoke evidence item",
            summary="Raw output capture",
            content_text="Starting Nmap 7.94 ( https://nmap.org )",
            entity_id=entity["id"],
            observation_id=observation["id"],
            source_name="local_nmap",
            conn=conn,
        )
        if not item.get("content_hash"):
            raise AssertionError("create_evidence_item did not store content_hash")
        fetched = db.get_evidence_item(item["id"], conn=conn)
        if fetched is None:
            raise AssertionError("get_evidence_item returned None")
        linked = db.link_evidence_to_observation(item["id"], observation["id"], conn=conn)
        if linked is None or linked.get("observation_id") != observation["id"]:
            raise AssertionError("link_evidence_to_observation failed")

        nmap_items = capture.capture_nmap_evidence(
            conn,
            case_id=case["id"],
            entity_id=entity["id"],
            observation_id=observation["id"],
            module_id="infra_nmap",
            result={
                "raw_output": "PORT STATE SERVICE\n22/tcp open ssh",
                "parsed_data": {
                    "xml_output": "<nmaprun></nmaprun>",
                    "parsed_ports": [{"port": "22", "protocol": "tcp", "state": "open"}],
                },
            },
        )
        if len(nmap_items) < 2:
            raise AssertionError("capture_nmap_evidence should create multiple items")

        listed = db.list_evidence_items(case_id=case["id"], observation_id=observation["id"], conn=conn)
        if len(listed) < 2:
            raise AssertionError("list_evidence_items observation filter failed")

        finding = db.create_finding(
            case["id"],
            "infra_nmap",
            "Locker link smoke finding",
            "info",
            50,
            "Evidence link smoke test.",
            entity_id=entity["id"],
            observation_id=observation["id"],
            conn=conn,
        )
        db.link_evidence_to_finding(item["id"], finding["id"], conn=conn)
        links = db.list_evidence_finding_links(finding_id=finding["id"], conn=conn)
        if not links:
            raise AssertionError("evidence_finding_links not created")
        resolved = db.list_evidence_for_finding(finding, conn=conn)
        if not resolved:
            raise AssertionError("list_evidence_for_finding returned no items")

        large_item = db.create_evidence_item(
            case["id"],
            "infra_nmap",
            "Large spill smoke item",
            content_text="A" * (storage.EVIDENCE_INLINE_MAX_BYTES + 100),
            entity_id=entity["id"],
            conn=conn,
        )
        if not large_item.get("storage_path"):
            raise AssertionError("large evidence item should spill to storage_path")

        binary_hash = db.calculate_content_hash_bytes(b"binary evidence smoke")
        if not binary_hash or len(binary_hash) != 64:
            raise AssertionError("calculate_content_hash_bytes should return SHA-256 hex digest")

        if not storage.should_spill_bytes(b"x" * (storage.EVIDENCE_INLINE_MAX_BYTES + 1)):
            raise AssertionError("should_spill_bytes threshold failed")

        binary_item = db.create_evidence_item(
            case["id"],
            "infra_nmap",
            "Binary smoke item",
            content_bytes=b"binary-smoke-payload",
            content_text="Binary preview note",
            content_type="application/octet-stream",
            entity_id=entity["id"],
            conn=conn,
        )
        if not binary_item.get("content_hash"):
            raise AssertionError("binary evidence item should store content_hash")

        hint_items = capture.capture_result_evidence_hints(
            conn,
            case_id=case["id"],
            entity_id=entity["id"],
            observation_id=observation["id"],
            module_id="infra_nmap",
            result={
                "evidence": [
                    {
                        "title": "SDK evidence hint",
                        "summary": "Smoke test hint capture",
                        "content_text": "hint body",
                        "source_name": "smoke_check",
                    }
                ]
            },
        )
        if len(hint_items) != 1:
            raise AssertionError("capture_result_evidence_hints should create one item")
    finally:
        conn.close()

    bundle = backup.export_case_bundle(case["id"])
    if "evidence_items" not in bundle:
        raise AssertionError("case backup export missing evidence_items")
    if "evidence_finding_links" not in bundle:
        raise AssertionError("case backup export missing evidence_finding_links")

    __import__("utils.report_builder", fromlist=["build_case_report"])
    __import__("modules.executor", fromlist=["execute_module"])
    __import__("ui.evidence_page", fromlist=["render_evidence_page"])


def _check_result_quality() -> None:
    result_status = __import__(
        "utils.result_status",
        fromlist=[
            "STATUS_COMPLETED_WITH_WARNINGS",
            "resolve_collection_status",
            "should_persist_observation",
        ],
    )
    display = __import__(
        "utils.display_format",
        fromlist=["format_wayback_timestamp", "display_or_unavailable"],
    )
    cert_interp = __import__(
        "utils.cert_subdomain_interpreter",
        fromlist=["interpret_cert_subdomain_results"],
    )
    domain_interp = __import__(
        "utils.domain_intel_interpreter",
        fromlist=["interpret_domain_intel_results"],
    )
    website_interp = __import__(
        "utils.website_metadata_interpreter",
        fromlist=["interpret_website_metadata_results"],
    )
    finding_interp = __import__(
        "utils.finding_interpreter",
        fromlist=["is_source_notice", "risk_findings"],
    )
    summary_mod = __import__(
        "utils.result_summary",
        fromlist=["summarize_run_results"],
    )

    timeout_findings = cert_interp.interpret_cert_subdomain_results(
        {
            "domain": "example.com",
            "subdomains": [],
            "warning": "Certificate transparency lookup timed out. crt.sh may be slow or unavailable.",
            "source": "crt.sh",
        }
    )
    if not timeout_findings or timeout_findings[0]["severity"] != "info":
        raise AssertionError("crt.sh timeout should be info severity")
    if not finding_interp.is_source_notice(timeout_findings[0]):
        raise AssertionError("crt.sh timeout should be a source notice")
    if "no related names" not in timeout_findings[0]["explanation"].lower():
        raise AssertionError("timeout wording should not imply no subdomains exist")

    empty_mx = domain_interp.interpret_domain_intel_results(
        {
            "domain": "example.com",
            "dns": {"MX": [], "A": ["93.184.216.34"]},
            "http": {"https": {"reachable": True}},
            "security_headers": {"https": {}},
            "tls": {},
            "wayback": {},
        }
    )
    if any(finding.get("title") == "MX records found" for finding in empty_mx):
        raise AssertionError("empty MX should not create MX-found finding")

    empty_subdomains = cert_interp.interpret_cert_subdomain_results(
        {"domain": "example.com", "subdomains": [], "source": "crt.sh"}
    )
    if any("discovered" in finding.get("title", "").lower() for finding in empty_subdomains):
        raise AssertionError("empty subdomain list should not create discovered finding")

    no_sitemap = website_interp.interpret_website_metadata_results(
        {
            "domain": "example.com",
            "homepage": {"page_title": "Example", "reachable": True},
            "robots_txt": {"available": False},
            "sitemap_hints": {"reachable_count": 0, "entries": []},
        }
    )
    if any("sitemap hints discovered" in finding.get("title", "").lower() for finding in no_sitemap):
        raise AssertionError("empty sitemap hints should not create sitemap-found finding")

    wayback_fmt = display.format_wayback_timestamp("19990101000000")
    if not wayback_fmt or "1999" not in wayback_fmt:
        raise AssertionError("wayback timestamp formatting failed")
    if display.display_or_unavailable(None) != "not available":
        raise AssertionError("display_or_unavailable failed for None")

    status = result_status.resolve_collection_status(warnings=["timeout"], has_core_data=False)
    if status not in {"partial", "completed_with_warnings"}:
        raise AssertionError("expected partial or completed_with_warnings for warning-only collection")
    if not result_status.should_persist_observation(result_status.STATUS_COMPLETED_WITH_WARNINGS):
        raise AssertionError("completed_with_warnings should persist observations")

    run_summary = summary_mod.summarize_run_results(
        [
            {
                "module_id": "infra_cert_subdomain",
                "status": result_status.STATUS_COMPLETED_WITH_WARNINGS,
                "success": True,
                "warnings": ["timed out"],
                "interpreter_findings": timeout_findings,
            }
        ]
    )
    if run_summary["total_findings"] != 0:
        raise AssertionError("source notices should not count as review findings in combined summary")


def _check_module_sdk() -> None:
    sdk = __import__(
        "utils.module_sdk",
        fromlist=[
            "STATUS_COMPLETED",
            "STATUS_ERROR",
            "build_module_result",
            "add_warning",
            "add_error",
            "add_finding",
            "is_successful_result",
            "normalise_result",
            "validate_module_result",
            "validate_module_registry",
            "validate_module_metadata",
            "validate_implemented_modules",
        ],
    )
    result = sdk.build_module_result(
        "smoke_test",
        sdk.STATUS_COMPLETED,
        "Smoke SDK result",
        success=True,
        data={"example": True},
        findings=["example finding"],
        evidence=[{"title": "Example evidence"}],
    )
    sdk.add_warning(result, "example warning")
    if not sdk.is_successful_result(result):
        raise AssertionError("build_module_result should be successful")
    normalized = sdk.normalise_result({"module_id": "legacy", "status": "completed", "parsed_data": {"a": 1}})
    if not normalized.get("data") or not normalized.get("parsed_data"):
        raise AssertionError("normalise_result should sync data and parsed_data")
    validation = sdk.validate_module_result(normalized)
    if not validation["ok"] and validation["errors"]:
        raise AssertionError(f"validate_module_result failed: {validation['errors']}")

    registry = __import__("modules.module_registry", fromlist=["MODULES", "get_module"])
    registry_check = sdk.validate_module_registry()
    if registry_check["module_count"] != len(registry.MODULES):
        raise AssertionError("validate_module_registry module_count mismatch")
    implemented_check = sdk.validate_implemented_modules()
    if not implemented_check["ok"]:
        raise AssertionError(f"implemented modules failed metadata validation: {implemented_check['errors']}")
    for module_id in (
        "infra_nmap",
        "infra_domain_intel",
        "infra_cert_subdomain",
        "infra_website_metadata",
        "infra_whois_rdap",
        "intel_virustotal",
    ):
        module = registry.get_module(module_id)
        if module is None:
            raise AssertionError(f"missing module: {module_id}")
        meta = sdk.validate_module_metadata(module)
        if not meta["ok"]:
            raise AssertionError(f"{module_id} metadata errors: {meta['errors']}")

    executor = __import__("modules.executor", fromlist=["make_result", "execute_module"])
    executor_result = executor.make_result(
        "infra_nmap",
        success=True,
        status="completed",
        summary="SDK smoke via make_result",
        parsed_data={"ports": []},
    )
    for field in ("findings", "warnings", "errors", "data", "evidence"):
        if field not in executor_result:
            raise AssertionError(f"make_result missing field: {field}")

    __import__("utils.report_builder", fromlist=["build_case_report"])
    __import__("database.db_setup", fromlist=["list_evidence_items"])
    __import__("ui.evidence_page", fromlist=["render_evidence_page"])


def _check_virustotal_module() -> None:
    import importlib.util

    registry = __import__("modules.module_registry", fromlist=["get_module"])
    module = registry.get_module("intel_virustotal")
    if module is None or not module.implemented:
        raise AssertionError("intel_virustotal should be implemented")
    if module.accepted_target_types != ("ipv4", "domain", "url"):
        raise AssertionError("intel_virustotal accepted_target_types mismatch")

    executor = __import__("modules.executor", fromlist=["is_runtime_ready"])
    if not executor.is_runtime_ready("intel_virustotal"):
        raise AssertionError("intel_virustotal runtime should be ready")

    vt_path = PROJECT_ROOT / "modules" / "4_threat_intel" / "intel_virustotal.py"
    spec = importlib.util.spec_from_file_location("intel_virustotal_smoke", vt_path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load intel_virustotal module")
    vt_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vt_mod)

    mock_payload = {
        "data": {
            "type": "domain",
            "id": "smoke.example",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 2,
                    "suspicious": 1,
                    "harmless": 50,
                    "undetected": 10,
                },
                "reputation": -3,
            },
        }
    }
    lookup = vt_mod.run_virustotal_lookup(
        "smoke.example",
        api_key="smoke-test-key",
        options={"mock_response": mock_payload},
    )
    if not lookup.get("success"):
        raise AssertionError("mock VirusTotal lookup should succeed")
    if not lookup.get("parsed_data", {}).get("last_analysis_stats"):
        raise AssertionError("mock VirusTotal lookup missing stats")
    if not lookup.get("evidence"):
        raise AssertionError("mock VirusTotal lookup should declare evidence hints")

    interpreter = __import__(
        "utils.virustotal_interpreter",
        fromlist=["interpret_virustotal_results"],
    )
    findings = interpreter.interpret_virustotal_results(lookup["parsed_data"])
    if not findings:
        raise AssertionError("virustotal interpreter should return findings")
    if findings[0].get("severity") != "high":
        raise AssertionError("malicious detections should produce high severity finding")

    findings_registry = __import__(
        "utils.findings_registry",
        fromlist=["interpret_module_findings", "module_has_findings_pipeline"],
    )
    if not findings_registry.module_has_findings_pipeline("intel_virustotal"):
        raise AssertionError("intel_virustotal should have findings pipeline")
    pipeline_findings = findings_registry.interpret_module_findings(
        "intel_virustotal",
        lookup["parsed_data"],
    )
    if not pipeline_findings:
        raise AssertionError("findings pipeline returned no virustotal findings")


def _check_module_sdk_unit_tests() -> None:
    import unittest

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName("tests.test_module_sdk")
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    if not result.wasSuccessful():
        raise AssertionError(
            f"module SDK unit tests failed: failures={len(result.failures)} errors={len(result.errors)}"
        )


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

    run(
        "settings manager",
        lambda: _check_settings_manager(),
    )

    run("database setup", lambda: __import__("database.db_setup", fromlist=["get_db_conn"]).get_db_conn().close())

    run(
        "module registry",
        lambda: len(__import__("modules.module_registry", fromlist=["MODULES"]).MODULES) > 0,
    )

    run(
        "module SDK",
        lambda: _check_module_sdk(),
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
        "entity workspace helpers",
        lambda: _check_entity_helpers(),
    )

    run(
        "batch queue helpers",
        lambda: _check_batch_queue_helpers(),
    )

    run(
        "batch queue persistence",
        lambda: _check_batch_queue_persistence(),
    )

    run(
        "pivot queue helpers",
        lambda: _check_pivot_queue_helpers(),
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
        "evidence model",
        lambda: _check_evidence_model(),
    )

    run(
        "evidence locker",
        lambda: _check_evidence_locker(),
    )

    run(
        "result quality",
        lambda: _check_result_quality(),
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
        "whois rdap module",
        lambda: _check_whois_rdap_module(),
    )

    run(
        "virustotal module",
        lambda: _check_virustotal_module(),
    )

    run(
        "module SDK unit tests",
        lambda: _check_module_sdk_unit_tests(),
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

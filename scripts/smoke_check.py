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
    expected = {"infra_domain_intel", "infra_cert_subdomain", "infra_website_metadata", "infra_email_security"}
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
    if not settings.has_api_key("VIRUSTOTAL_API_KEY"):
        vt_validation = settings.validate_module_settings("intel_virustotal")
        if vt_validation["ok"]:
            raise AssertionError("intel_virustotal should fail validation without API key")

    aipdb = registry.get_module("intel_abuseipdb")
    if aipdb is None or not aipdb.implemented:
        raise AssertionError("intel_abuseipdb should be implemented")
    if not aipdb.requires_api_key:
        raise AssertionError("intel_abuseipdb should require API key")
    if aipdb.api_key_names != ("ABUSEIPDB_API_KEY",):
        raise AssertionError("intel_abuseipdb api_key_names mismatch")
    if aipdb.accepted_target_types != ("ipv4",):
        raise AssertionError("intel_abuseipdb accepted_target_types mismatch")
    if not settings.has_api_key("ABUSEIPDB_API_KEY"):
        aipdb_validation = settings.validate_module_settings("intel_abuseipdb")
        if aipdb_validation["ok"]:
            raise AssertionError("intel_abuseipdb should fail validation without API key")

    gn = registry.get_module("intel_greynoise")
    if gn is None or not gn.implemented:
        raise AssertionError("intel_greynoise should be implemented")
    if gn.requires_api_key:
        raise AssertionError("intel_greynoise should not require API key")
    if gn.api_key_names != ("GREYNOISE_API_KEY",):
        raise AssertionError("intel_greynoise api_key_names mismatch")
    if gn.accepted_target_types != ("ipv4",):
        raise AssertionError("intel_greynoise accepted_target_types mismatch")
    gn_validation = settings.validate_module_settings("intel_greynoise")
    if not gn_validation["ok"]:
        raise AssertionError("intel_greynoise should pass validation without API key")

    shodan = registry.get_module("intel_shodan")
    if shodan is None or not shodan.implemented:
        raise AssertionError("intel_shodan should be implemented")
    if not shodan.requires_api_key:
        raise AssertionError("intel_shodan should require API key")
    if shodan.api_key_names != ("SHODAN_API_KEY",):
        raise AssertionError("intel_shodan api_key_names mismatch")
    if shodan.accepted_target_types != ("ipv4",):
        raise AssertionError("intel_shodan accepted_target_types mismatch")
    if not settings.has_api_key("SHODAN_API_KEY"):
        shodan_validation = settings.validate_module_settings("intel_shodan")
        if shodan_validation["ok"]:
            raise AssertionError("intel_shodan should fail validation without API key")

    urlhaus = registry.get_module("intel_urlhaus")
    if urlhaus is None or not urlhaus.implemented:
        raise AssertionError("intel_urlhaus should be implemented")
    if not urlhaus.requires_api_key:
        raise AssertionError("intel_urlhaus should require API key")
    if urlhaus.api_key_names != ("ABUSECH_AUTH_KEY", "URLHAUS_AUTH_KEY"):
        raise AssertionError("intel_urlhaus api_key_names mismatch")
    if urlhaus.accepted_target_types != ("url", "domain", "ipv4"):
        raise AssertionError("intel_urlhaus accepted_target_types mismatch")
    if not settings.get_urlhaus_auth_key():
        urlhaus_validation = settings.validate_module_settings("intel_urlhaus")
        if urlhaus_validation["ok"]:
            raise AssertionError("intel_urlhaus should fail validation without API key")

    st = registry.get_module("intel_securitytrails")
    if st is None or st.implemented:
        raise AssertionError("intel_securitytrails should remain planned/not implemented")
    if registry.is_executable(st):
        raise AssertionError("intel_securitytrails must not be executable")

    providers = settings.list_api_provider_status()
    if len(providers) < 9:
        raise AssertionError("expected at least 9 API provider definitions")
    modules = settings.list_module_config_status()
    if not any(row["module_id"] == "infra_nmap" for row in modules):
        raise AssertionError("list_module_config_status missing infra_nmap")

    if settings.rate_limit_seconds() <= 0:
        raise AssertionError("rate_limit_seconds should be positive")


def _check_security_baseline() -> None:
    security = __import__(
        "utils.security",
        fromlist=[
            "mask_secret",
            "redact_secrets_from_text",
            "redact_secrets_from_dict",
            "looks_like_secret",
            "is_safe_target_string",
        ],
    )
    masked = security.mask_secret("ghp_abcdefghijklmnopqrstuvwxyz123456")
    if "abcdefghijklmnopqrst" in masked:
        raise AssertionError("mask_secret exposed too much of the value")
    if masked.count("*") < 4:
        raise AssertionError("mask_secret did not mask sufficiently")

    redacted = security.redact_secrets_from_text("api_key=supersecretvalue1234567890")
    if "supersecretvalue" in redacted:
        raise AssertionError("redact_secrets_from_text did not redact assignment")

    payload = security.redact_secrets_from_dict({"token": "ghp_abcdefghijklmnopqrstuvwxyz123456"})
    if "ghp_" in str(payload.get("token", "")):
        raise AssertionError("redact_secrets_from_dict did not redact token value")

    if not security.is_safe_target_string("example.com"):
        raise AssertionError("is_safe_target_string rejected a normal domain")
    if security.is_safe_target_string("example.com; rm -rf /"):
        raise AssertionError("is_safe_target_string accepted shell metacharacters")

    settings = __import__(
        "utils.settings_manager",
        fromlist=["env_example_exists", "env_ignored_by_git", "list_api_provider_status"],
    )
    if not settings.env_example_exists():
        raise AssertionError(".env.example is missing")
    if not settings.env_ignored_by_git():
        raise AssertionError(".env is not ignored by Git")

    for provider in settings.list_api_provider_status():
        for item in provider["key_status"]:
            masked_value = item["masked"]
            if item["configured"] and masked_value != "not configured" and masked_value.count("*") < 4:
                raise AssertionError(f"provider {provider['provider_id']} may expose full secret")

    registry = __import__(
        "modules.module_registry",
        fromlist=["QUARANTINED_MODULE_IDS", "get_module", "is_executable"],
    )
    for module_id in registry.QUARANTINED_MODULE_IDS:
        module = registry.get_module(module_id)
        if module is None:
            raise AssertionError(f"missing quarantined module: {module_id}")
        if registry.is_executable(module):
            raise AssertionError(f"quarantined module must not be executable: {module_id}")

    crypto = __import__("utils.crypto_utils", fromlist=["calculate_sha256"])
    digest = crypto.calculate_sha256("smoke-check")
    if not digest or len(digest) != 64:
        raise AssertionError("calculate_sha256 returned unexpected digest")


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
        or "infra_tls_review" not in module_ids
        or "infra_http_security" not in module_ids
        or "infra_web_stack_identifier" not in module_ids
        or "infra_domain_intel" not in module_ids
        or "infra_cert_subdomain" not in module_ids
        or "infra_website_metadata" not in module_ids
        or "infra_email_security" not in module_ids
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
        "infra_email_security",
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


def _check_email_security_module() -> None:
    import importlib.util

    registry = __import__("modules.module_registry", fromlist=["get_module"])
    module = registry.get_module("infra_email_security")
    if module is None or not module.implemented:
        raise AssertionError("infra_email_security registry entry missing or not implemented")
    if module.requires_api_key:
        raise AssertionError("infra_email_security should not require API key")
    if module.accepted_target_types != ("domain", "url"):
        raise AssertionError("infra_email_security accepted_target_types mismatch")
    for field in ("short_help", "detailed_help", "caution_notes", "config_notes"):
        if not getattr(module, field, None):
            raise AssertionError(f"infra_email_security missing registry metadata: {field}")

    module_path = Path(PROJECT_ROOT) / "modules" / "2_infrastructure" / "infra_email_security.py"
    spec = importlib.util.spec_from_file_location("infra_email_security", module_path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load infra_email_security module spec")
    email_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(email_mod)

    spf = email_mod.parse_spf_record("v=spf1 include:spf.example.com -all")
    if not spf.get("present") or spf.get("policy") != "-all":
        raise AssertionError("SPF parser failed")
    dmarc = email_mod.parse_dmarc_record("v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=50")
    if dmarc.get("policy") != "reject" or not dmarc.get("rua_present") or dmarc.get("pct") != 50:
        raise AssertionError("DMARC parser failed")
    mta_policy = email_mod.parse_mta_sts_policy_file("version: STSv1\nmode: enforce\nmx: mail.example.com\nmax_age: 86400\n")
    if mta_policy.get("mode") != "enforce" or mta_policy.get("mx") != ["mail.example.com"]:
        raise AssertionError("MTA-STS policy parser failed")

    mock_data = {
        "domain": "example.com",
        "target": "example.com",
        "spf": spf,
        "dmarc": dmarc,
        "mx": [{"priority": 10, "hostname": "mail.example.com"}],
        "caa": [{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}],
        "mta_sts": {"txt_present": True, "policy_reachable": False, "mode": None, "max_age": None, "mx": []},
        "tls_rpt": email_mod.parse_tls_rpt_record("v=TLSRPTv1; rua=mailto:tls@example.com"),
        "bimi": email_mod.parse_bimi_record(None),
    }
    result = email_mod.run_email_security_review(
        "example.com",
        options={"mock_data": mock_data, "skip_mta_sts_policy_fetch": True},
    )
    if not result.get("success") or result.get("module_id") != "infra_email_security":
        raise AssertionError("mock email security review should succeed")

    blocked = email_mod.run_email_security_review("not a valid domain !!!")
    if blocked.get("success"):
        raise AssertionError("invalid domain should fail email security review")

    interpreter = __import__(
        "utils.email_security_interpreter",
        fromlist=["interpret_email_security_results"],
    )
    findings = interpreter.interpret_email_security_results(mock_data)
    if not findings:
        raise AssertionError("email security interpreter should return findings")

    registry_pipeline = __import__(
        "utils.findings_registry",
        fromlist=["module_has_findings_pipeline", "interpret_module_findings"],
    )
    if not registry_pipeline.module_has_findings_pipeline("infra_email_security"):
        raise AssertionError("findings pipeline not registered for infra_email_security")
    pipeline_findings = registry_pipeline.interpret_module_findings("infra_email_security", mock_data)
    if not pipeline_findings:
        raise AssertionError("findings pipeline returned no email security findings")

    executor = __import__("modules.executor", fromlist=["is_runtime_ready"])
    if not executor.is_runtime_ready("infra_email_security"):
        raise AssertionError("executor cannot load infra_email_security backend")

    source = module_path.read_text(encoding="utf-8")
    if "smtplib" in source:
        raise AssertionError("infra_email_security must not import smtplib")


def _check_tls_review_module() -> None:
    import importlib.util

    registry = __import__("modules.module_registry", fromlist=["get_module"])
    module = registry.get_module("infra_tls_review")
    if module is None or not module.implemented:
        raise AssertionError("infra_tls_review registry entry missing or not implemented")
    if not module.requires_authorisation:
        raise AssertionError("infra_tls_review must require authorisation")
    if module.requires_api_key:
        raise AssertionError("infra_tls_review should not require API key")
    if module.accepted_target_types != ("domain", "url", "ipv4"):
        raise AssertionError("infra_tls_review accepted_target_types mismatch")
    for field in ("short_help", "detailed_help", "caution_notes", "config_notes"):
        if not getattr(module, field, None):
            raise AssertionError(f"infra_tls_review missing registry metadata: {field}")

    module_path = Path(PROJECT_ROOT) / "modules" / "2_infrastructure" / "infra_tls_review.py"
    spec = importlib.util.spec_from_file_location("infra_tls_review", module_path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load infra_tls_review module spec")
    tls_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tls_mod)

    parsed = tls_mod.parse_tls_target("https://example.com:8443/path")
    if parsed.get("host") != "example.com" or parsed.get("port") != 8443:
        raise AssertionError("TLS target URL parser failed")
    ipv4_parsed = tls_mod.parse_tls_target("8.8.8.8")
    if ipv4_parsed.get("host") != "8.8.8.8" or ipv4_parsed.get("port") != 443:
        raise AssertionError("TLS target IPv4 parser failed")

    mock_data = {
        "target": "example.com",
        "host": "example.com",
        "port": 443,
        "sni": "example.com",
        "target_type": "domain",
        "connection": {"success": True, "error": None},
        "tls": {
            "version": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "protocol_probe": {
                "TLS 1.3": {"label": "TLS 1.3", "tested": True, "accepted": True},
            },
        },
        "certificate": {
            "subject": "example.com",
            "issuer": "Example CA",
            "not_before": "2025-01-01T00:00:00+00:00",
            "not_after": "2026-01-01T00:00:00+00:00",
            "days_until_expiry": 120,
            "san_dns_names": ["example.com", "www.example.com"],
            "hostname_valid": True,
            "chain_valid": True,
            "fingerprint_sha256": "abc123",
        },
    }
    result = tls_mod.run_tls_review("example.com", options={"mock_data": mock_data})
    if not result.get("success") or result.get("module_id") != "infra_tls_review":
        raise AssertionError("mock TLS review should succeed")
    for field in ("findings", "warnings", "errors", "data"):
        if field not in result:
            raise AssertionError(f"TLS review result missing field: {field}")

    blocked_target = tls_mod.run_tls_review("not a valid domain !!!")
    if blocked_target.get("success"):
        raise AssertionError("invalid TLS target should be blocked")

    interpreter = __import__(
        "utils.tls_review_interpreter",
        fromlist=["interpret_tls_review_results"],
    )
    findings = interpreter.interpret_tls_review_results(mock_data)
    if not findings:
        raise AssertionError("TLS review interpreter should return findings")

    registry_pipeline = __import__(
        "utils.findings_registry",
        fromlist=["module_has_findings_pipeline", "interpret_module_findings"],
    )
    if not registry_pipeline.module_has_findings_pipeline("infra_tls_review"):
        raise AssertionError("findings pipeline not registered for infra_tls_review")

    executor = __import__("modules.executor", fromlist=["is_runtime_ready", "execute_module"])
    if not executor.is_runtime_ready("infra_tls_review"):
        raise AssertionError("executor cannot load infra_tls_review backend")

    guardrail_blocked = executor.execute_module(
        "infra_tls_review",
        "example.com",
        authorisation_confirmed=False,
        options={"mock_data": mock_data},
    )
    if guardrail_blocked.get("status") != "blocked":
        raise AssertionError("TLS review should be blocked without engagement/authorisation")

    evidence = __import__(
        "utils.evidence_model",
        fromlist=["default_evidence_for_module", "default_relationship_evidence"],
    )
    defaults = evidence.default_evidence_for_module("infra_tls_review")
    if defaults.get("collection_method") != "controlled_tls_review":
        raise AssertionError("TLS review evidence defaults unexpected")
    rel = evidence.default_relationship_evidence("infra_tls_review", "exposes_tls_service")
    if rel.get("reliability") != "high":
        raise AssertionError("TLS exposes_tls_service relationship evidence unexpected")

    testing_levels = __import__(
        "utils.module_testing_levels",
        fromlist=["get_module_testing_level"],
    )
    if testing_levels.get_module_testing_level("infra_tls_review") != "safe_active_check":
        raise AssertionError("infra_tls_review testing level should be safe_active_check")

    source = module_path.read_text(encoding="utf-8")
    if "subprocess" in source or "shell=True" in source:
        raise AssertionError("infra_tls_review must not use subprocess/shell=True")


def _check_http_security_module() -> None:
    import importlib.util

    registry = __import__("modules.module_registry", fromlist=["get_module"])
    module = registry.get_module("infra_http_security")
    if module is None or not module.implemented:
        raise AssertionError("infra_http_security registry entry missing or not implemented")
    if not module.requires_authorisation:
        raise AssertionError("infra_http_security must require authorisation")
    if module.requires_api_key:
        raise AssertionError("infra_http_security should not require API key")
    if module.accepted_target_types != ("domain", "url", "ipv4"):
        raise AssertionError("infra_http_security accepted_target_types mismatch")
    for field in ("short_help", "detailed_help", "caution_notes", "config_notes"):
        if not getattr(module, field, None):
            raise AssertionError(f"infra_http_security missing registry metadata: {field}")

    module_path = Path(PROJECT_ROOT) / "modules" / "2_infrastructure" / "infra_http_security.py"
    spec = importlib.util.spec_from_file_location("infra_http_security", module_path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load infra_http_security module spec")
    http_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(http_mod)

    parsed = http_mod.parse_http_target("https://example.com/login")
    if parsed.get("host") != "example.com" or parsed.get("requested_url") != "https://example.com/login":
        raise AssertionError("HTTP target URL parser failed")
    domain_parsed = http_mod.parse_http_target("example.com")
    if domain_parsed.get("requested_url") != "https://example.com/":
        raise AssertionError("HTTP target domain parser failed")

    cookie = http_mod.parse_set_cookie_header("sessionid=supersecret; Secure; HttpOnly; SameSite=Lax")
    if "supersecret" in str(cookie.values()):
        raise AssertionError("cookie parser must not store cookie values")
    if cookie.get("name") != "sessionid" or not cookie.get("secure") or not cookie.get("httponly"):
        raise AssertionError("cookie flag parser failed")

    mock_data = {
        "target": "example.com",
        "host": "example.com",
        "scheme": "https",
        "port": 443,
        "requested_url": "https://example.com/",
        "target_type": "domain",
        "response": {
            "success": True,
            "status_code": 200,
            "final_url": "https://example.com/",
            "redirect_chain": [{"url": "https://example.com/", "status_code": 200}],
            "content_type": "text/html",
            "content_length": 1234,
            "error": None,
        },
        "headers": {
            "server": "nginx",
            "x_powered_by": None,
            "cache_control": "no-store",
            "raw": {"server": "nginx", "set-cookie": "[redacted]"},
        },
        "security_headers": {
            "hsts": {"present": True, "value": "max-age=31536000"},
            "csp": {"present": False, "value": None},
            "x_frame_options": {"present": True, "value": "DENY"},
            "x_content_type_options": {"present": True, "value": "nosniff"},
            "referrer_policy": {"present": False, "value": None},
            "permissions_policy": {"present": False, "value": None},
            "coop": {"present": False, "value": None},
            "coep": {"present": False, "value": None},
            "corp": {"present": False, "value": None},
            "x_xss_protection": {"present": False, "value": None},
        },
        "cookies": [
            {
                "name": "sessionid",
                "secure": False,
                "httponly": False,
                "samesite": None,
                "session_like": True,
            }
        ],
        "well_known": {
            "security_txt": {"observed": False, "status_code": 404, "url": None, "attempts": []},
            "robots_txt": {"observed": True, "status_code": 200, "url": "https://example.com/robots.txt"},
        },
    }
    result = http_mod.run_http_security_review("example.com", options={"mock_data": mock_data})
    if not result.get("success") or result.get("module_id") != "infra_http_security":
        raise AssertionError("mock HTTP security review should succeed")
    for field in ("findings", "warnings", "errors", "data"):
        if field not in result:
            raise AssertionError(f"HTTP security result missing field: {field}")
    if "supersecret" in result.get("raw_output", ""):
        raise AssertionError("raw output must not contain cookie values")

    blocked_target = http_mod.run_http_security_review("not a valid domain !!!")
    if blocked_target.get("success"):
        raise AssertionError("invalid HTTP target should be blocked")

    interpreter = __import__(
        "utils.http_security_interpreter",
        fromlist=["interpret_http_security_results"],
    )
    findings = interpreter.interpret_http_security_results(mock_data)
    if not findings:
        raise AssertionError("HTTP security interpreter should return findings")

    registry_pipeline = __import__(
        "utils.findings_registry",
        fromlist=["module_has_findings_pipeline", "interpret_module_findings"],
    )
    if not registry_pipeline.module_has_findings_pipeline("infra_http_security"):
        raise AssertionError("findings pipeline not registered for infra_http_security")

    executor = __import__("modules.executor", fromlist=["is_runtime_ready", "execute_module"])
    if not executor.is_runtime_ready("infra_http_security"):
        raise AssertionError("executor cannot load infra_http_security backend")

    guardrail_blocked = executor.execute_module(
        "infra_http_security",
        "https://example.com",
        authorisation_confirmed=False,
        options={"mock_data": mock_data},
    )
    if guardrail_blocked.get("status") != "blocked":
        raise AssertionError("HTTP security review should be blocked without engagement/authorisation")

    evidence = __import__(
        "utils.evidence_model",
        fromlist=["default_evidence_for_module", "default_relationship_evidence"],
    )
    defaults = evidence.default_evidence_for_module("infra_http_security")
    if defaults.get("collection_method") != "controlled_http_header_review":
        raise AssertionError("HTTP security evidence defaults unexpected")
    rel = evidence.default_relationship_evidence("infra_http_security", "exposes_web_service")
    if rel.get("reliability") != "high":
        raise AssertionError("HTTP exposes_web_service relationship evidence unexpected")

    testing_levels = __import__(
        "utils.module_testing_levels",
        fromlist=["get_module_testing_level"],
    )
    if testing_levels.get_module_testing_level("infra_http_security") != "safe_active_check":
        raise AssertionError("infra_http_security testing level should be safe_active_check")

    source = module_path.read_text(encoding="utf-8")
    if "subprocess" in source or "shell=True" in source:
        raise AssertionError("infra_http_security must not use subprocess/shell=True")


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
        "infra_tls_review",
        "infra_http_security",
        "infra_domain_intel",
        "infra_cert_subdomain",
        "infra_website_metadata",
        "infra_email_security",
        "infra_whois_rdap",
        "intel_virustotal",
        "intel_abuseipdb",
        "intel_greynoise",
        "intel_shodan",
        "intel_urlhaus",
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
    if module.display_name != "VirusTotal Reputation Intelligence":
        raise AssertionError("intel_virustotal display_name mismatch")
    if module.accepted_target_types != ("ipv4", "domain", "url"):
        raise AssertionError("intel_virustotal accepted_target_types mismatch")
    if module.api_key_names != ("VIRUSTOTAL_API_KEY",):
        raise AssertionError("intel_virustotal api_key_names mismatch")

    executor = __import__("modules.executor", fromlist=["is_runtime_ready"])
    if not executor.is_runtime_ready("intel_virustotal"):
        raise AssertionError("intel_virustotal runtime should be ready")

    vt_path = PROJECT_ROOT / "modules" / "4_threat_intelligence" / "intel_virustotal.py"
    spec = importlib.util.spec_from_file_location("intel_virustotal_smoke", vt_path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load intel_virustotal module")
    vt_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(vt_mod)

    missing = vt_mod.run_virustotal_lookup("example.com", api_key="")
    if missing.get("status") != "blocked":
        raise AssertionError("missing API key should return blocked status")
    if "VirusTotal API key is not configured" not in str(missing.get("errors")):
        raise AssertionError("missing API key message mismatch")

    private = vt_mod.run_virustotal_lookup("192.168.1.1", api_key="test-key", target_type="ipv4")
    if not private.get("success") or not private.get("parsed_data", {}).get("private_local_ip"):
        raise AssertionError("private IP should complete without API query")

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
                "last_analysis_results": {
                    "VendorA": {"category": "malicious", "result": "Trojan.Test"},
                    "VendorB": {"category": "harmless", "result": "clean"},
                },
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
    if not lookup.get("parsed_data", {}).get("engine_results_flagged"):
        raise AssertionError("mock VirusTotal lookup should parse flagged engines")
    if not lookup.get("evidence"):
        raise AssertionError("mock VirusTotal lookup should declare evidence hints")
    raw = lookup.get("raw_output") or ""
    if "smoke-test-key" in raw:
        raise AssertionError("raw_output must not contain API key")

    interpreter = __import__(
        "utils.virustotal_interpreter",
        fromlist=["interpret_virustotal_results"],
    )
    findings = interpreter.interpret_virustotal_results(lookup["parsed_data"])
    if not findings:
        raise AssertionError("virustotal interpreter should return findings")
    if findings[0].get("severity") not in {"low", "medium"}:
        raise AssertionError("flagged detections should produce low/medium severity finding")

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

    security = __import__("utils.security", fromlist=["redact_secrets_from_text"])
    redacted = security.redact_secrets_from_text("api_key=supersecretvalue1234567890")
    if "supersecretvalue" in redacted:
        raise AssertionError("security redaction failed in virustotal smoke path")


def _check_abuseipdb_module() -> None:
    import importlib.util

    registry = __import__("modules.module_registry", fromlist=["get_module"])
    module = registry.get_module("intel_abuseipdb")
    if module is None or not module.implemented:
        raise AssertionError("intel_abuseipdb should be implemented")
    if module.display_name != "AbuseIPDB Reputation Intelligence":
        raise AssertionError("intel_abuseipdb display_name mismatch")
    if module.accepted_target_types != ("ipv4",):
        raise AssertionError("intel_abuseipdb accepted_target_types mismatch")
    if module.api_key_names != ("ABUSEIPDB_API_KEY",):
        raise AssertionError("intel_abuseipdb api_key_names mismatch")

    executor = __import__("modules.executor", fromlist=["is_runtime_ready"])
    if not executor.is_runtime_ready("intel_abuseipdb"):
        raise AssertionError("intel_abuseipdb runtime should be ready")

    aipdb_path = PROJECT_ROOT / "modules" / "4_threat_intelligence" / "intel_abuseipdb.py"
    spec = importlib.util.spec_from_file_location("intel_abuseipdb_smoke", aipdb_path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load intel_abuseipdb module")
    aipdb_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(aipdb_mod)

    missing = aipdb_mod.run_abuseipdb_lookup("8.8.8.8", api_key="")
    if missing.get("status") != "blocked":
        raise AssertionError("missing API key should return blocked status")
    if "AbuseIPDB API key is not configured" not in str(missing.get("errors")):
        raise AssertionError("missing API key message mismatch")

    private = aipdb_mod.run_abuseipdb_lookup("192.168.1.1", api_key="smoke-test-key", target_type="ipv4")
    if not private.get("success") or not private.get("parsed_data", {}).get("private_local_ip"):
        raise AssertionError("private IP should complete without API query")

    domain_blocked = aipdb_mod.run_abuseipdb_lookup("example.com", api_key="smoke-test-key")
    if domain_blocked.get("status") != "blocked":
        raise AssertionError("domain target should be blocked for abuseipdb")

    mock_payload = {
        "data": {
            "ipAddress": "8.8.8.8",
            "abuseConfidenceScore": 42,
            "totalReports": 7,
            "numDistinctUsers": 3,
            "countryCode": "US",
            "countryName": "United States",
            "isp": "Smoke ISP",
            "usageType": "Data Center/Web Hosting/Transit",
            "isWhitelisted": False,
            "lastReportedAt": "2024-06-01T12:00:00+00:00",
        }
    }
    lookup = aipdb_mod.run_abuseipdb_lookup(
        "8.8.8.8",
        api_key="smoke-test-key",
        options={"mock_response": mock_payload},
    )
    if not lookup.get("success"):
        raise AssertionError("mock AbuseIPDB lookup should succeed")
    parsed = lookup.get("parsed_data") or {}
    if parsed.get("abuse_confidence_score") != 42:
        raise AssertionError("mock AbuseIPDB lookup missing abuse score")
    if not lookup.get("evidence"):
        raise AssertionError("mock AbuseIPDB lookup should declare evidence hints")
    raw = lookup.get("raw_output") or ""
    if "smoke-test-key" in raw:
        raise AssertionError("raw_output must not contain API key")

    interpreter = __import__(
        "utils.abuseipdb_interpreter",
        fromlist=["interpret_abuseipdb_results"],
    )
    findings = interpreter.interpret_abuseipdb_results(parsed)
    if not findings:
        raise AssertionError("abuseipdb interpreter should return findings")

    findings_registry = __import__(
        "utils.findings_registry",
        fromlist=["interpret_module_findings", "module_has_findings_pipeline"],
    )
    if not findings_registry.module_has_findings_pipeline("intel_abuseipdb"):
        raise AssertionError("intel_abuseipdb should have findings pipeline")
    pipeline_findings = findings_registry.interpret_module_findings("intel_abuseipdb", parsed)
    if not pipeline_findings:
        raise AssertionError("findings pipeline returned no abuseipdb findings")

    security = __import__("utils.security", fromlist=["redact_secrets_from_text"])
    redacted = security.redact_secrets_from_text("api_key=supersecretvalue1234567890")
    if "supersecretvalue" in redacted:
        raise AssertionError("security redaction failed in abuseipdb smoke path")


def _check_greynoise_module() -> None:
    import importlib.util

    registry = __import__("modules.module_registry", fromlist=["get_module"])
    module = registry.get_module("intel_greynoise")
    if module is None or not module.implemented:
        raise AssertionError("intel_greynoise should be implemented")
    if module.display_name != "GreyNoise Internet Noise Intelligence":
        raise AssertionError("intel_greynoise display_name mismatch")
    if module.requires_api_key:
        raise AssertionError("intel_greynoise should have optional API key")
    if module.accepted_target_types != ("ipv4",):
        raise AssertionError("intel_greynoise accepted_target_types mismatch")

    executor = __import__("modules.executor", fromlist=["is_runtime_ready"])
    if not executor.is_runtime_ready("intel_greynoise"):
        raise AssertionError("intel_greynoise runtime should be ready")

    gn_path = PROJECT_ROOT / "modules" / "4_threat_intelligence" / "intel_greynoise.py"
    spec = importlib.util.spec_from_file_location("intel_greynoise_smoke", gn_path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load intel_greynoise module")
    gn_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(gn_mod)

    no_key = gn_mod.run_greynoise_lookup("8.8.8.8", api_key=None, options={"mock_response": {
        "ip": "8.8.8.8",
        "noise": False,
        "riot": True,
        "classification": "benign",
        "name": "Google Public DNS",
        "message": "Success",
    }})
    if not no_key.get("success"):
        raise AssertionError("missing-key mock GreyNoise lookup should succeed")
    warnings_text = str(no_key.get("warnings"))
    if "GreyNoise API key is not configured" not in warnings_text:
        raise AssertionError("missing key should add community lookup warning")

    private = gn_mod.run_greynoise_lookup("192.168.1.1", api_key="smoke-test-key", target_type="ipv4")
    if not private.get("success") or not private.get("parsed_data", {}).get("private_local_ip"):
        raise AssertionError("private IP should complete without API query")

    domain_blocked = gn_mod.run_greynoise_lookup("example.com", api_key="smoke-test-key")
    if domain_blocked.get("status") != "blocked":
        raise AssertionError("domain target should be blocked for greynoise")

    mock_noise = {
        "ip": "8.8.8.8",
        "noise": True,
        "riot": False,
        "classification": "malicious",
        "name": "smoke-scanner",
        "link": "https://viz.greynoise.io/ip/8.8.8.8",
        "last_seen": "2024-06-01",
        "message": "Success",
    }
    lookup = gn_mod.run_greynoise_lookup(
        "8.8.8.8",
        api_key="smoke-test-key",
        options={"mock_response": mock_noise},
    )
    if not lookup.get("success"):
        raise AssertionError("mock GreyNoise lookup should succeed")
    parsed = lookup.get("parsed_data") or {}
    if not parsed.get("noise"):
        raise AssertionError("mock GreyNoise lookup missing noise flag")
    if not lookup.get("evidence"):
        raise AssertionError("mock GreyNoise lookup should declare evidence hints")
    raw = lookup.get("raw_output") or ""
    if "smoke-test-key" in raw:
        raise AssertionError("raw_output must not contain API key")

    interpreter = __import__(
        "utils.greynoise_interpreter",
        fromlist=["interpret_greynoise_results"],
    )
    findings = interpreter.interpret_greynoise_results(parsed)
    if not findings:
        raise AssertionError("greynoise interpreter should return findings")

    findings_registry = __import__(
        "utils.findings_registry",
        fromlist=["interpret_module_findings", "module_has_findings_pipeline"],
    )
    if not findings_registry.module_has_findings_pipeline("intel_greynoise"):
        raise AssertionError("intel_greynoise should have findings pipeline")
    pipeline_findings = findings_registry.interpret_module_findings("intel_greynoise", parsed)
    if not pipeline_findings:
        raise AssertionError("findings pipeline returned no greynoise findings")


def _check_shodan_module() -> None:
    import importlib.util
    import json

    registry = __import__("modules.module_registry", fromlist=["get_module"])
    module = registry.get_module("intel_shodan")
    if module is None or not module.implemented:
        raise AssertionError("intel_shodan should be implemented")
    if module.display_name != "Shodan Internet Exposure Intelligence":
        raise AssertionError("intel_shodan display_name mismatch")
    if module.accepted_target_types != ("ipv4",):
        raise AssertionError("intel_shodan accepted_target_types mismatch")
    if module.api_key_names != ("SHODAN_API_KEY",):
        raise AssertionError("intel_shodan api_key_names mismatch")

    executor = __import__("modules.executor", fromlist=["is_runtime_ready"])
    if not executor.is_runtime_ready("intel_shodan"):
        raise AssertionError("intel_shodan runtime should be ready")

    shodan_path = PROJECT_ROOT / "modules" / "4_threat_intelligence" / "intel_shodan.py"
    spec = importlib.util.spec_from_file_location("intel_shodan_smoke", shodan_path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load intel_shodan module")
    shodan_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(shodan_mod)

    missing = shodan_mod.run_shodan_lookup("8.8.8.8", api_key="")
    if missing.get("status") != "blocked":
        raise AssertionError("missing API key should return blocked status")
    if "Shodan API key is not configured" not in str(missing.get("errors")):
        raise AssertionError("missing API key message mismatch")

    private = shodan_mod.run_shodan_lookup("192.168.1.1", api_key="smoke-test-key", target_type="ipv4")
    if not private.get("success") or not private.get("parsed_data", {}).get("private_local_ip"):
        raise AssertionError("private IP should complete without API query")

    domain_blocked = shodan_mod.run_shodan_lookup("example.com", api_key="smoke-test-key")
    if domain_blocked.get("status") != "blocked":
        raise AssertionError("domain target should be blocked for shodan")

    mock_payload = {
        "ip_str": "8.8.8.8",
        "org": "Google",
        "isp": "Google LLC",
        "asn": "AS15169",
        "country_name": "United States",
        "city": "Mountain View",
        "hostnames": ["dns.google"],
        "domains": ["dns.google"],
        "ports": [53, 443],
        "tags": ["dns"],
        "last_update": "2024-06-01T00:00:00",
        "vulns": ["CVE-EXAMPLE-1"],
        "data": [
            {
                "port": 53,
                "transport": "udp",
                "product": "Unbound",
                "timestamp": "2024-06-01T00:00:00",
                "_shodan": {"module": "dns-udp"},
            },
            {
                "port": 443,
                "transport": "tcp",
                "product": "nginx",
                "ssl": {"cert": {}},
                "http": {"title": "Google Public DNS"},
                "_shodan": {"module": "https"},
            },
        ],
    }
    lookup = shodan_mod.run_shodan_lookup(
        "8.8.8.8",
        api_key="smoke-test-key",
        options={"mock_response": mock_payload},
    )
    if not lookup.get("success"):
        raise AssertionError("mock Shodan lookup should succeed")
    parsed = lookup.get("parsed_data") or {}
    if parsed.get("service_count", 0) < 1:
        raise AssertionError("mock Shodan lookup missing service count")
    if not lookup.get("evidence"):
        raise AssertionError("mock Shodan lookup should declare evidence hints")
    raw = lookup.get("raw_output") or ""
    if "smoke-test-key" in raw:
        raise AssertionError("raw_output must not contain API key")
    if "CVE-EXAMPLE-1" in json.dumps(parsed):
        raise AssertionError("parsed_data should not persist vulnerability identifiers")

    interpreter = __import__(
        "utils.shodan_interpreter",
        fromlist=["interpret_shodan_results"],
    )
    findings = interpreter.interpret_shodan_results(parsed)
    if not findings:
        raise AssertionError("shodan interpreter should return findings")

    findings_registry = __import__(
        "utils.findings_registry",
        fromlist=["interpret_module_findings", "module_has_findings_pipeline"],
    )
    if not findings_registry.module_has_findings_pipeline("intel_shodan"):
        raise AssertionError("intel_shodan should have findings pipeline")
    pipeline_findings = findings_registry.interpret_module_findings("intel_shodan", parsed)
    if not pipeline_findings:
        raise AssertionError("findings pipeline returned no shodan findings")

    security = __import__("utils.security", fromlist=["redact_secrets_from_text"])
    probe_url = "".join(
        (
            "https://api.shodan.io/shodan/host/8.8.8.8?",
            "key=",
            "supersecretshodankey123",
        )
    )
    redacted = security.redact_secrets_from_text(probe_url)
    if "supersecretshodankey123" in redacted:
        raise AssertionError("shodan URL key redaction failed in smoke path")


def _check_pcap_module() -> None:
    import importlib.util
    from pathlib import Path

    registry = __import__(
        "modules.module_registry",
        fromlist=["get_module", "is_executable"],
    )
    module = registry.get_module("net_pcap_review")
    if module is None or not registry.is_executable(module):
        raise AssertionError("net_pcap_review should be registered and executable")

    module_path = Path(__file__).resolve().parent.parent / "modules" / "5_network_analysis" / "net_pcap_review.py"
    spec = importlib.util.spec_from_file_location("net_pcap_review_smoke", module_path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load net_pcap_review module")
    pcap_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(pcap_mod)

    blocked = pcap_mod.run_pcap_review(
        "notes.txt",
        options={"pcap_filename": "notes.txt"},
    )
    if blocked.get("status") != "blocked":
        raise AssertionError("unsupported file type should return blocked status")
    if blocked.get("success"):
        raise AssertionError("unsupported file type should not succeed")

    mock_parsed = {
        "filename": "lab.pcap",
        "parser_available": True,
        "packets_analysed": 2400,
        "packet_count": 2400,
        "duration_seconds": 240,
        "protocols": [{"protocol": "dns", "count": 10}, {"protocol": "tls", "count": 50}],
        "dns_queries": [{"query": "example.com"}],
        "http_entries": [{"host": "example.com", "method": "GET", "status_code": "200"}],
        "tls_sni": [{"server_name": "example.com", "version": ""}],
        "cleartext_protocols": ["http"],
        "entities_preview": {"ips": ["10.0.0.1"], "domains": ["example.com"], "services": []},
    }
    mock_result = pcap_mod.run_pcap_review(
        "lab.pcap",
        options={"mock_parsed_data": mock_parsed},
    )
    if not mock_result.get("success"):
        raise AssertionError("mock PCAP review should succeed")
    if "PCAP analysed" not in (mock_result.get("summary") or ""):
        raise AssertionError("mock PCAP summary missing analysed wording")

    interpreter = __import__(
        "utils.pcap_interpreter",
        fromlist=["interpret_pcap_results"],
    )
    findings = interpreter.interpret_pcap_results(mock_parsed)
    if not findings:
        raise AssertionError("pcap interpreter should return findings")

    findings_registry = __import__(
        "utils.findings_registry",
        fromlist=["interpret_module_findings", "module_has_findings_pipeline"],
    )
    if not findings_registry.module_has_findings_pipeline("net_pcap_review"):
        raise AssertionError("net_pcap_review should have findings pipeline")
    pipeline_findings = findings_registry.interpret_module_findings("net_pcap_review", mock_parsed)
    if not pipeline_findings:
        raise AssertionError("findings pipeline returned no pcap findings")

    executor = __import__(
        "modules.executor",
        fromlist=["is_runtime_ready", "execute_module"],
    )
    if not executor.is_runtime_ready("net_pcap_review"):
        raise AssertionError("net_pcap_review runtime should be ready")

    partial = pcap_mod.run_pcap_review(
        "lab.pcap",
        options={
            "pcap_filename": "lab.pcap",
            "mock_parsed_data": {
                "filename": "lab.pcap",
                "parser_available": False,
                "sha256": "abc",
                "file_size_bytes": 12,
            },
            "mock_status": "partial",
        },
    )
    if partial.get("success") is not True:
        raise AssertionError("parser-missing mock should still return success partial metadata")
    summary_lower = (partial.get("summary") or "").lower()
    if "tshark" not in summary_lower and "pyshark" not in summary_lower:
        raise AssertionError("parser-missing summary should mention tshark or pyshark")

    pcap_analysis = __import__(
        "utils.pcap_analysis",
        fromlist=["analyze_pcap_file", "parser_available"],
    )
    if pcap_analysis.parser_available():
        import tempfile

        empty_pcap = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        empty_pcap.write(b"")
        empty_pcap.close()
        try:
            fallback = pcap_analysis.analyze_pcap_file(
                Path(empty_pcap.name),
                filename="empty.pcap",
                file_hash="0" * 64,
                file_size=0,
            )
            if fallback.get("status") not in {"partial", "error", "completed", "completed_with_warnings"}:
                raise AssertionError("analyze_pcap_file should return a structured status")
        finally:
            Path(empty_pcap.name).unlink(missing_ok=True)


def _check_live_capture_module() -> None:
    import importlib.util
    from pathlib import Path

    registry = __import__(
        "modules.module_registry",
        fromlist=["get_module", "is_executable"],
    )
    module = registry.get_module("net_live_capture")
    if module is None or not registry.is_executable(module):
        raise AssertionError("net_live_capture should be registered and executable")
    if module.mode != "local-capture":
        raise AssertionError("net_live_capture mode should be local-capture")

    live_capture_utils = __import__(
        "utils.live_capture",
        fromlist=[
            "build_tshark_command",
            "capture_backend_status",
            "validate_duration",
            "validate_packet_cap",
            "build_bpf_filter",
        ],
    )
    status = live_capture_utils.capture_backend_status()
    if not isinstance(status.get("tshark_available"), bool):
        raise AssertionError("capture_backend_status missing tshark flag")

    duration, duration_err = live_capture_utils.validate_duration(30)
    if duration != 30 or duration_err:
        raise AssertionError("validate_duration(30) should pass")
    capped_duration, _ = live_capture_utils.validate_duration(999)
    if capped_duration != 120:
        raise AssertionError("validate_duration should cap at 120")

    packet_cap, cap_err = live_capture_utils.validate_packet_cap(1000)
    if packet_cap != 1000 or cap_err:
        raise AssertionError("validate_packet_cap(1000) should pass")
    capped_cap, _ = live_capture_utils.validate_packet_cap(99999)
    if capped_cap != 10000:
        raise AssertionError("validate_packet_cap should cap at 10000")

    bpf, bpf_err = live_capture_utils.build_bpf_filter("web_traffic")
    if bpf_err or "tcp port 80" not in bpf:
        raise AssertionError("web_traffic bpf preset failed")
    _, host_err = live_capture_utils.build_bpf_filter("target_host", target_host="")
    if not host_err:
        raise AssertionError("target_host without value should error")

    cmd = live_capture_utils.build_tshark_command(
        interface_id="en0",
        output_path=Path("/tmp/smoke_capture.pcap"),
        duration_seconds=30,
        packet_cap=1000,
        bpf_filter="port 53",
    )
    if "shell" in " ".join(cmd):
        pass
    if cmd[0] != "tshark" or "-i" not in cmd:
        raise AssertionError("tshark command malformed")

    module_path = PROJECT_ROOT / "modules" / "5_network_analysis" / "net_live_capture.py"
    spec = importlib.util.spec_from_file_location("net_live_capture_smoke", module_path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load net_live_capture module")
    live_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(live_mod)

    blocked = live_mod.run_live_capture(
        "live-capture:en0",
        options={"personal_lab_confirmed": False},
    )
    if blocked.get("success"):
        raise AssertionError("live capture without confirmation should not succeed")

    dry = live_mod.run_live_capture(
        "live-capture:en0",
        options={
            "personal_lab_confirmed": True,
            "dry_run": True,
            "interface_id": "en0",
            "interfaces": [{"id": "en0", "label": "en0"}],
        },
    )
    if not dry.get("success") or not (dry.get("parsed_data") or {}).get("dry_run"):
        raise AssertionError("dry_run should succeed without real capture")
    if "&&" in (dry.get("raw_output") or ""):
        raise AssertionError("command should not use shell chaining")

    mock = {
        "capture_success": True,
        "analysis_success": True,
        "capture": {
            "backend": "tshark",
            "interface": "en0",
            "duration_seconds": 30,
            "packet_cap": 100,
            "filename": "lab.pcap",
            "sha256": "abc",
        },
        "pcap_review": {
            "parsed_data": {"packets_analysed": 100, "parser_available": True, "protocols": []},
        },
    }
    mock_result = live_mod.run_live_capture(
        "live-capture:en0",
        options={"mock_capture_result": mock},
    )
    if not mock_result.get("success"):
        raise AssertionError("mock live capture should succeed")

    findings_registry = __import__(
        "utils.findings_registry",
        fromlist=["interpret_module_findings", "module_has_findings_pipeline"],
    )
    if not findings_registry.module_has_findings_pipeline("net_live_capture"):
        raise AssertionError("net_live_capture should have findings pipeline")

    executor = __import__("modules.executor", fromlist=["is_runtime_ready"])
    if not executor.is_runtime_ready("net_live_capture"):
        raise AssertionError("net_live_capture runtime should be ready")

    from utils.pcap_triage import actionable_cleartext, build_triage_report, rank_investigation_entities
    from utils.pcap_fingerprint import build_capture_fingerprint, diff_fingerprints

    sample_parsed = {
        "filename": "lab.pcap",
        "packets_analysed": 500,
        "duration_seconds": 20,
        "cleartext_protocols": ["dns"],
        "protocols": [{"protocol": "tls", "count": 400}, {"protocol": "quic", "count": 80}],
        "entities_preview": {"domains": ["api.example.com"], "ips": ["192.168.1.10", "8.8.8.8"], "services": []},
        "top_source_ips": [{"ip": "192.168.1.10", "packets": 200}, {"ip": "8.8.8.8", "packets": 50}],
        "top_destination_ips": [{"ip": "192.168.1.10", "packets": 200}],
        "tls_sni": [{"server_name": "api.example.com"}],
    }
    if actionable_cleartext(["dns"]):
        raise AssertionError("dns alone should not be actionable cleartext")
    triage = build_triage_report(sample_parsed, workspace_target="192.168.1.10")
    if not triage.get("narrative"):
        raise AssertionError("triage should produce narrative")
    ranked = rank_investigation_entities(sample_parsed)
    if not ranked:
        raise AssertionError("rank_investigation_entities should return items")
    fp1 = build_capture_fingerprint(sample_parsed)
    fp2 = build_capture_fingerprint({**sample_parsed, "entities_preview": {"domains": ["new.example.com"], "ips": [], "services": []}})
    delta = diff_fingerprints(fp2, fp1)
    if "new.example.com" not in (delta.get("new_domains") or []):
        raise AssertionError("fingerprint diff should detect new domain")

    from utils.pcap_triage import bucket_ip_talkers, build_network_picture, resolve_org_bucket

    if resolve_org_bucket("142.250.129.132") != "Google":
        raise AssertionError("Google IP should bucket as Google")
    buckets = bucket_ip_talkers(sample_parsed)
    if not buckets:
        raise AssertionError("bucket_ip_talkers should return buckets")
    picture = build_network_picture(sample_parsed, ranked=ranked, encrypted_ratio=0.9)
    if "one_liner" not in picture:
        raise AssertionError("network picture should include one_liner")

    from utils.pcap_resilience import resilience_notes_for_triage

    notes = resilience_notes_for_triage(triage)
    if not notes:
        raise AssertionError("resilience notes should be returned for triage")

    from utils.pcap_synthesis import build_capture_followup_synthesis

    synthesis = build_capture_followup_synthesis(
        sample_parsed,
        [
            {
                "module_id": "intel_abuseipdb",
                "target": "8.8.8.8",
                "status": "completed",
                "summary": "clean reputation 0 malicious",
            }
        ],
    )
    if not synthesis:
        raise AssertionError("synthesis should link capture entity to follow-up module")

    from utils.pcap_next_actions import suggest_pcap_investigation_actions

    actions = suggest_pcap_investigation_actions(
        {"module_id": "net_live_capture", "success": True, "parsed_data": {"pcap_review": {"parsed_data": sample_parsed}, "capture": {}, "triage": triage}},
        case_id=1,
        workspace_target="192.168.1.10",
    )
    if not actions:
        raise AssertionError("pcap investigation actions should not be empty")

    from utils.pcap_followup_runner import (
        build_recon_progress_summary,
        runnable_modules_for_entity,
    )

    ranked_item = ranked[0] if ranked else None
    if ranked_item:
        runnable = runnable_modules_for_entity(ranked_item)
        if not runnable:
            raise AssertionError("runnable_modules_for_entity should return modules for ranked item")
    summary = build_recon_progress_summary(
        {"summary": "test capture"},
        [{"module_id": "intel_abuseipdb", "target": "8.8.8.8", "success": True, "interpreter_findings": [{}]}],
    )
    if summary.get("modules_completed") != 1:
        raise AssertionError("build_recon_progress_summary completed count mismatch")

    from utils.pcap_next_actions import suggest_post_followup_actions

    post = suggest_post_followup_actions(
        [
            {
                "success": True,
                "module_id": "infra_nmap",
                "target": "192.168.1.10",
                "parsed_data": {"parsed_ports": [{"port": 443}]},
            }
        ],
        case_id=1,
    )
    if not post:
        raise AssertionError("suggest_post_followup_actions should suggest TLS/HTTP after nmap")

    from utils.pcap_device_map import merge_device_observations

    devices = merge_device_observations(
        [
            {"type": "dhcp", "ip": "192.168.1.20", "mac": "aa:bb:cc:dd:ee:01", "hostname": "living-room-tv"},
            {"type": "arp", "ip": "192.168.1.20", "mac": "aa:bb:cc:dd:ee:01"},
            {"type": "mdns", "ip": "192.168.1.20", "hostname": "living-room-tv", "service": "_googlecast._tcp.local"},
        ]
    )
    if not devices or devices[0].get("ip") != "192.168.1.20":
        raise AssertionError("merge_device_observations should merge DHCP/ARP/mDNS rows")

    from utils.pcap_iot_heuristics import enrich_devices_with_roles

    enriched = enrich_devices_with_roles(devices)
    if enriched[0].get("role") not in {"smart_tv", "iot_unknown", "unknown"}:
        raise AssertionError("IoT role heuristic should classify cast-like device")

    from utils.pcap_recon_artifact import build_capture_recon_artifact

    artifact = build_capture_recon_artifact(
        {"summary": "capture ok", "parsed_data": {"triage": triage, "pcap_review": {"parsed_data": {**sample_parsed, "lan_devices": enriched}}}},
        followup_results=[{"module_id": "intel_abuseipdb", "target": "8.8.8.8", "success": True, "status": "completed", "summary": "clean"}],
        case_id=1,
    )
    if not artifact.get("progress"):
        raise AssertionError("build_capture_recon_artifact should include progress")

    parsed = live_capture_utils._parse_interface_line(
        "2.en0 [Up, Running, Wireless, Associated]"
    )
    if not parsed or parsed.get("id") != "en0":
        raise AssertionError("macOS tcpdump interface line parse failed")

    __import__("ui.packet_capture_page", fromlist=["render_packet_capture_page"])


def _check_urlhaus_module() -> None:
    import importlib.util
    import json

    registry = __import__("modules.module_registry", fromlist=["get_module", "is_executable"])
    module = registry.get_module("intel_urlhaus")
    if module is None or not module.implemented:
        raise AssertionError("intel_urlhaus should be implemented")
    if module.display_name != "URLhaus Malware URL Intelligence":
        raise AssertionError("intel_urlhaus display_name mismatch")
    if module.accepted_target_types != ("url", "domain", "ipv4"):
        raise AssertionError("intel_urlhaus accepted_target_types mismatch")
    if registry.is_executable(registry.get_module("intel_securitytrails")):
        raise AssertionError("intel_securitytrails must not be executable")

    executor = __import__("modules.executor", fromlist=["is_runtime_ready"])
    if not executor.is_runtime_ready("intel_urlhaus"):
        raise AssertionError("intel_urlhaus runtime should be ready")

    module_path = PROJECT_ROOT / "modules" / "4_threat_intelligence" / "intel_urlhaus.py"
    source = module_path.read_text(encoding="utf-8")
    for forbidden in (
        "urls/recent",
        "payloads/",
        "urlhaus.abuse.ch/api/",
        "v1/download",
    ):
        if forbidden in source:
            raise AssertionError(f"intel_urlhaus must not reference forbidden endpoint: {forbidden}")

    spec = importlib.util.spec_from_file_location("intel_urlhaus_smoke", module_path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load intel_urlhaus module")
    urlhaus_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(urlhaus_mod)

    missing = urlhaus_mod.run_urlhaus_lookup("http://example.com/test", auth_key="")
    if missing.get("status") != "blocked":
        raise AssertionError("missing Auth-Key should return blocked status")
    if "URLhaus / abuse.ch Auth-Key is not configured" not in str(missing.get("errors")):
        raise AssertionError("missing Auth-Key message mismatch")

    private = urlhaus_mod.run_urlhaus_lookup("192.168.1.1", auth_key="smoke-test-key", target_type="ipv4")
    if not private.get("success") or not private.get("parsed_data", {}).get("private_local_ip"):
        raise AssertionError("private IP should complete without API query")

    email_blocked = urlhaus_mod.run_urlhaus_lookup("user@example.com", auth_key="smoke-test-key")
    if email_blocked.get("status") != "blocked":
        raise AssertionError("email target should be blocked for urlhaus")

    mock_url = {
        "query_status": "ok",
        "id": "12345",
        "urlhaus_reference": "https://urlhaus.abuse.ch/url/12345/",
        "url": "http://example.com/malware.exe",
        "url_status": "online",
        "host": "example.com",
        "date_added": "2024-06-01 12:00:00 UTC",
        "threat": "malware_download",
        "blacklists": {"spamhaus_dbl": "not listed"},
        "tags": ["exe"],
        "payloads": [
            {
                "filename": "malware.exe",
                "sha256_hash": "abc123",
                "urlhaus_download": "https://urlhaus.abuse.ch/download/abc123/",
            }
        ],
    }
    url_lookup = urlhaus_mod.run_urlhaus_lookup(
        "http://example.com/malware.exe",
        auth_key="smoke-test-key",
        options={"mock_response": mock_url, "mock_lookup_type": "url"},
    )
    if not url_lookup.get("success"):
        raise AssertionError("mock URLhaus URL lookup should succeed")
    parsed = url_lookup.get("parsed_data") or {}
    if parsed.get("lookup_type") != "url":
        raise AssertionError("mock URL lookup missing lookup_type")
    if "urlhaus_download" in json.dumps(parsed):
        raise AssertionError("parsed_data should strip urlhaus_download fields")
    if not url_lookup.get("evidence"):
        raise AssertionError("mock URLhaus URL lookup should declare evidence hints")

    mock_host = {
        "query_status": "ok",
        "urlhaus_reference": "https://urlhaus.abuse.ch/host/example.com/",
        "host": "example.com",
        "firstseen": "2024-01-01",
        "url_count": "2",
        "blacklists": {"surbl": "listed"},
        "urls": [
            {
                "id": "1",
                "url": "http://example.com/a.exe",
                "url_status": "online",
                "threat": "malware_download",
                "date_added": "2024-06-01 12:00:00 UTC",
            },
            {
                "id": "2",
                "url": "http://example.com/b.exe",
                "url_status": "offline",
                "threat": "malware_download",
                "date_added": "2024-05-01 12:00:00 UTC",
            },
        ],
    }
    host_lookup = urlhaus_mod.run_urlhaus_lookup(
        "example.com",
        auth_key="smoke-test-key",
        options={"mock_response": mock_host, "mock_lookup_type": "host"},
    )
    if not host_lookup.get("success"):
        raise AssertionError("mock URLhaus host lookup should succeed")
    host_parsed = host_lookup.get("parsed_data") or {}
    if host_parsed.get("lookup_type") != "host":
        raise AssertionError("mock host lookup missing lookup_type")
    if not host_parsed.get("sampled_urls"):
        raise AssertionError("mock host lookup missing sampled URLs")

    interpreter = __import__(
        "utils.urlhaus_interpreter",
        fromlist=["interpret_urlhaus_results"],
    )
    findings = interpreter.interpret_urlhaus_results(parsed)
    if not findings:
        raise AssertionError("urlhaus interpreter should return findings")

    findings_registry = __import__(
        "utils.findings_registry",
        fromlist=["interpret_module_findings", "module_has_findings_pipeline"],
    )
    if not findings_registry.module_has_findings_pipeline("intel_urlhaus"):
        raise AssertionError("intel_urlhaus should have findings pipeline")
    pipeline_findings = findings_registry.interpret_module_findings("intel_urlhaus", parsed)
    if not pipeline_findings:
        raise AssertionError("findings pipeline returned no urlhaus findings")

    security = __import__("utils.security", fromlist=["redact_secrets_from_text"])
    redacted = security.redact_secrets_from_text("Auth-Key: supersecretauthkey123456")
    if "supersecretauthkey" in redacted:
        raise AssertionError("Auth-Key redaction failed in urlhaus smoke path")


def _check_api_module_helpers() -> None:
    import time

    helpers = __import__(
        "utils.api_module_helpers",
        fromlist=[
            "classify_provider_http_status",
            "missing_api_key_blocked_result",
            "project_user_agent",
            "rate_limit_seconds",
            "request_timeout_seconds",
            "reset_api_courtesy_delay_for_tests",
            "respect_api_courtesy_delay",
        ],
    )
    if "ProjectOverwatch/" not in helpers.project_user_agent():
        raise AssertionError("project_user_agent missing version")
    if helpers.request_timeout_seconds() <= 0:
        raise AssertionError("request_timeout_seconds should be positive")
    helpers.reset_api_courtesy_delay_for_tests()
    start = time.monotonic()
    helpers.respect_api_courtesy_delay()
    helpers.respect_api_courtesy_delay()
    elapsed = time.monotonic() - start
    if elapsed < helpers.rate_limit_seconds() * 0.9:
        raise AssertionError("respect_api_courtesy_delay should pause between consecutive calls")
    helpers.reset_api_courtesy_delay_for_tests()
    status, success, _, _ = helpers.classify_provider_http_status(429)
    if status != "completed_with_warnings" or not success:
        raise AssertionError("429 should map to completed_with_warnings")
    blocked = helpers.missing_api_key_blocked_result(
        module_id="smoke_api",
        env_key_name="SMOKE_API_KEY",
        provider_label="Smoke Provider",
        target="example.com",
        target_type="domain",
    )
    if blocked.get("status") != "blocked":
        raise AssertionError("missing_api_key_blocked_result should be blocked")


def _check_rdap_cache_backup() -> None:
    cache = __import__(
        "utils.rdap_cache",
        fromlist=[
            "clear_rdap_cache_for_case",
            "count_rdap_cache_for_case",
            "export_rdap_cache_for_case",
            "list_rdap_cache_for_case",
        ],
    )
    backup = __import__("utils.case_backup", fromlist=["export_case_bundle", "import_case_bundle"])
    db = __import__("database.db_setup", fromlist=["create_case", "get_db_conn"])
    conn = db.get_db_conn()
    try:
        case = db.create_case("RDAP cache backup smoke", conn=conn)
        case_id = case["id"]
        cache.set_rdap_cache_entry(
            case_id,
            "domain:backup-smoke.example",
            "domain",
            "rdap",
            '{"ldhName":"backup-smoke.example"}',
            conn=conn,
        )
        if cache.count_rdap_cache_for_case(case_id, conn=conn) != 1:
            raise AssertionError("rdap cache count mismatch")
        summaries = cache.list_rdap_cache_for_case(case_id, conn=conn)
        if not summaries or "response_bytes" not in summaries[0]:
            raise AssertionError("rdap cache summary missing response_bytes")
        bundle = backup.export_case_bundle(case_id)
        if not bundle.get("rdap_lookup_cache"):
            raise AssertionError("case backup should include rdap_lookup_cache")
        imported = backup.import_case_bundle(bundle, new_case_name="RDAP cache import smoke")
        imported_count = cache.count_rdap_cache_for_case(imported["id"], conn=conn)
        if imported_count != 1:
            raise AssertionError("imported case should restore rdap cache")
        cache.clear_rdap_cache_for_case(case_id, conn=conn)
    finally:
        conn.close()


def _check_crypto_scaffold() -> None:
    crypto = __import__(
        "utils.crypto_utils",
        fromlist=[
            "calculate_sha256",
            "cryptography_installed",
            "encryption_available",
            "local_encryption_configured",
        ],
    )
    digest = crypto.calculate_sha256("rdap-cache-smoke")
    if not digest or len(digest) != 64:
        raise AssertionError("calculate_sha256 failed")
    if crypto.local_encryption_configured():
        raise AssertionError("smoke environment should not have encryption key configured")
    if crypto.encryption_available():
        raise AssertionError("encryption_available should be false without key")


def _check_module_sdk_unit_tests() -> None:
    import unittest

    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName("tests.test_module_sdk")
    result = unittest.TextTestRunner(verbosity=0).run(suite)
    if not result.wasSuccessful():
        raise AssertionError(
            f"module SDK unit tests failed: failures={len(result.failures)} errors={len(result.errors)}"
        )


def _check_engagement_framework() -> None:
    from database.engagements import (
        SCOPE_STATUSES,
        add_scope_item,
        create_engagement,
        default_roe_payload,
        ensure_engagement_tables,
        get_engagement_for_case,
        get_roe,
        link_case_to_engagement,
        list_scope_items,
    )
    from database.db_setup import get_db_conn, get_or_create_default_case
    from utils.engagement_guardrails import assess_target_scope, check_engagement_execution
    from utils.module_testing_levels import get_module_testing_level, is_active_testing_level

    conn = get_db_conn()
    try:
        ensure_engagement_tables(conn)
        created = create_engagement(name="Smoke Engagement", client_name="Smoke Client", conn=conn)
        engagement_id = int(created["id"])
        roe = get_roe(engagement_id, conn=conn)
        if roe.get("denial_of_service_allowed"):
            raise AssertionError("default ROE should not allow DoS")
        add_scope_item(
            engagement_id,
            asset_value="example.com",
            asset_type="domain",
            scope_status="in_scope",
            permitted_testing_level="safe_active",
            conn=conn,
        )
        items = list_scope_items(engagement_id, conn=conn)
        if len(items) != 1:
            raise AssertionError("scope item not created")
        case = get_or_create_default_case(conn=conn)
        link_case_to_engagement(case["id"], engagement_id, conn=conn)
        linked = get_engagement_for_case(case["id"], conn=conn)
        if linked is None or linked["id"] != engagement_id:
            raise AssertionError("case engagement link failed")
        assessment = assess_target_scope("example.com", case_id=case["id"], conn=conn)
        if assessment.get("scope_status") != "in_scope":
            raise AssertionError("scope assessment should match in-scope domain")
        passive = check_engagement_execution(
            "infra_domain_intel",
            "example.com",
            case_id=case["id"],
            authorisation_confirmed=False,
            conn=conn,
        )
        if not passive.get("allowed"):
            raise AssertionError("passive module should be allowed")
        active = check_engagement_execution(
            "infra_nmap",
            "example.com",
            case_id=case["id"],
            authorisation_confirmed=False,
            conn=conn,
        )
        if active.get("allowed"):
            raise AssertionError("active module should be blocked without authorisation")
        level = get_module_testing_level("infra_nmap", {"nmap_options": {"script_category": "vuln"}})
        if level != "intrusive_active_check":
            raise AssertionError("nmap vuln scripts should map to intrusive level")
        if not is_active_testing_level(level):
            raise AssertionError("intrusive nmap level should be active")
    finally:
        conn.close()


def _check_operating_context_framework() -> None:
    from database.db_setup import create_case, get_db_conn
    from database.engagements import (
        create_engagement,
        ensure_engagement_tables,
        link_case_to_engagement,
    )
    from database.personal_lab import (
        add_personal_lab_scope_item,
        ensure_personal_lab_tables,
        list_personal_lab_scope,
    )
    from utils.operating_context import (
        CLIENT_ENGAGEMENT,
        PASSIVE_RESEARCH,
        PERSONAL_LAB,
        PERSONAL_LAB_PROFILE,
        check_module_execution_guardrails,
        enrich_operation_plan_with_preflight,
        operating_context_label,
    )
    from utils.module_compatibility import build_operation_plan

    if PERSONAL_LAB_PROFILE.get("name") != "Personal Lab":
        raise AssertionError("Personal Lab profile name mismatch")
    if not PERSONAL_LAB_PROFILE.get("safe_active_allowed"):
        raise AssertionError("Personal Lab profile should allow safe active checks")

    label = operating_context_label(PERSONAL_LAB)
    if "Personal Lab" not in label:
        raise AssertionError("operating_context_label failed")

    conn = get_db_conn()
    try:
        ensure_personal_lab_tables(conn)
        ensure_engagement_tables(conn)
        case = create_case("Operating Context Smoke", conn=conn)
        case_id = int(case["id"])

        passive = check_module_execution_guardrails(
            "infra_domain_intel",
            "example.com",
            case_id=case_id,
            authorisation_confirmed=False,
            operating_context=PASSIVE_RESEARCH,
            conn=conn,
        )
        if not passive.get("allowed"):
            raise AssertionError("passive module should run in Passive Research")

        active_passive_ctx = check_module_execution_guardrails(
            "infra_tls_review",
            "192.168.1.10",
            case_id=case_id,
            authorisation_confirmed=False,
            operating_context=PASSIVE_RESEARCH,
            conn=conn,
        )
        if active_passive_ctx.get("allowed"):
            raise AssertionError("active module should block in Passive Research")

        lab_blocked = check_module_execution_guardrails(
            "infra_tls_review",
            "192.168.1.10",
            case_id=case_id,
            authorisation_confirmed=False,
            operating_context=PERSONAL_LAB,
            personal_lab_confirmed=False,
            conn=conn,
        )
        if lab_blocked.get("allowed"):
            raise AssertionError("Personal Lab active module should block without confirmation")

        lab_ready = check_module_execution_guardrails(
            "infra_tls_review",
            "192.168.1.10",
            case_id=case_id,
            authorisation_confirmed=False,
            operating_context=PERSONAL_LAB,
            personal_lab_confirmed=True,
            conn=conn,
        )
        if not lab_ready.get("allowed"):
            raise AssertionError(
                "Personal Lab active module should be ready after confirmation (auto-scope on run)"
            )
        if not lab_ready.get("will_auto_scope_on_run"):
            raise AssertionError("unknown lab target should show will_auto_scope_on_run when confirmed")
        if lab_ready.get("result") != "ready":
            raise AssertionError("Personal Lab preflight should report ready")

        lab_exec = check_module_execution_guardrails(
            "infra_tls_review",
            "192.168.1.10",
            case_id=case_id,
            authorisation_confirmed=False,
            operating_context=PERSONAL_LAB,
            personal_lab_confirmed=True,
            apply_auto_scope=True,
            conn=conn,
        )
        if not lab_exec.get("allowed"):
            raise AssertionError("Personal Lab executor preflight should pass after auto-scope")
        if not lab_exec.get("auto_scope_created"):
            raise AssertionError("apply_auto_scope should create personal lab scope item")
        if not list_personal_lab_scope(case_id, conn=conn):
            raise AssertionError("personal lab scope item not created by auto-scope")

        draft = create_engagement(name="Draft Smoke Engagement", status="draft", conn=conn)
        link_case_to_engagement(case_id, int(draft["id"]), conn=conn)
        client_blocked = check_module_execution_guardrails(
            "infra_tls_review",
            "example.com",
            case_id=case_id,
            authorisation_confirmed=True,
            operating_context=CLIENT_ENGAGEMENT,
            conn=conn,
        )
        if client_blocked.get("allowed"):
            raise AssertionError("draft client engagement should block active checks")

        plan = build_operation_plan(
            case_name=case["name"],
            case_id=case_id,
            target="192.168.1.10",
            selected_module_ids=["infra_tls_review"],
            authorisation_confirmed=True,
        )
        enriched = enrich_operation_plan_with_preflight(
            plan,
            target="192.168.1.10",
            case_id=case_id,
            selected_module_ids=["infra_tls_review"],
            operating_context=PERSONAL_LAB,
            personal_lab_confirmed=True,
            authorisation_confirmed=False,
            conn=conn,
        )
        if not enriched.get("module_preflights"):
            raise AssertionError("enrich_operation_plan_with_preflight should attach module preflights")
    finally:
        conn.close()


def _check_next_actions_schema() -> None:
    from database.db_setup import create_case, get_db_conn
    from utils.next_actions import (
        ACTION_TYPES,
        enrich_action_readiness,
        finalize_actions,
        make_action,
        make_action_id,
        suggest_next_actions,
    )
    from utils.assessment_goals import GOAL_QUICK_SAFETY
    from utils.target_profile import build_target_profile

    required = {
        "id",
        "title",
        "reason",
        "priority",
        "action_type",
        "target",
        "entity_id",
        "module_id",
        "finding_id",
        "enabled",
        "blocked_reason",
        "button_label",
    }
    action = make_action(
        title="Test action",
        reason="Schema smoke test.",
        action_type="run_module",
        module_id="intel_shodan",
        target="203.0.113.1",
        enabled=False,
        blocked_reason="Disabled for smoke test.",
        button_label="Select module",
    )
    if not required.issubset(action.keys()):
        raise AssertionError(f"action missing fields: {required - set(action.keys())}")
    if action.get("enabled"):
        raise AssertionError("explicitly disabled action should have enabled=False")
    if not action.get("blocked_reason"):
        raise AssertionError("disabled action should include blocked_reason")

    action_id = make_action_id("add_to_queue", "Queue pivot", target="api.example.com")
    if not action_id:
        raise AssertionError("make_action_id should return a stable id")

    if "no_action" not in ACTION_TYPES:
        raise AssertionError("ACTION_TYPES should include no_action")

    conn = get_db_conn()
    try:
        case = create_case("Next Actions Schema", conn=conn)
        profile = build_target_profile(case["id"], "example.com", conn=conn)
        actions = suggest_next_actions(
            case_id=case["id"],
            target="example.com",
            goal_id=GOAL_QUICK_SAFETY,
            target_profile=profile,
            latest_results=[],
            operating_context="passive_research",
            conn=conn,
        )
        for item in actions:
            if not required.issubset(item.keys()):
                raise AssertionError(f"suggested action missing fields: {required - set(item.keys())}")
            if not item.get("enabled") and not item.get("blocked_reason"):
                raise AssertionError("disabled suggested action must explain why")

        finalized = finalize_actions(
            [
                make_action(
                    title="Run VirusTotal",
                    reason="Reputation check.",
                    action_type="run_module",
                    module_id="intel_virustotal",
                    target="example.com",
                )
            ],
            case_id=case["id"],
            operating_context="passive_research",
            personal_lab_confirmed=False,
            authorisation_confirmed=False,
            conn=conn,
        )
        vt = finalized[0]
        if vt.get("enabled") and vt.get("action_type") == "run_module":
            from utils.settings_manager import has_api_key

            if not has_api_key("VIRUSTOTAL_API_KEY"):
                raise AssertionError("VirusTotal action should be blocked without API key")
        elif not vt.get("blocked_reason") and vt.get("action_type") == "no_action":
            raise AssertionError("blocked VT action should include blocked_reason or no_action hint")

        blocked_active = enrich_action_readiness(
            make_action(
                title="Run TLS review",
                reason="Active check.",
                action_type="run_module",
                module_id="infra_tls_review",
                target="example.com",
            ),
            case_id=case["id"],
            operating_context="passive_research",
            personal_lab_confirmed=False,
            authorisation_confirmed=False,
            conn=conn,
        )
        if blocked_active.get("enabled"):
            raise AssertionError("active module in passive context should be blocked")
        if not blocked_active.get("blocked_reason"):
            raise AssertionError("blocked active action should include blocked_reason")
    finally:
        conn.close()


def _check_local_ip_triage() -> None:
    from database.db_setup import create_case, get_db_conn
    from utils.assessment_goals import GOAL_FULL_CLIENT, GOAL_LOCAL_NETWORK, get_modules_for_goal
    from utils.http_security_interpreter import interpret_http_security_results
    from utils.journey_planner import build_assessment_journey
    from utils.pivot_discovery import discover_pivots_from_results
    from utils.service_classifier import (
        CLASS_HTTP_CANDIDATE,
        CLASS_HTTPS_CANDIDATE,
        CLASS_NON_WEB_SERVICE,
        classify_service_observation,
    )
    from utils.web_port_planner import (
        DEFAULT_COMMON_WEB_PORTS,
        filter_modules_without_service_data,
        parse_custom_web_port_list,
    )

    if classify_service_observation(port=80, service_name="http") != CLASS_HTTP_CANDIDATE:
        raise AssertionError("port 80 http should be http_candidate")
    if classify_service_observation(port=443, service_name="https") != CLASS_HTTPS_CANDIDATE:
        raise AssertionError("port 443 https should be https_candidate")
    if classify_service_observation(port=22, service_name="ssh") != CLASS_NON_WEB_SERVICE:
        raise AssertionError("port 22 ssh should be non_web_service")
    if classify_service_observation(port=445, service_name="microsoft-ds") != CLASS_NON_WEB_SERVICE:
        raise AssertionError("port 445 smb should be non_web_service")
    if classify_service_observation(port=3389, service_name="ms-wbt-server") != CLASS_NON_WEB_SERVICE:
        raise AssertionError("port 3389 rdp should be non_web_service")
    if classify_service_observation(port=5900, service_name="vnc") != CLASS_NON_WEB_SERVICE:
        raise AssertionError("port 5900 vnc should be non_web_service")

    ports, err = parse_custom_web_port_list("80, 443, 8080")
    if err or ports != [80, 443, 8080]:
        raise AssertionError("valid custom port list should parse")
    _, err = parse_custom_web_port_list("1-65535")
    if err is None:
        raise AssertionError("port ranges should be rejected")
    many, err = parse_custom_web_port_list(",".join(str(8000 + i) for i in range(11)))
    if err is None:
        raise AssertionError("custom port list should cap at 10 ports")
    if len(DEFAULT_COMMON_WEB_PORTS) != 6:
        raise AssertionError("common web ports should remain capped to default list")

    private_modules = get_modules_for_goal(
        GOAL_LOCAL_NETWORK, "ipv4", target="192.168.1.10"
    )
    if private_modules != ["infra_nmap"]:
        raise AssertionError("private IP local network goal should recommend nmap first")
    full_client_private = get_modules_for_goal(
        GOAL_FULL_CLIENT, "ipv4", target="192.168.1.10"
    )
    if "infra_tls_review" in full_client_private or "infra_http_security" in full_client_private:
        raise AssertionError("private IP full client should not blindly recommend TLS/HTTP")
    filtered = filter_modules_without_service_data(
        ["infra_nmap", "infra_tls_review", "infra_http_security"]
    )
    if filtered != ["infra_nmap"]:
        raise AssertionError("filter should remove blind HTTP/TLS without service data")

    conn = get_db_conn()
    try:
        case = create_case("Local IP Triage", conn=conn)
        journey = build_assessment_journey(
            case_id=case["id"],
            target="192.168.1.10",
            goal_id=GOAL_LOCAL_NETWORK,
            selected_module_ids=private_modules,
            operating_context="personal_lab",
            personal_lab_confirmed=True,
            conn=conn,
        )
        recommended_ids = journey.get("recommended_module_ids") or []
        if "infra_nmap" not in recommended_ids:
            raise AssertionError("journey should recommend nmap for private IP")
        if "infra_tls_review" in recommended_ids or "infra_http_security" in recommended_ids:
            raise AssertionError("journey should not recommend blind HTTP/TLS without service data")
        if not journey.get("triage_message"):
            raise AssertionError("private IP journey should include triage message")

        nmap_http = classify_service_observation(port=80, service_name="http")
        nmap_https = classify_service_observation(port=443, service_name="https")
        if nmap_http != CLASS_HTTP_CANDIDATE or nmap_https != CLASS_HTTPS_CANDIDATE:
            raise AssertionError("nmap-like service hints should classify web ports")

        unreachable_findings = interpret_http_security_results(
            {
                "host": "192.168.1.10",
                "port": 443,
                "scheme": "https",
                "requested_url": "https://192.168.1.10/",
                "target_source": "default_assumption",
                "response": {"success": False, "error": "timed out"},
                "connection_outcome": {
                    "reachable": False,
                    "host": "192.168.1.10",
                    "port": 443,
                    "scheme": "https",
                    "error": "timed out",
                },
                "security_headers": {},
            }
        )
        if any("not observed" in (f.get("title") or "").lower() for f in unreachable_findings):
            raise AssertionError("unreachable HTTP should not create missing-header findings")
        if not any("not reachable" in (f.get("title") or "").lower() for f in unreachable_findings):
            raise AssertionError("unreachable HTTP should create reachability finding")

        pivots = discover_pivots_from_results(
            [
                {
                    "success": True,
                    "module_id": "infra_http_security",
                    "parsed_data": {
                        "target_source": "default_assumption",
                        "response": {"success": False, "final_url": "https://192.168.1.10/"},
                    },
                }
            ]
        )
        if pivots:
            raise AssertionError("unreachable default HTTP URL should not create URL pivot")
    finally:
        conn.close()


def _check_workspace_ui_helpers() -> None:
    from ui.styles import STATUS_CHIPS, status_chip
    import ui.action_cards
    import ui.workspace_cards

    if not STATUS_CHIPS.get("ready"):
        raise AssertionError("status chips should define ready")
    if "Ready" not in status_chip("ready"):
        raise AssertionError("status_chip should format ready label")
    if not hasattr(ui.workspace_cards, "render_target_profile_card"):
        raise AssertionError("workspace_cards should expose card helpers")
    if not hasattr(ui.action_cards, "render_action_cards"):
        raise AssertionError("action_cards should expose render_action_cards")


def _check_assessment_goal_modules_registered() -> None:
    from modules.module_registry import get_module
    from utils.assessment_goals import GOAL_ORDER, get_modules_for_goal

    target_types = ("domain", "ipv4", "url", "email")
    seen: set[str] = set()
    for goal_id in GOAL_ORDER:
        for target_type in target_types:
            for module_id in get_modules_for_goal(goal_id, target_type, target="example.com"):
                if module_id in seen:
                    continue
                seen.add(module_id)
                if get_module(module_id) is None:
                    raise AssertionError(f"goal {goal_id} references unknown module {module_id}")
    if "infra_shodan" in seen:
        raise AssertionError("infra_shodan should be intel_shodan in goal module sets")


def _check_nmap_profile_runner() -> None:
    from utils.nmap_profiles import (
        PROFILE_ORDER,
        PROFILE_WEB_SURFACE,
        all_profile_ids,
        dangerous_default_flags,
        get_profile_definition,
        options_for_profile,
        parse_custom_port_list,
        profile_display_name,
        resolve_profile_id,
    )
    from utils.nmap_options import build_nmap_flags, normalize_options

    if len(all_profile_ids()) != len(PROFILE_ORDER):
        raise AssertionError("profile order mismatch")
    for profile_id in PROFILE_ORDER:
        definition = get_profile_definition(profile_id)
        for key in (
            "profile_id",
            "display_name",
            "description",
            "intended_use",
            "estimated_noise",
            "testing_level",
            "requires_elevation",
            "active_warning",
        ):
            if key not in definition:
                raise AssertionError(f"profile {profile_id} missing {key}")
        if not profile_display_name(profile_id):
            raise AssertionError(f"profile display name missing for {profile_id}")

    validated, errors = parse_custom_port_list("80,443,abc")
    if validated or not errors:
        raise AssertionError("custom port validation should reject abc")
    validated, errors = parse_custom_port_list("80,443")
    if validated != "80,443" or errors:
        raise AssertionError("custom port validation should accept 80,443")

    too_many = ",".join(str(port) for port in range(1, 60))
    _, errors = parse_custom_port_list(too_many)
    if not errors:
        raise AssertionError("custom port list should cap at 50 ports")

    if dangerous_default_flags():
        raise AssertionError(f"dangerous default profiles: {dangerous_default_flags()}")

    web_opts = normalize_options(options_for_profile(PROFILE_WEB_SURFACE))
    flags = build_nmap_flags(web_opts)
    if "-F" in flags and "--top-ports=1000" in " ".join(flags):
        raise AssertionError("web surface profile should not use broad default range")

    legacy = resolve_profile_id("Quick check")
    if legacy != "quick_service_check":
        raise AssertionError("legacy profile alias failed")

    from modules.executor_dispatch import get_dispatch_entry

    entry = get_dispatch_entry("infra_nmap")
    if entry is None or not callable(entry.execute):
        raise AssertionError("infra_nmap dispatch entry missing after profile runner")

    from utils.nmap_lan_enrichment import enrich_lan_devices_from_nmap

    devices = [{"ip": "192.168.1.10", "hostname": "router", "sources": ["dhcp"], "confidence": "high"}]
    nmap_result = {
        "module_id": "infra_nmap",
        "success": True,
        "target": "192.168.1.10",
        "parsed_data": {
            "parsed_ports": [{"port": 443, "protocol": "tcp", "service": "https"}],
            "scan_profile": {"display_name": "Local Device Detail"},
        },
    }
    enriched = enrich_lan_devices_from_nmap(devices, [nmap_result])
    if enriched[0].get("nmap_open_ports") != 1 or "nmap" not in enriched[0].get("sources", []):
        raise AssertionError("LAN enrichment should merge Nmap hints without dropping PCAP sources")


def _check_remote_access_review() -> None:
    from utils.remote_access_classifier import (
        classify_remote_access_service,
        filter_remote_access_services,
        service_display_name,
    )
    from utils.remote_access_interpreter import interpret_remote_access_results

    cases = (
        (22, "ssh", "remote_admin"),
        (3389, "ms-wbt-server", "remote_admin"),
        (5900, "vnc", "remote_admin"),
        (445, "microsoft-ds", "file_sharing"),
        (23, "telnet", "legacy_cleartext"),
        (21, "ftp", "legacy_cleartext"),
    )
    for port, service, expected in cases:
        got = classify_remote_access_service(port=port, service_name=service)
        if got != expected:
            raise AssertionError(f"classification for {service}:{port} expected {expected}, got {got}")

    services = filter_remote_access_services(
        [
            {"port": 22, "protocol": "tcp", "service_name": "ssh"},
            {"port": 80, "protocol": "tcp", "service_name": "http"},
        ]
    )
    if len(services) != 1 or services[0]["service_label"] != "SSH":
        raise AssertionError("filter_remote_access_services should keep SSH only")

    parsed = {
        "target": "192.168.1.10",
        "is_private_target": True,
        "remote_services": services,
        "no_service_data": False,
    }
    findings = interpret_remote_access_results(parsed)
    if not findings or not any("SSH" in f.get("title", "") for f in findings):
        raise AssertionError("interpreter should emit SSH finding")

    from modules.module_registry import get_module
    from modules.executor_dispatch import get_dispatch_entry

    mod = get_module("infra_remote_access_review")
    if mod is None or not mod.implemented:
        raise AssertionError("infra_remote_access_review registry entry missing")
    entry = get_dispatch_entry("infra_remote_access_review")
    if entry is None or not callable(entry.execute):
        raise AssertionError("infra_remote_access_review dispatch missing")

    from modules.executors.loaders import _load_remote_access_handler

    _load_remote_access_handler()
    from modules.executors import loaders

    if loaders._remote_access_handler is None:
        raise AssertionError("remote access handler failed to load")

    if not loaders._remote_access_handler(
        "192.168.1.10",
        options={"manual_services": [{"port": 22, "service_name": "ssh"}]},
    ).get("success"):
        raise AssertionError("manual port review should succeed")
    if not loaders._remote_access_handler(
        "192.168.1.10",
        options={"manual_services": [{"port": 22, "service_name": "ssh"}]},
    ).get("data", {}).get("remote_services"):
        raise AssertionError("manual SSH port should classify as remote access")


def _check_web_stack_identifier() -> None:
    import importlib.util

    from utils.web_stack_indicators import CATEGORY_CMS, detect_indicators, extract_html_artifacts
    from utils.web_stack_interpreter import interpret_web_stack_results

    html = (
        '<html><head><meta name="generator" content="WordPress 6.4">'
        '<script src="/wp-includes/js/jquery/jquery.min.js"></script>'
        '<link href="/wp-content/themes/twenty/style.css" rel="stylesheet">'
        "</head><body>Example</body></html>"
    )
    artifacts = extract_html_artifacts(html)
    if artifacts["meta_generator"] != "WordPress 6.4":
        raise AssertionError("meta generator extraction failed")
    indicators = detect_indicators(
        headers={"server": "nginx/1.24.0", "x-powered-by": "PHP/8.2"},
        body_preview=html,
        script_sources=artifacts["script_sources"],
        stylesheet_links=artifacts["stylesheet_links"],
        meta_generator=artifacts["meta_generator"],
        cookie_names=["wordpress_logged_in"],
        redirect_urls=["https://example.com/"],
    )
    names = {row["name"] for row in indicators}
    if "WordPress" not in names or "nginx" not in names:
        raise AssertionError(f"expected WordPress/nginx indicators, got {names}")

    mock_data = {
        "target": "example.com",
        "host": "example.com",
        "scheme": "https",
        "port": 443,
        "requested_url": "https://example.com/",
        "target_type": "domain",
        "response": {
            "success": True,
            "status_code": 200,
            "final_url": "https://example.com/",
            "redirect_chain": [{"url": "https://example.com/", "status_code": 200}],
            "content_type": "text/html",
            "error": None,
        },
        "headers": {"server": "nginx", "x-powered-by": "PHP/8.2"},
        "indicators": indicators,
        "categories": ["CMS", "Web server"],
        "script_sources": artifacts["script_sources"],
        "stylesheet_links": artifacts["stylesheet_links"],
        "meta_generator": artifacts["meta_generator"],
    }
    findings = interpret_web_stack_results(mock_data)
    if not findings or not any("indicator" in f.get("title", "").lower() for f in findings):
        raise AssertionError("web stack interpreter should emit indicator finding")

    registry = __import__("modules.module_registry", fromlist=["get_module"])
    module = registry.get_module("infra_web_stack_identifier")
    if module is None or not module.implemented:
        raise AssertionError("infra_web_stack_identifier registry entry missing or not implemented")
    if not module.requires_authorisation:
        raise AssertionError("infra_web_stack_identifier must require authorisation")
    if module.requires_api_key:
        raise AssertionError("infra_web_stack_identifier should not require API key")
    if module.accepted_target_types != ("domain", "url", "ipv4"):
        raise AssertionError("infra_web_stack_identifier accepted_target_types mismatch")
    for field in ("short_help", "detailed_help", "caution_notes", "config_notes"):
        if not getattr(module, field, None):
            raise AssertionError(f"infra_web_stack_identifier missing registry metadata: {field}")

    module_path = Path(PROJECT_ROOT) / "modules" / "2_infrastructure" / "infra_web_stack_identifier.py"
    spec = importlib.util.spec_from_file_location("infra_web_stack_identifier", module_path)
    if spec is None or spec.loader is None:
        raise AssertionError("could not load infra_web_stack_identifier module spec")
    stack_mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(stack_mod)

    result = stack_mod.run_web_stack_identifier("example.com", options={"mock_data": mock_data})
    if not result.get("success") or result.get("module_id") != "infra_web_stack_identifier":
        raise AssertionError("mock web stack identification should succeed")
    data = result.get("data") or {}
    if "body_preview" in data:
        raise AssertionError("parsed data must not store full page body")
    if len(result.get("raw_output", "")) > 50000:
        raise AssertionError("raw output unexpectedly large")

    blocked = stack_mod.run_web_stack_identifier("not a valid domain !!!")
    if blocked.get("success"):
        raise AssertionError("invalid web stack target should be blocked")

    registry_pipeline = __import__(
        "utils.findings_registry",
        fromlist=["module_has_findings_pipeline", "interpret_module_findings"],
    )
    if not registry_pipeline.module_has_findings_pipeline("infra_web_stack_identifier"):
        raise AssertionError("findings pipeline not registered for infra_web_stack_identifier")

    executor = __import__("modules.executor", fromlist=["is_runtime_ready", "execute_module"])
    if not executor.is_runtime_ready("infra_web_stack_identifier"):
        raise AssertionError("executor cannot load infra_web_stack_identifier backend")

    evidence = __import__("utils.evidence_model", fromlist=["default_evidence_for_module", "default_relationship_evidence"])
    defaults = evidence.default_evidence_for_module("infra_web_stack_identifier")
    if not defaults.get("collection_method"):
        raise AssertionError("web stack default evidence missing collection_method")
    rel = evidence.default_relationship_evidence("infra_web_stack_identifier", "exposes_web_service")
    if not rel.get("evidence_type"):
        raise AssertionError("web stack relationship evidence missing")

    testing_levels = __import__("utils.module_testing_levels", fromlist=["get_module_testing_level"])
    if testing_levels.get_module_testing_level("infra_web_stack_identifier") != "safe_active_check":
        raise AssertionError("infra_web_stack_identifier testing level should be safe_active_check")

    source = module_path.read_text(encoding="utf-8")
    if "subprocess" in source or "shell=True" in source:
        raise AssertionError("infra_web_stack_identifier must not use subprocess/shell=True")

    from modules.executor_dispatch import get_dispatch_entry

    entry = get_dispatch_entry("infra_web_stack_identifier")
    if entry is None or not callable(entry.execute):
        raise AssertionError("infra_web_stack_identifier dispatch missing")

    from modules.executors.loaders import _load_web_stack_handler

    _load_web_stack_handler()
    from modules.executors import loaders

    if loaders._web_stack_handler is None:
        raise AssertionError("web stack handler failed to load")

    from utils.result_next_actions import suggest_result_action

    cms_data = {**mock_data, "indicators": [{"name": "WordPress", "category": CATEGORY_CMS, "confidence": "high", "source": "meta"}]}
    cms_action = suggest_result_action(
        {"module_id": "infra_web_stack_identifier", "success": True, "parsed_data": cms_data, "interpreter_findings": findings},
        target="example.com",
    )
    if cms_action.get("module_id") != "infra_website_metadata":
        raise AssertionError("CMS indicators should suggest website metadata review")


def _check_executor_dispatch_registry() -> None:
    import inspect

    from modules import executor as executor_mod
    from modules import executor_dispatch as dispatch_mod
    from modules.executors import infrastructure, loaders, network_analysis, registry, threat_intelligence
    from modules.executor_dispatch import get_dispatch_entry, list_registered_module_ids
    from modules.module_registry import MODULES, is_executable

    for mod in (
        executor_mod,
        dispatch_mod,
        loaders,
        infrastructure,
        threat_intelligence,
        network_analysis,
        registry,
    ):
        __import__(mod.__name__)

    registered = set(list_registered_module_ids())
    expected = {
        "infra_nmap",
        "infra_domain_intel",
        "infra_cert_subdomain",
        "infra_website_metadata",
        "infra_whois_rdap",
        "infra_email_security",
        "infra_tls_review",
        "infra_http_security",
        "infra_remote_access_review",
        "infra_web_stack_identifier",
        "intel_virustotal",
        "intel_abuseipdb",
        "intel_greynoise",
        "intel_shodan",
        "intel_urlhaus",
        "net_pcap_review",
        "net_live_capture",
    }
    if registered != expected:
        missing = expected - registered
        extra = registered - expected
        raise AssertionError(
            f"dispatch registry mismatch missing={sorted(missing)} extra={sorted(extra)}"
        )

    for module in MODULES:
        if not is_executable(module):
            continue
        if module.module_id not in registered:
            raise AssertionError(f"executable module {module.module_id} missing dispatch registration")
        entry = get_dispatch_entry(module.module_id)
        if entry is None or entry.execute is None:
            raise AssertionError(f"dispatch entry incomplete for {module.module_id}")
        for attr in ("load", "is_ready", "get_error", "execute"):
            fn = getattr(entry, attr)
            if not callable(fn):
                raise AssertionError(f"dispatch {module.module_id}.{attr} is not callable")
        if entry.persist_hook is not None and not callable(entry.persist_hook):
            raise AssertionError(f"dispatch {module.module_id}.persist_hook is not callable")

    if not callable(executor_mod.execute_module):
        raise AssertionError("execute_module must remain callable on modules.executor")
    if len(inspect.signature(executor_mod.execute_module).parameters) < 3:
        raise AssertionError("execute_module signature changed unexpectedly")


def _check_case_workflow_helpers() -> None:
    from database.db_setup import get_or_create_default_case
    from utils.case_workflow import STAGE_TARGET, assess_case_workflow

    case = get_or_create_default_case()
    workflow = assess_case_workflow(case["id"])
    if STAGE_TARGET not in workflow.get("completed", {}):
        raise AssertionError("case workflow should include target stage")


def _check_case_session_helpers() -> None:
    import streamlit as st
    from utils import case_session as cs

    store: dict = {}

    class _SessionState:
        def get(self, key, default=None):
            return store.get(key, default)

        def __contains__(self, key):
            return key in store

        def __getitem__(self, key):
            return store[key]

        def __setitem__(self, key, value):
            store[key] = value

        def __delitem__(self, key):
            del store[key]

        def __getattr__(self, key):
            try:
                return store[key]
            except KeyError as exc:
                raise AttributeError(key) from exc

        def __setattr__(self, key, value):
            if key == "store":
                object.__setattr__(self, key, value)
            else:
                store[key] = value

        def pop(self, key, *args):
            return store.pop(key, *args)

        def setdefault(self, key, default):
            if key not in store:
                store[key] = default
            return store[key]

    st.session_state = _SessionState()
    st.session_state.operation_target = "acme.test"
    cs.persist_case_session(7)
    st.session_state.operation_target = ""
    cs.load_case_session(7)
    if st.session_state.get("operation_target") != "acme.test":
        raise AssertionError("case session roundtrip failed")

    st.session_state = _SessionState()
    st.session_state.operation_target = "keep.me"
    cs.ensure_case_session(3)
    if st.session_state.get("operation_target") != "keep.me":
        raise AssertionError("case session upgrade seed failed")


def _check_guided_workspace_helpers() -> None:
    from utils.assessment_goals import GOAL_QUICK_SAFETY, get_modules_for_goal, list_assessment_goals
    from utils.journey_planner import build_assessment_journey
    from utils.next_actions import suggest_next_actions
    from utils.personal_lab_readiness import evaluate_personal_lab_readiness
    from utils.pivot_discovery import discover_pivots_from_results
    from utils.target_profile import build_target_profile
    from database.db_setup import create_case, get_db_conn

    if not list_assessment_goals():
        raise AssertionError("assessment goals should be defined")
    modules = get_modules_for_goal(GOAL_QUICK_SAFETY, "domain", target="example.com")
    if not modules:
        raise AssertionError("quick safety goal should recommend domain modules")

    conn = get_db_conn()
    try:
        case = create_case("Workspace Smoke", conn=conn)
        profile = build_target_profile(case["id"], "example.com", conn=conn)
        if profile.get("target_type") != "domain":
            raise AssertionError("target profile type detection failed")
        journey = build_assessment_journey(
            case_id=case["id"],
            target="example.com",
            goal_id=GOAL_QUICK_SAFETY,
            operating_context="passive_research",
            conn=conn,
        )
        if not journey.get("recommended") and not journey.get("optional"):
            raise AssertionError("journey should classify modules")
        actions = suggest_next_actions(
            case_id=case["id"],
            target="example.com",
            goal_id=GOAL_QUICK_SAFETY,
            target_profile=profile,
            latest_results=[],
            conn=conn,
        )
        if not actions:
            raise AssertionError("next actions should return suggestions")
        schema_fields = {
            "id",
            "title",
            "reason",
            "priority",
            "action_type",
            "enabled",
            "blocked_reason",
            "button_label",
        }
        for action in actions:
            if not schema_fields.issubset(action.keys()):
                raise AssertionError("next action schema incomplete")
        readiness = evaluate_personal_lab_readiness(
            "203.0.113.10",
            case_id=case["id"],
            personal_lab_confirmed=True,
            testing_level="safe_active_check",
            conn=conn,
        )
        if not readiness.get("will_auto_scope_on_run"):
            raise AssertionError("confirmed public target should auto-scope on run")
    finally:
        conn.close()

    pivots = discover_pivots_from_results(
        [
            {
                "success": True,
                "module_id": "infra_cert_subdomain",
                "parsed_data": {"subdomains": ["api.example.com"]},
            }
        ]
    )
    if not pivots:
        raise AssertionError("pivot discovery should find subdomains")


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

    run(
        "security baseline",
        lambda: _check_security_baseline(),
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
        "email security module",
        lambda: _check_email_security_module(),
    )

    run(
        "tls review module",
        lambda: _check_tls_review_module(),
    )

    run(
        "http security module",
        lambda: _check_http_security_module(),
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
        "abuseipdb module",
        lambda: _check_abuseipdb_module(),
    )

    run(
        "greynoise module",
        lambda: _check_greynoise_module(),
    )

    run(
        "shodan module",
        lambda: _check_shodan_module(),
    )

    run(
        "urlhaus module",
        lambda: _check_urlhaus_module(),
    )

    run(
        "pcap module",
        lambda: _check_pcap_module(),
    )

    run(
        "live capture module",
        lambda: _check_live_capture_module(),
    )

    run(
        "api module helpers",
        lambda: _check_api_module_helpers(),
    )

    run(
        "rdap cache backup",
        lambda: _check_rdap_cache_backup(),
    )

    run(
        "crypto scaffold",
        lambda: _check_crypto_scaffold(),
    )

    run(
        "module SDK unit tests",
        lambda: _check_module_sdk_unit_tests(),
    )

    run(
        "engagement framework",
        lambda: _check_engagement_framework(),
    )

    run(
        "operating context framework",
        lambda: _check_operating_context_framework(),
    )

    run(
        "workspace UI helpers",
        lambda: _check_workspace_ui_helpers(),
    )

    run(
        "nmap profile runner",
        lambda: _check_nmap_profile_runner(),
    )

    run(
        "remote access review",
        lambda: _check_remote_access_review(),
    )

    run(
        "web stack identifier",
        lambda: _check_web_stack_identifier(),
    )

    run(
        "local IP triage",
        lambda: _check_local_ip_triage(),
    )

    run(
        "next actions schema",
        lambda: _check_next_actions_schema(),
    )

    run(
        "executor dispatch registry",
        lambda: _check_executor_dispatch_registry(),
    )

    run(
        "case workflow helpers",
        lambda: _check_case_workflow_helpers(),
    )

    run(
        "case session helpers",
        lambda: _check_case_session_helpers(),
    )

    run(
        "assessment goal modules",
        lambda: _check_assessment_goal_modules_registered(),
    )

    run(
        "guided workspace helpers",
        lambda: _check_guided_workspace_helpers(),
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

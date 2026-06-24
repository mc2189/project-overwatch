"""Run and queue PCAP triage follow-up modules from capture results."""

from __future__ import annotations

from typing import Any

from database.db_setup import create_or_get_entity, get_db_conn, infer_entity_type, list_operations
from modules.executor import execute_module
from modules.module_registry import get_module, is_executable
from utils.batch_queue import add_queue_item, sort_queue_items
from utils.batch_queue_store import load_batch_queue, save_batch_queue
from utils.module_compatibility import get_incompatible_reason
from utils.nmap_options import PROFILE_STANDARD, default_options_for_profile
from utils.operating_context import PERSONAL_LAB
from utils.pcap_next_actions import _api_block_reason
from utils.target_detection import get_target_type
from utils.web_port_planner import is_private_ipv4_target

PASSIVE_FOLLOWUP_MODULES: frozenset[str] = frozenset(
    {
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
    }
)

ACTIVE_LAN_MODULES: tuple[str, ...] = ("infra_nmap",)


def _target_type_for_value(value: str, entity_type: str) -> str:
    if entity_type == "domain":
        return "domain"
    return get_target_type(value.strip())


def runnable_modules_for_entity(
    item: dict[str, Any],
    *,
    passive_only: bool = False,
    active_only: bool = False,
) -> list[str]:
    """Return suggested module IDs that can run for a ranked capture entity."""
    value = str(item.get("value") or "").strip()
    entity_type = str(item.get("entity_type") or "ip")
    if not value:
        return []

    target_type = _target_type_for_value(value, entity_type)
    module_ids = list(item.get("suggested_modules") or [])
    if not module_ids:
        if entity_type == "ip" and is_private_ipv4_target(value):
            module_ids = ["infra_nmap", "infra_tls_review", "infra_http_security"]
        elif entity_type == "ip":
            module_ids = ["intel_abuseipdb", "intel_greynoise", "intel_shodan"]
        elif entity_type == "domain":
            module_ids = ["infra_domain_intel", "intel_urlhaus"]

    selected: list[str] = []
    for module_id in module_ids:
        if passive_only and module_id not in PASSIVE_FOLLOWUP_MODULES:
            continue
        if active_only and module_id not in ACTIVE_LAN_MODULES:
            continue
        module = get_module(module_id)
        if module is None or not is_executable(module):
            continue
        if get_incompatible_reason(module, target_type):
            continue
        if _api_block_reason(module_id):
            continue
        selected.append(module_id)
    return selected


def queue_passive_for_ranked_entities(
    case_id: int,
    ranked: list[dict[str, Any]],
    *,
    tiers: tuple[str, ...] = ("investigate", "review"),
) -> tuple[int, list[str]]:
    """Queue passive suggested modules for ranked capture entities."""
    conn = get_db_conn()
    try:
        operations = list_operations(case_id, conn=conn)
        items = load_batch_queue(case_id)
        added_count = 0
        messages: list[str] = []

        for item in ranked:
            if item.get("tier") not in tiers:
                continue
            value = str(item.get("value") or "").strip()
            if not value:
                continue
            entity = create_or_get_entity(
                case_id,
                infer_entity_type(value),
                value,
                label=value,
                source="capture_followup",
                conn=conn,
            )
            for module_id in runnable_modules_for_entity(item, passive_only=True):
                items, queue_item, reason = add_queue_item(
                    items,
                    case_id,
                    entity,
                    module_id,
                    operations=operations,
                )
                if queue_item:
                    added_count += 1
                elif reason and "Already queued" not in reason:
                    messages.append(f"{value}/{module_id}: {reason}")

        if added_count:
            save_batch_queue(case_id, sort_queue_items(items))
    finally:
        conn.close()

    return added_count, messages


def run_modules_for_ranked_entities(
    case_id: int,
    ranked: list[dict[str, Any]],
    *,
    tiers: tuple[str, ...] = ("investigate",),
    passive_only: bool = False,
    active_only: bool = False,
    personal_lab_confirmed: bool = True,
    limit_entities: int = 8,
    limit_modules_per_entity: int = 4,
    ignore_tier: bool = False,
) -> list[dict[str, Any]]:
    """Execute suggested modules immediately (Personal Lab capture follow-up)."""
    results: list[dict[str, Any]] = []
    nmap_options = default_options_for_profile(PROFILE_STANDARD)
    conn = get_db_conn()
    try:
        count = 0
        for item in ranked:
            if count >= limit_entities:
                break
            if not ignore_tier and tiers and item.get("tier") not in tiers:
                continue
            value = str(item.get("value") or "").strip()
            if not value:
                continue

            entity = create_or_get_entity(
                case_id,
                infer_entity_type(value),
                value,
                label=value,
                source="capture_followup",
                conn=conn,
            )
            module_ids = runnable_modules_for_entity(
                item,
                passive_only=passive_only,
                active_only=active_only,
            )[:limit_modules_per_entity]
            if not module_ids:
                continue
            count += 1

            for module_id in module_ids:
                module = get_module(module_id)
                if module is None:
                    continue
                options: dict[str, Any] = {
                    "operating_context": PERSONAL_LAB,
                    "personal_lab_confirmed": personal_lab_confirmed,
                }
                if module_id == "infra_nmap":
                    options["nmap_options"] = nmap_options
                result = execute_module(
                    module_id,
                    value,
                    options=options,
                    db_context=conn,
                    authorisation_confirmed=personal_lab_confirmed,
                    case_id=case_id,
                    entity_id=entity["id"],
                    run_mode_id="capture_followup",
                    run_mode_label="Capture follow-up",
                )
                result["target"] = value
                results.append(result)
    finally:
        conn.close()
    return results


def run_suggested_for_entity(
    case_id: int,
    item: dict[str, Any],
    *,
    personal_lab_confirmed: bool = True,
) -> list[dict[str, Any]]:
    """Run all runnable suggested modules for one ranked entity."""
    return run_modules_for_ranked_entities(
        case_id,
        [item],
        personal_lab_confirmed=personal_lab_confirmed,
        limit_entities=1,
        limit_modules_per_entity=6,
        ignore_tier=True,
    )


def queue_passive_for_entity(case_id: int, item: dict[str, Any]) -> tuple[int, list[str]]:
    """Queue passive modules for a single ranked entity."""
    return queue_passive_for_ranked_entities(case_id, [item], tiers=(item.get("tier") or "investigate", "review"))


def build_recon_progress_summary(
    capture_result: dict[str, Any],
    followup_results: list[dict[str, Any]],
) -> dict[str, Any]:
    """Aggregate capture + follow-up runs into a recon progress snapshot."""
    completed = sum(1 for row in followup_results if row.get("success"))
    findings = sum(len(row.get("interpreter_findings") or []) for row in followup_results)
    modules = sorted({str(row.get("module_id")) for row in followup_results if row.get("module_id")})
    targets = sorted({str(row.get("target") or "") for row in followup_results if row.get("target")})
    return {
        "capture_summary": capture_result.get("summary") or "",
        "modules_run": len(followup_results),
        "modules_completed": completed,
        "modules_failed": len(followup_results) - completed,
        "total_findings": findings,
        "module_ids": modules,
        "targets": targets,
        "ready_for_deeper_review": completed > 0,
    }

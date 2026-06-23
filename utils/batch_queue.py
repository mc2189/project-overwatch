"""Batch queue helpers for controlled entity/module pivot runs."""

from __future__ import annotations

import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

from database.db_setup import create_or_get_entity, infer_entity_type
from modules.executor import execute_module
from modules.module_registry import ModuleEntry, get_module, is_executable
from utils.entity_pivot import entity_execution_target, entity_target_type
from utils.module_compatibility import get_incompatible_reason
from utils.nmap_options import PROFILE_STANDARD, default_options_for_profile
from utils.result_status import normalize_run_status

PASSIVE_BATCH_MODULE_IDS: tuple[str, ...] = (
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
)

ACTIVE_BATCH_MODULE_IDS: tuple[str, ...] = ("infra_nmap",)

QUEUE_STATUSES: tuple[str, ...] = (
    "queued",
    "running",
    "completed",
    "completed_with_warnings",
    "blocked",
    "error",
)

TERMINAL_QUEUE_STATUSES: frozenset[str] = frozenset(
    {"completed", "completed_with_warnings", "blocked", "error"}
)

SESSION_QUEUE_KEY = "batch_queue_by_case"
SESSION_RESULTS_KEY = "batch_queue_latest_results"
SESSION_STOP_KEY = "batch_queue_stop_after_current"
DEFAULT_COURTESY_DELAY_SECONDS = 1.5


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_timestamp(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def get_case_queue(queue_store: dict[str, list[dict[str, Any]]], case_id: int) -> list[dict[str, Any]]:
    """Return queue items for a case from session storage."""
    return list(queue_store.get(str(case_id), []))


def set_case_queue(
    queue_store: dict[str, list[dict[str, Any]]],
    case_id: int,
    items: list[dict[str, Any]],
) -> dict[str, list[dict[str, Any]]]:
    """Replace queue items for a case."""
    updated = dict(queue_store)
    updated[str(case_id)] = items
    return updated


def queue_pair_key(case_id: int, entity_id: int, module_id: str) -> tuple[int, int, str]:
    return (case_id, entity_id, module_id)


def is_duplicate_queue_item(
    items: list[dict[str, Any]],
    case_id: int,
    entity_id: int,
    module_id: str,
) -> bool:
    """Return True when the entity/module pair is already queued (non-terminal items count)."""
    key = queue_pair_key(case_id, entity_id, module_id)
    for item in items:
        if queue_pair_key(item["case_id"], item["entity_id"], item["module_id"]) != key:
            continue
        if item.get("status", "queued") == "queued":
            return True
    return False


def find_recent_operation(
    operations: list[dict[str, Any]],
    *,
    module_id: str,
    target: str,
    within_hours: int = 24,
) -> dict[str, Any] | None:
    """Return the most recent matching operation within the lookback window."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=within_hours)
    target_norm = target.strip().lower()
    best: dict[str, Any] | None = None
    best_time: datetime | None = None

    for operation in operations:
        if operation.get("module_id") != module_id:
            continue
        op_target = (operation.get("target") or "").strip().lower()
        if op_target != target_norm:
            continue
        started = _parse_timestamp(operation.get("started_at") or operation.get("completed_at"))
        if started is None or started < cutoff:
            continue
        if best_time is None or started > best_time:
            best = operation
            best_time = started
    return best


def build_queue_item(
    case_id: int,
    entity: dict[str, Any],
    module: ModuleEntry,
) -> dict[str, Any]:
    """Build a queue item dictionary for an entity/module pair."""
    from utils.settings_manager import active_modules_enabled, module_api_key_status

    execution_target = entity_execution_target(entity)
    target_type = entity_target_type(entity)
    incompatible = get_incompatible_reason(module, target_type)

    if module.mode == "active" and not active_modules_enabled():
        incompatible = (
            "Active modules are disabled in settings "
            "(PROJECT_OVERWATCH_ENABLE_ACTIVE_MODULES=false)."
        )

    if module.requires_api_key and not incompatible:
        key_status = module_api_key_status(module)
        if not key_status["configured"]:
            missing = ", ".join(key_status["missing_keys"])
            incompatible = f"Missing required API key(s): {missing}. Add them to your local .env file."

    return {
        "queue_id": str(uuid.uuid4()),
        "case_id": case_id,
        "entity_id": entity["id"],
        "entity_value": entity.get("value") or execution_target,
        "entity_type": entity.get("entity_type") or "unknown",
        "execution_target": execution_target,
        "module_id": module.module_id,
        "module_display_name": module.display_name,
        "mode": module.mode,
        "compatibility_status": "compatible" if not incompatible else incompatible,
        "status": "queued",
        "position": 0,
        "created_at": _now_iso(),
        "completed_at": None,
        "summary": "",
        "recent_run_warning": None,
    }


def module_recommendations_for_entity(entity: dict[str, Any]) -> list[dict[str, Any]]:
    """Return module recommendation rows for an entity using compatibility helpers."""
    from utils.entity_pivot import build_pivot_recommendations

    pivot = build_pivot_recommendations(entity)
    rows: list[dict[str, Any]] = []
    for row in pivot.get("module_rows") or []:
        module = get_module(row["module_id"])
        if module is None:
            continue
        rows.append(
            {
                **row,
                "mode": module.mode,
                "requires_authorisation": module.requires_authorisation,
                "is_passive_default": module.module_id in PASSIVE_BATCH_MODULE_IDS,
            }
        )
    return rows


def add_queue_item(
    items: list[dict[str, Any]],
    case_id: int,
    entity: dict[str, Any],
    module_id: str,
    operations: list[dict[str, Any]] | None = None,
    *,
    warn_recent_hours: int = 24,
) -> tuple[list[dict[str, Any]], dict[str, Any] | None, str | None]:
    """
    Append a queue item if not duplicate.

    Returns (updated_items, added_item_or_none, skip_reason_or_none).
    """
    module = get_module(module_id)
    if module is None or not is_executable(module):
        return items, None, f"{module_id} is not available."

    if is_duplicate_queue_item(items, case_id, entity["id"], module_id):
        return items, None, "Already queued for this entity and module."

    from utils.settings_manager import max_batch_items

    queued_count = sum(1 for item in items if item.get("status", "queued") == "queued")
    if queued_count >= max_batch_items():
        return items, None, f"Batch queue limit reached ({max_batch_items()} items)."

    item = build_queue_item(case_id, entity, module)
    item["position"] = len(items)
    if operations:
        recent = find_recent_operation(
            operations,
            module_id=module_id,
            target=item["execution_target"],
            within_hours=warn_recent_hours,
        )
        if recent:
            item["recent_run_warning"] = (
                f"This module ran against {item['execution_target']} recently "
                f"(operation #{recent.get('id', '?')})."
            )

    return items + [item], item, None


def add_passive_modules_for_entity(
    items: list[dict[str, Any]],
    case_id: int,
    entity: dict[str, Any],
    operations: list[dict[str, Any]] | None = None,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]], list[str]]:
    """Add all compatible passive default modules for an entity."""
    added: list[dict[str, Any]] = []
    skipped: list[str] = []
    current = items
    recommendations = module_recommendations_for_entity(entity)
    passive_ids = [
        row["module_id"]
        for row in recommendations
        if row.get("compatible") and row["module_id"] in PASSIVE_BATCH_MODULE_IDS
    ]
    for module_id in passive_ids:
        current, item, reason = add_queue_item(
            current,
            case_id,
            entity,
            module_id,
            operations=operations,
        )
        if item:
            added.append(item)
        elif reason:
            skipped.append(f"{entity.get('value', entity['id'])} / {module_id}: {reason}")
    return current, added, skipped


def remove_queue_item(items: list[dict[str, Any]], queue_id: str) -> list[dict[str, Any]]:
    return [item for item in items if item.get("queue_id") != queue_id]


def clear_queue_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return []


def clear_completed_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    remaining = [item for item in items if item.get("status", "queued") not in TERMINAL_QUEUE_STATUSES]
    for position, item in enumerate(remaining):
        item["position"] = position
    return remaining


def sort_queue_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return items sorted by position."""
    return sorted(items, key=lambda item: (item.get("position", 0), item.get("created_at", "")))


def passive_queued_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        item
        for item in items
        if item.get("status") == "queued"
        and item.get("mode") == "passive"
        and item.get("compatibility_status") == "compatible"
    ]


def selectable_queued_items(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        item
        for item in items
        if item.get("status") == "queued" and item.get("compatibility_status") == "compatible"
    ]


def map_result_to_queue_status(result: dict[str, Any]) -> str:
    """Map executor result status to batch queue item status."""
    status = normalize_run_status(result.get("status"))
    if status == "partial":
        return "completed_with_warnings"
    if status in TERMINAL_QUEUE_STATUSES:
        return status
    if result.get("success"):
        return "completed"
    return "error"


def execute_queue_items(
    case_id: int,
    items: list[dict[str, Any]],
    queue_ids: list[str],
    *,
    db_conn: Any,
    authorisation_confirmed: bool = False,
    nmap_options: dict[str, Any] | None = None,
    delay_seconds: float = DEFAULT_COURTESY_DELAY_SECONDS,
    stop_after_first: bool = False,
    sleep_fn: Callable[[float], None] = time.sleep,
    run_mode_label: str = "Batch Queue",
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """
    Execute queued items one at a time via execute_module.

    Returns (updated_items, result_rows).
    Continues after individual failures. Applies courtesy delay between passive runs.
    """
    id_set = set(queue_ids)
    results: list[dict[str, Any]] = []
    updated = list(items)
    nmap_options = nmap_options or default_options_for_profile(PROFILE_STANDARD)
    ran_passive = False
    executed_count = 0

    for index, item in enumerate(updated):
        if item.get("queue_id") not in id_set:
            continue
        if item.get("status") != "queued":
            continue
        if stop_after_first and executed_count >= 1:
            break
        if item.get("compatibility_status") != "compatible":
            item = {**item, "status": "blocked", "summary": item.get("compatibility_status", "Incompatible")}
            updated[index] = item
            results.append({"queue_item": item, "result": None})
            continue

        module = get_module(item["module_id"])
        if module is None:
            item = {**item, "status": "blocked", "summary": "Module not registered."}
            updated[index] = item
            results.append({"queue_item": item, "result": None})
            continue

        if module.requires_authorisation and not authorisation_confirmed:
            item = {
                **item,
                "status": "blocked",
                "summary": "Active module requires authorisation confirmation.",
            }
            updated[index] = item
            results.append({"queue_item": item, "result": None})
            continue

        if ran_passive and module.mode == "passive" and delay_seconds > 0:
            sleep_fn(delay_seconds)

        item = {**item, "status": "running", "summary": "Running..."}
        updated[index] = item

        target_value = item.get("execution_target") or item.get("entity_value") or ""
        entity_row = create_or_get_entity(
            case_id,
            infer_entity_type(target_value),
            target_value,
            label=item.get("entity_value") or target_value,
            source="batch_queue",
            conn=db_conn,
        )
        options: dict[str, Any] = {}
        if item["module_id"] == "infra_nmap":
            options = {"nmap_options": nmap_options}

        result = execute_module(
            item["module_id"],
            target_value,
            options=options,
            db_context=db_conn,
            authorisation_confirmed=authorisation_confirmed,
            case_id=case_id,
            entity_id=entity_row["id"],
            run_mode_id="batch_queue",
            run_mode_label=run_mode_label,
        )

        queue_status = map_result_to_queue_status(result)
        item = {
            **item,
            "status": queue_status,
            "completed_at": _now_iso(),
            "summary": result.get("summary") or queue_status,
        }
        updated[index] = item
        results.append({"queue_item": item, "result": result})
        executed_count += 1

        if module.mode == "passive":
            ran_passive = True

        if stop_after_first:
            break

    return updated, results

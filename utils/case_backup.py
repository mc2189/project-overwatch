"""Case backup export and import for local migration."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from database.db_setup import (
    create_case,
    create_evidence_item,
    create_finding,
    link_evidence_to_finding,
    create_observation,
    create_operation_log,
    create_or_get_entity,
    create_relationship,
    get_db_conn,
    add_to_pivot_queue,
    list_entities,
    list_evidence_finding_links,
    list_evidence_items,
    list_findings,
    list_observations,
    list_operations,
    list_pivot_queue,
    list_batch_queue_items,
    list_relationships,
    sync_batch_queue_items,
    get_case,
)
from utils.rdap_cache import export_rdap_cache_for_case, import_rdap_cache_entries


def export_case_bundle(case_id: int) -> dict[str, Any]:
    """Export a case and related records as a JSON-serialisable bundle."""
    conn = get_db_conn()
    try:
        case = get_case(case_id, conn=conn)
        if case is None:
            raise ValueError(f"Case {case_id} not found.")
        return {
            "overwatch_export_version": 1,
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "case": case,
            "entities": list_entities(case_id=case_id, conn=conn),
            "relationships": list_relationships(case_id=case_id, conn=conn),
            "observations": list_observations(case_id=case_id, conn=conn),
            "operations": list_operations(case_id=case_id, conn=conn),
            "findings": list_findings(case_id=case_id, conn=conn),
            "pivot_queue": list_pivot_queue(case_id=case_id, conn=conn),
            "batch_queue_items": list_batch_queue_items(case_id=case_id, conn=conn),
            "evidence_items": list_evidence_items(case_id=case_id, conn=conn),
            "evidence_finding_links": list_evidence_finding_links(case_id=case_id, conn=conn),
            "rdap_lookup_cache": export_rdap_cache_for_case(case_id, conn=conn),
        }
    finally:
        conn.close()


def export_case_bundle_json(case_id: int) -> str:
    return json.dumps(export_case_bundle(case_id), indent=2, default=str)


def import_case_bundle(bundle: dict[str, Any], *, new_case_name: str | None = None) -> dict[str, Any]:
    """
    Import a case bundle into a new case.

    Entity IDs are remapped; relationships and foreign keys are rebuilt.
    """
    if bundle.get("overwatch_export_version") != 1:
        raise ValueError("Unsupported or missing overwatch_export_version.")

    source_case = bundle.get("case") or {}
    name = new_case_name or f"{source_case.get('name', 'Imported case')} (imported)"
    description = source_case.get("description")
    if description:
        description = f"{description}\n\nImported at {datetime.now(timezone.utc).isoformat()}."
    else:
        description = f"Imported at {datetime.now(timezone.utc).isoformat()}."

    conn = get_db_conn()
    try:
        new_case = create_case(name, description, conn=conn)
        case_id = new_case["id"]
        id_map: dict[int, int] = {}
        observation_id_map: dict[int, int] = {}
        finding_id_map: dict[int, int] = {}
        evidence_id_map: dict[int, int] = {}

        for entity in bundle.get("entities", []):
            created = create_or_get_entity(
                case_id,
                entity.get("entity_type", "unknown"),
                entity.get("value", ""),
                label=entity.get("label"),
                source=entity.get("source"),
                confidence=entity.get("confidence", 50),
                conn=conn,
            )
            id_map[entity["id"]] = created["id"]

        for relationship in bundle.get("relationships", []):
            source_id = id_map.get(relationship.get("source_entity_id"))
            target_id = id_map.get(relationship.get("target_entity_id"))
            if source_id is None or target_id is None:
                continue
            create_relationship(
                case_id,
                source_id,
                relationship.get("relationship_type", "related"),
                target_id,
                source_module=relationship.get("source_module"),
                confidence=relationship.get("confidence", 50),
                evidence_type=relationship.get("evidence_type"),
                reliability=relationship.get("reliability"),
                conn=conn,
            )

        for observation in bundle.get("observations", []):
            entity_id = id_map.get(observation.get("entity_id"))
            if entity_id is None:
                continue
            created_observation = create_observation(
                case_id,
                entity_id,
                observation.get("module_id", "unknown"),
                observation.get("observation_type", "imported"),
                observation.get("title", "Imported observation"),
                summary=observation.get("summary"),
                data_json=observation.get("data_json"),
                raw_output=observation.get("raw_output"),
                evidence_type=observation.get("evidence_type"),
                source_name=observation.get("source_name"),
                source_url=observation.get("source_url"),
                reliability=observation.get("reliability"),
                collection_method=observation.get("collection_method"),
                collected_at=observation.get("collected_at"),
                module_version=observation.get("module_version"),
                conn=conn,
            )
            if observation.get("id") is not None:
                observation_id_map[int(observation["id"])] = created_observation["id"]

        for operation in bundle.get("operations", []):
            create_operation_log(
                case_id,
                operation.get("module_id", "unknown"),
                operation.get("target", ""),
                operation.get("status", "imported"),
                authorisation_confirmed=bool(operation.get("authorisation_confirmed")),
                summary=operation.get("summary"),
                run_mode_id=operation.get("run_mode_id"),
                run_mode_label=operation.get("run_mode_label"),
                conn=conn,
            )

        for finding in bundle.get("findings", []):
            entity_id = id_map.get(finding.get("entity_id")) if finding.get("entity_id") else None
            actions = finding.get("suggested_actions_json")
            if isinstance(actions, str):
                try:
                    actions_list = json.loads(actions)
                except json.JSONDecodeError:
                    actions_list = []
            else:
                actions_list = finding.get("suggested_actions") or []
            created_finding = create_finding(
                case_id,
                finding.get("module_id", "unknown"),
                finding.get("title", "Imported finding"),
                finding.get("severity", "info"),
                int(finding.get("confidence", 50)),
                finding.get("explanation", ""),
                actions_list,
                entity_id=entity_id,
                observation_id=observation_id_map.get(finding.get("observation_id"))
                if finding.get("observation_id")
                else None,
                status=finding.get("status", "open"),
                evidence_type=finding.get("evidence_type"),
                source_name=finding.get("source_name"),
                reliability=finding.get("reliability"),
                conn=conn,
            )
            if finding.get("id") is not None:
                finding_id_map[int(finding["id"])] = created_finding["id"]

        for item in bundle.get("evidence_items", []):
            entity_id = id_map.get(item.get("entity_id")) if item.get("entity_id") else None
            observation_id = (
                observation_id_map.get(item.get("observation_id"))
                if item.get("observation_id")
                else None
            )
            finding_id = finding_id_map.get(item.get("finding_id")) if item.get("finding_id") else None
            if entity_id is None:
                continue
            created_item = create_evidence_item(
                case_id,
                item.get("module_id", "unknown"),
                item.get("title", "Imported evidence item"),
                summary=item.get("summary"),
                content_text=item.get("content_text"),
                content_type=item.get("content_type") or "text/plain",
                entity_id=entity_id,
                observation_id=observation_id,
                finding_id=finding_id,
                evidence_type=item.get("evidence_type"),
                source_name=item.get("source_name"),
                source_url=item.get("source_url"),
                collection_method=item.get("collection_method"),
                reliability=item.get("reliability"),
                confidence=item.get("confidence"),
                storage_path=item.get("storage_path"),
                captured_at=item.get("captured_at"),
                conn=conn,
            )
            if item.get("id") is not None:
                evidence_id_map[int(item["id"])] = created_item["id"]

        for link in bundle.get("evidence_finding_links", []):
            evidence_id = evidence_id_map.get(link.get("evidence_id"))
            finding_id = finding_id_map.get(link.get("finding_id"))
            if evidence_id is None or finding_id is None:
                continue
            link_evidence_to_finding(evidence_id, finding_id, conn=conn)

        for queue_item in bundle.get("pivot_queue", []):
            entity_id = id_map.get(queue_item.get("entity_id"))
            if entity_id is not None:
                add_to_pivot_queue(case_id, entity_id, conn=conn)

        imported_batch_items = []
        for batch_item in bundle.get("batch_queue_items", []):
            mapped_entity_id = id_map.get(batch_item.get("entity_id"))
            if mapped_entity_id is None:
                continue
            imported_batch_items.append(
                {
                    **batch_item,
                    "case_id": case_id,
                    "entity_id": mapped_entity_id,
                }
            )
        if imported_batch_items:
            sync_batch_queue_items(case_id, imported_batch_items, conn=conn)

        cache_entries = bundle.get("rdap_lookup_cache") or []
        if cache_entries:
            import_rdap_cache_entries(case_id, cache_entries, conn=conn)

        return new_case
    finally:
        conn.close()


def parse_case_bundle_json(raw: str) -> dict[str, Any]:
    bundle = json.loads(raw)
    if not isinstance(bundle, dict):
        raise ValueError("Case bundle must be a JSON object.")
    return bundle

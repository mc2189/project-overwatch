"""Case backup export and import for local migration."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from database.db_setup import (
    create_case,
    create_finding,
    create_observation,
    create_operation_log,
    create_or_get_entity,
    create_relationship,
    get_db_conn,
    add_to_pivot_queue,
    list_entities,
    list_findings,
    list_observations,
    list_operations,
    list_pivot_queue,
    list_relationships,
    get_case,
)


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
                conn=conn,
            )

        for observation in bundle.get("observations", []):
            entity_id = id_map.get(observation.get("entity_id"))
            if entity_id is None:
                continue
            create_observation(
                case_id,
                entity_id,
                observation.get("module_id", "unknown"),
                observation.get("observation_type", "imported"),
                observation.get("title", "Imported observation"),
                summary=observation.get("summary"),
                data_json=observation.get("data_json"),
                raw_output=observation.get("raw_output"),
                conn=conn,
            )

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
            create_finding(
                case_id,
                finding.get("module_id", "unknown"),
                finding.get("title", "Imported finding"),
                finding.get("severity", "info"),
                int(finding.get("confidence", 50)),
                finding.get("explanation", ""),
                actions_list,
                entity_id=entity_id,
                observation_id=None,
                status=finding.get("status", "open"),
                conn=conn,
            )

        for queue_item in bundle.get("pivot_queue", []):
            entity_id = id_map.get(queue_item.get("entity_id"))
            if entity_id is not None:
                add_to_pivot_queue(case_id, entity_id, conn=conn)

        return new_case
    finally:
        conn.close()


def parse_case_bundle_json(raw: str) -> dict[str, Any]:
    bundle = json.loads(raw)
    if not isinstance(bundle, dict):
        raise ValueError("Case bundle must be a JSON object.")
    return bundle

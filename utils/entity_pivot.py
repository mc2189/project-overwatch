"""Entity pivot recommendations and execution target resolution."""

from __future__ import annotations

import re
from typing import Any

from modules.module_registry import ModuleEntry
from utils.module_compatibility import get_compatible_modules, get_incompatible_reason
from utils.target_detection import get_target_type, normalize_target_value, target_type_label

SERVICE_VALUE_PATTERN = re.compile(r"^(.+):(\d+)/(tcp|udp)$", re.IGNORECASE)


def parse_service_entity_details(entity: dict[str, Any]) -> dict[str, str] | None:
    """Extract host, port, and protocol from a service entity value."""
    value = (entity.get("value") or "").strip()
    match = SERVICE_VALUE_PATTERN.match(value)
    if not match:
        return None
    host, port, protocol = match.groups()
    details: dict[str, str] = {
        "host": host.strip(),
        "port": port,
        "protocol": protocol.lower(),
    }
    label = entity.get("label") or ""
    if label:
        parts = label.split(None, 2)
        if len(parts) >= 2 and parts[0] == f"{port}/{protocol.lower()}":
            if len(parts) >= 2:
                details["service"] = parts[1]
            if len(parts) >= 3:
                details["version"] = parts[2]
    return details


def entity_execution_target(entity: dict[str, Any]) -> str:
    """Resolve the module execution target string for an entity."""
    value = (entity.get("value") or "").strip()
    entity_type = (entity.get("entity_type") or "").strip().lower()

    if entity_type == "service":
        details = parse_service_entity_details(entity)
        if details:
            return details["host"]
        if ":" in value:
            return value.split(":", 1)[0]
    return value


def entity_target_type(entity: dict[str, Any]) -> str:
    """Detect target type for module compatibility from an entity."""
    execution_target = entity_execution_target(entity)
    entity_type = (entity.get("entity_type") or "").strip().lower()

    if entity_type == "email":
        return "email"
    if entity_type == "username":
        return "username"
    if entity_type == "ip_address":
        return "ipv4"
    if entity_type == "service":
        return get_target_type(entity_execution_target(entity))

    return get_target_type(execution_target)


def get_compatible_modules_for_entity(entity: dict[str, Any]) -> list[ModuleEntry]:
    """Return implemented modules compatible with this entity's execution target."""
    entity_type = (entity.get("entity_type") or "").strip().lower()
    if entity_type in {"email", "username"}:
        return []
    if entity_type == "service":
        return []

    execution_target = entity_execution_target(entity)
    if not execution_target.strip():
        return []
    return get_compatible_modules(execution_target)


def build_pivot_recommendations(
    entity: dict[str, Any],
    *,
    entities_by_value: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build pivot module recommendations and analyst suggestions for an entity."""
    entity_type = (entity.get("entity_type") or "").strip().lower()
    execution_target = entity_execution_target(entity)
    target_type = entity_target_type(entity)
    compatible = get_compatible_modules_for_entity(entity)
    suggestions: list[str] = []

    if entity_type == "service":
        details = parse_service_entity_details(entity)
        host = details["host"] if details else execution_target
        service_name = (details or {}).get("service", "").lower()
        port = (details or {}).get("port", "")
        if "ssh" in service_name or port == "22":
            suggestions.append(
                f"SSH service entity — run **SSH Configuration Review** against parent host `{host}` "
                f"on port {port or '22'} after confirming authorisation."
            )
        suggestions.append(
            f"No direct module targets service entities. Review the parent host `{host}` "
            "in Entity Workspace and run Network Service Check or passive modules there."
        )
        if entities_by_value and host in entities_by_value:
            parent = entities_by_value[host]
            suggestions.append(
                f"Parent host entity #{parent['id']} ({parent.get('label') or parent.get('value')}) "
                "is in this case — select it to pivot."
            )
    elif entity_type in {"email", "username"}:
        suggestions.append("No implemented modules yet for this entity type.")
    elif not compatible:
        suggestions.append(
            f"No compatible modules for target type {target_type_label(target_type)}."
        )
    elif target_type == "url":
        suggestions.append(
            "URL entities run against the normalised hostname for domain-oriented modules."
        )

    module_rows: list[dict[str, Any]] = []
    for module in compatible:
        reason = get_incompatible_reason(module, target_type)
        module_rows.append(
            {
                "module_id": module.module_id,
                "display_name": module.display_name,
                "mode": module.mode,
                "requires_authorisation": module.requires_authorisation,
                "compatible": not reason,
                "incompatible_reason": reason or None,
            }
        )

    normalized_target = (
        normalize_target_value(execution_target, target_type) if execution_target.strip() else ""
    )

    return {
        "entity_type": entity_type,
        "execution_target": execution_target,
        "normalized_target": normalized_target,
        "target_type": target_type,
        "target_type_label": target_type_label(target_type),
        "compatible_modules": compatible,
        "module_rows": module_rows,
        "suggestions": suggestions,
        "service_details": parse_service_entity_details(entity),
    }


def filter_operations_for_entity(
    operations: list[dict[str, Any]],
    entity: dict[str, Any],
) -> list[dict[str, Any]]:
    """Return operations whose target matches the entity execution value."""
    execution_target = entity_execution_target(entity).strip().lower()
    entity_value = (entity.get("value") or "").strip().lower()
    if not execution_target and not entity_value:
        return []

    matched: list[dict[str, Any]] = []
    for operation in operations:
        op_target = (operation.get("target") or "").strip().lower()
        if not op_target:
            continue
        if op_target in {execution_target, entity_value}:
            matched.append(operation)
            continue
        if entity_target_type(entity) in {"domain", "url", "ipv4"}:
            normalized = normalize_target_value(
                operation.get("target") or "",
                get_target_type(operation.get("target") or ""),
            ).lower()
            if normalized and normalized in {execution_target, entity_value}:
                matched.append(operation)
    return matched


def split_relationships_for_entity(
    entity_id: int,
    relationships: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split relationships into outgoing (from) and incoming (to) for an entity."""
    outgoing = [
        relationship
        for relationship in relationships
        if relationship.get("source_entity_id") == entity_id
    ]
    incoming = [
        relationship
        for relationship in relationships
        if relationship.get("target_entity_id") == entity_id
    ]
    return outgoing, incoming


def get_entity_neighbour_ids(
    entity_id: int,
    relationships: list[dict[str, Any]],
) -> set[int]:
    """Return entity ids directly connected to the given entity."""
    neighbours: set[int] = set()
    for relationship in relationships:
        source_id = relationship.get("source_entity_id")
        target_id = relationship.get("target_entity_id")
        if source_id == entity_id and target_id is not None:
            neighbours.add(target_id)
        elif target_id == entity_id and source_id is not None:
            neighbours.add(source_id)
    return neighbours

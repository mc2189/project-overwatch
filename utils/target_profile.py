"""Target profile helper for the guided assessment workspace."""

from __future__ import annotations

from typing import Any

from database.db_setup import (
    ACTIVE_FINDING_STATUSES,
    get_db_conn,
    list_entities,
    list_findings,
    list_operations,
    list_relationships,
)
from utils.assessment_goals import suggested_goals_for_target
from utils.module_compatibility import get_compatible_modules
from utils.module_testing_levels import get_module_testing_level, is_active_testing_level
from utils.service_discovery import load_discovered_services
from utils.target_detection import get_target_type, normalize_target_value, target_type_label
from utils.web_port_planner import is_private_ipv4_target, local_ip_triage_message

_MODULE_FAMILIES: dict[str, str] = {
    "infra_nmap": "Network services",
    "infra_tls_review": "TLS / certificates",
    "infra_http_security": "HTTP security",
    "infra_domain_intel": "Domain intelligence",
    "infra_cert_subdomain": "Subdomains / CT",
    "infra_website_metadata": "Website metadata",
    "infra_email_security": "Email security",
    "infra_whois_rdap": "Registration / RDAP",
    "intel_virustotal": "Reputation",
    "intel_abuseipdb": "Reputation",
    "intel_greynoise": "Reputation",
    "intel_shodan": "Exposure",
    "intel_urlhaus": "Malware URLs",
}


def _entity_matches_target(entity: dict[str, Any], target: str, normalized: str) -> bool:
    value = (entity.get("value") or "").strip().lower()
    label = (entity.get("label") or "").strip().lower()
    needle = target.strip().lower()
    norm = normalized.lower() if normalized else needle
    return value in {needle, norm} or label in {needle, norm}


def build_target_profile(
    case_id: int,
    target: str,
    *,
    conn: Any | None = None,
) -> dict[str, Any]:
    """Build a compact target profile for the workspace."""
    cleaned = target.strip()
    target_type = get_target_type(cleaned) if cleaned else "unknown"
    normalized = normalize_target_value(cleaned, target_type) if cleaned else ""

    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()

    try:
        entities = list_entities(case_id, conn=conn)
        matching = [
            entity
            for entity in entities
            if cleaned and _entity_matches_target(entity, cleaned, normalized)
        ]
        known_entity = matching[0] if matching else None
        entity_id = known_entity["id"] if known_entity else None

        operations = list_operations(case_id, conn=conn)
        target_ops = [
            op
            for op in operations
            if cleaned
            and (
                (op.get("target") or "").strip().lower() == cleaned.lower()
                or (normalized and (op.get("target") or "").strip().lower() == normalized.lower())
            )
        ]

        findings = list_findings(case_id, conn=conn)
        open_findings = [
            finding
            for finding in findings
            if (finding.get("status") or "open") in ACTIVE_FINDING_STATUSES
            and entity_id is not None
            and finding.get("entity_id") == entity_id
        ]

        related_count = 0
        if entity_id is not None:
            relationships = list_relationships(case_id, conn=conn)
            related_ids: set[int] = set()
            for rel in relationships:
                if rel.get("source_entity_id") == entity_id:
                    related_ids.add(int(rel["target_entity_id"]))
                elif rel.get("target_entity_id") == entity_id:
                    related_ids.add(int(rel["source_entity_id"]))
            related_count = len(related_ids)

        compatible = get_compatible_modules(cleaned) if cleaned else []
        families: list[str] = []
        seen_families: set[str] = set()
        for module in compatible:
            family = _MODULE_FAMILIES.get(module.module_id, module.mode.title())
            if family not in seen_families:
                seen_families.add(family)
                families.append(family)

        passive_count = sum(
            1 for module in compatible if not is_active_testing_level(get_module_testing_level(module.module_id))
        )
        active_count = len(compatible) - passive_count

        services: list[dict[str, Any]] = []
        has_service_data = False
        if is_private_ipv4_target(cleaned):
            services = load_discovered_services(case_id, cleaned, conn=conn)
            has_service_data = bool(services)

        return {
            "target": cleaned,
            "target_type": target_type,
            "target_type_label": target_type_label(target_type),
            "normalized": normalized,
            "known_in_case": known_entity is not None,
            "entity_id": entity_id,
            "entity_label": known_entity.get("label") if known_entity else None,
            "operations_count": len(target_ops),
            "open_findings_count": len(open_findings),
            "related_entities_count": related_count,
            "compatible_module_count": len(compatible),
            "compatible_passive_count": passive_count,
            "compatible_active_count": active_count,
            "compatible_module_families": families,
            "suggested_goals": suggested_goals_for_target(target_type, cleaned),
            "compatible_module_ids": [module.module_id for module in compatible],
            "is_private_ipv4": is_private_ipv4_target(cleaned),
            "has_service_data": has_service_data,
            "discovered_service_count": len(services),
            "triage_message": local_ip_triage_message(has_service_data=has_service_data)
            if is_private_ipv4_target(cleaned)
            else None,
        }
    finally:
        if own_conn and conn is not None:
            conn.close()

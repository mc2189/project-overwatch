"""Case memory aggregation and baseline snapshot builders."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from database.db_setup import (
    ACTIVE_FINDING_STATUSES,
    TERMINAL_FINDING_STATUSES,
    effective_finding_severity,
    finding_status_counts,
    list_entities,
    list_expected_items,
    list_findings,
    get_latest_case_baseline,
    list_observations,
    list_operations,
    normalize_finding_status,
)
from utils.entity_pivot import parse_service_entity_details
from utils.memory_keys import finding_fingerprint, finding_row_fingerprint
from utils.remote_access_classifier import filter_remote_access_services, nmap_ports_to_service_rows

MEMORY_VERSION = "2.34"


def _parse_observation_payload(observation: dict[str, Any]) -> dict[str, Any]:
    data_json = observation.get("data_json")
    if not data_json:
        return {}
    try:
        return json.loads(data_json) if isinstance(data_json, str) else dict(data_json)
    except (TypeError, json.JSONDecodeError):
        return {}


def _service_key(host: str, port: Any, protocol: str = "tcp") -> str:
    return f"{host.strip().lower()}:{int(port)}/{protocol.lower()}"


def _entity_temporal(entity_id: int, observations: list[dict[str, Any]]) -> tuple[str | None, str | None, list[str]]:
    seen_at: list[str] = []
    modules: set[str] = set()
    for observation in observations:
        if observation.get("entity_id") != entity_id:
            continue
        created = observation.get("created_at")
        if created:
            seen_at.append(str(created))
        module_id = observation.get("module_id")
        if module_id:
            modules.add(str(module_id))
    if not seen_at:
        return None, None, sorted(modules)
    seen_at.sort()
    return seen_at[0], seen_at[-1], sorted(modules)


def build_case_memory(case_id: int, *, conn: Any) -> dict[str, Any]:
    """Build a lightweight in-memory view of case knowledge from existing records."""
    entities = list_entities(case_id=case_id, conn=conn)
    findings = list_findings(case_id=case_id, conn=conn)
    observations = list_observations(case_id=case_id, conn=conn)
    operations = list_operations(case_id=case_id, conn=conn)
    expected_items = list_expected_items(case_id, conn=conn)
    latest_baseline = get_latest_case_baseline(case_id, conn=conn)

    expected_keys = {(row["item_type"], row["item_key"]) for row in expected_items}
    entity_by_id = {entity["id"]: entity for entity in entities}

    known_targets: dict[str, dict[str, Any]] = {}
    known_devices: dict[str, dict[str, Any]] = {}
    known_services: dict[str, dict[str, Any]] = {}
    known_domains: dict[str, dict[str, Any]] = {}
    known_hostnames: dict[str, dict[str, Any]] = {}
    known_macs: dict[str, dict[str, Any]] = {}
    known_technologies: dict[str, dict[str, Any]] = {}
    known_web_paths: dict[str, dict[str, Any]] = {}
    known_remote_access: dict[str, dict[str, Any]] = {}
    public_contacts: dict[str, dict[str, Any]] = {}
    sensitive_metadata: dict[str, dict[str, Any]] = {}

    for entity in entities:
        entity_id = entity["id"]
        first_seen, last_seen, modules = _entity_temporal(entity_id, observations)
        base = {
            "entity_id": entity_id,
            "value": entity.get("value"),
            "label": entity.get("label"),
            "first_seen": first_seen or entity.get("created_at"),
            "last_seen": last_seen or entity.get("updated_at") or entity.get("created_at"),
            "source_modules": modules,
            "notes": entity.get("notes"),
        }
        entity_type = (entity.get("entity_type") or "").lower()
        value = (entity.get("value") or "").strip()
        key = value.lower()
        if entity_type in {"ip_address", "ipv4"} and value:
            known_targets[key] = base
            known_devices[key] = {**base, "type": "ip"}
        elif entity_type == "domain" and value:
            known_domains[key] = base
        elif entity_type == "hostname" and value:
            known_hostnames[key] = base
        elif entity_type == "service" and value:
            details = parse_service_entity_details(entity) or {}
            host = details.get("host") or value.split(":", 1)[0]
            service_key = _service_key(host, details.get("port") or "0", details.get("protocol") or "tcp")
            known_services[service_key] = {
                **base,
                "host": host,
                "port": details.get("port"),
                "protocol": details.get("protocol"),
                "service": details.get("service"),
            }

    for observation in observations:
        module_id = observation.get("module_id") or ""
        payload = _parse_observation_payload(observation)
        created = observation.get("created_at")

        if module_id == "infra_nmap":
            host = payload.get("primary_ip") or payload.get("host") or payload.get("target") or ""
            for row in payload.get("parsed_ports") or []:
                try:
                    port = int(row.get("port"))
                except (TypeError, ValueError):
                    continue
                service_key = _service_key(str(host), port, str(row.get("protocol") or "tcp"))
                known_services[service_key] = {
                    "host": str(host),
                    "port": port,
                    "protocol": row.get("protocol") or "tcp",
                    "service": row.get("service"),
                    "product": row.get("product"),
                    "version": row.get("version"),
                    "last_seen": created,
                    "source_modules": ["infra_nmap"],
                }
            for row in filter_remote_access_services(nmap_ports_to_service_rows(payload.get("parsed_ports") or [])):
                ra_key = _service_key(str(host), row.get("port") or 0)
                known_remote_access[ra_key] = {
                    **row,
                    "host": str(host),
                    "last_seen": created,
                    "source_module": "infra_nmap",
                }

        if module_id in {"net_pcap_review", "net_live_capture"}:
            pcap_payload = payload
            if module_id == "net_live_capture":
                pcap_payload = (payload.get("pcap_review") or {}).get("parsed_data") or payload
            for device in pcap_payload.get("lan_devices") or pcap_payload.get("devices") or []:
                ip_value = str(device.get("ip") or device.get("ipv4") or "").strip()
                if not ip_value:
                    continue
                known_devices[ip_value.lower()] = {
                    "ip": ip_value,
                    "mac": device.get("mac"),
                    "hostname": device.get("hostname"),
                    "role_hint": device.get("role_hint") or device.get("iot_role"),
                    "last_seen": created,
                    "source_modules": [module_id],
                }
                if device.get("mac"):
                    known_macs[str(device["mac"]).lower()] = {
                        "mac": device.get("mac"),
                        "ip": ip_value,
                        "last_seen": created,
                    }
                if device.get("hostname"):
                    known_hostnames[str(device["hostname"]).lower()] = {
                        "hostname": device.get("hostname"),
                        "ip": ip_value,
                        "last_seen": created,
                    }
            preview = pcap_payload.get("entities_preview") or {}
            for domain in preview.get("domains") or []:
                known_domains[str(domain).lower()] = {"domain": str(domain), "last_seen": created, "source_module": module_id}
            for ip_value in preview.get("ips") or []:
                public_contacts[str(ip_value).lower()] = {"value": str(ip_value), "kind": "ip", "last_seen": created}

        if module_id == "evidence_file_metadata":
            for row in payload.get("files") or []:
                flags = row.get("privacy_flags") or {}
                if not (flags.get("gps_present") or flags.get("author_present") or flags.get("company_present")):
                    continue
                filename = str(row.get("filename") or "file")
                fingerprint = f"evidence_file_metadata|{filename.lower()}"
                sensitive_metadata[fingerprint] = {
                    "filename": filename,
                    "fingerprint": fingerprint,
                    "privacy_flags": flags,
                    "last_seen": created,
                    "source_module": module_id,
                }

        if module_id == "infra_web_stack_identifier":
            target = payload.get("requested_url") or payload.get("target") or ""
            for indicator in payload.get("indicators") or []:
                tech_key = f"{target}:{indicator.get('name') or indicator.get('category')}".lower()
                known_technologies[tech_key] = {
                    "target": target,
                    "name": indicator.get("name"),
                    "category": indicator.get("category"),
                    "version": indicator.get("version"),
                    "last_seen": created,
                }

        if module_id == "infra_web_path_review":
            base_url = payload.get("base_url") or payload.get("requested_url") or ""
            for row in payload.get("path_results") or []:
                path = row.get("path") or "/"
                path_key = f"{base_url.rstrip('/')}{path}".lower()
                known_web_paths[path_key] = {
                    "url": path_key,
                    "status_code": row.get("status_code"),
                    "notable": row.get("notable"),
                    "category": row.get("category"),
                    "last_seen": created,
                }

    finding_rows = []
    accepted_findings = []
    open_findings = []
    for finding in findings:
        status = normalize_finding_status(finding.get("status"))
        severity = effective_finding_severity(finding)
        entity = entity_by_id.get(finding.get("entity_id") or -1) or {}
        row = {
            "finding_id": finding.get("id"),
            "title": finding.get("title"),
            "fingerprint": finding_fingerprint(finding),
            "severity": severity,
            "status": status,
            "module_id": finding.get("module_id"),
            "entity_value": entity.get("value"),
            "updated_at": finding.get("updated_at") or finding.get("created_at"),
        }
        finding_rows.append(row)
        if status in ACTIVE_FINDING_STATUSES:
            open_findings.append(row)
        if status in {"accepted", "false_positive"} or (finding.get("id"), "finding") in {
            (item.get("finding_id"), "finding") for item in expected_items if item.get("finding_id")
        }:
            accepted_findings.append(row)

    return {
        "case_id": case_id,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "latest_baseline": {
            "baseline_id": latest_baseline.get("baseline_id") if latest_baseline else None,
            "name": latest_baseline.get("name") if latest_baseline else None,
            "updated_at": latest_baseline.get("updated_at") if latest_baseline else None,
        },
        "counts": {
            "entities": len(entities),
            "observations": len(observations),
            "operations": len(operations),
            "findings": len(findings),
            "expected_items": len(expected_items),
            **finding_status_counts(case_id, conn=conn),
        },
        "known_targets": list(known_targets.values()),
        "known_devices": list(known_devices.values()),
        "known_services": list(known_services.values()),
        "known_domains": list(known_domains.values()),
        "known_hostnames": list(known_hostnames.values()),
        "known_macs": list(known_macs.values()),
        "known_technologies": list(known_technologies.values()),
        "known_web_paths": list(known_web_paths.values()),
        "known_remote_access": list(known_remote_access.values()),
        "public_contacts": list(public_contacts.values()),
        "sensitive_metadata": list(sensitive_metadata.values()),
        "findings": finding_rows,
        "open_findings": open_findings,
        "accepted_findings": accepted_findings,
        "expected_keys": sorted([f"{item_type}:{item_key}" for item_type, item_key in expected_keys]),
    }


def build_baseline_snapshot(case_id: int, *, conn: Any, name: str | None = None) -> dict[str, Any]:
    """Summarise current case state for baseline storage."""
    memory = build_case_memory(case_id, conn=conn)
    findings = memory.get("findings") or []
    return {
        "version": MEMORY_VERSION,
        "generated_at": memory.get("generated_at"),
        "name": name or "Case baseline",
        "devices": memory.get("known_devices") or [],
        "services": memory.get("known_services") or [],
        "domains": memory.get("known_domains") or [],
        "hostnames": memory.get("known_hostnames") or [],
        "macs": memory.get("known_macs") or [],
        "web_technologies": memory.get("known_technologies") or [],
        "web_paths": memory.get("known_web_paths") or [],
        "remote_access_services": memory.get("known_remote_access") or [],
        "public_contacts": memory.get("public_contacts") or [],
        "sensitive_metadata": memory.get("sensitive_metadata") or [],
        "findings": findings,
        "finding_counts": memory.get("counts") or {},
        "lan_devices": memory.get("known_devices") or [],
    }


def entity_memory_view(
    entity: dict[str, Any],
    *,
    case_id: int,
    conn: Any,
) -> dict[str, Any]:
    """Return memory-oriented details for a single entity."""
    observations = list_observations(case_id=case_id, entity_id=entity["id"], conn=conn)
    findings = list_findings(case_id=case_id, entity_id=entity["id"], conn=conn)
    expected_items = list_expected_items(case_id, conn=conn)
    first_seen, last_seen, modules = _entity_temporal(entity["id"], observations)
    value = (entity.get("value") or "").strip().lower()
    entity_type = (entity.get("entity_type") or "").lower()
    expected = any(
        row.get("entity_id") == entity["id"]
        or (row.get("item_key") == value and row.get("item_type") in {entity_type, "device", "service"})
        for row in expected_items
    )
    for finding in findings:
        if normalize_finding_status(finding.get("status")) in TERMINAL_FINDING_STATUSES:
            expected = expected or normalize_finding_status(finding.get("status")) in {"accepted", "false_positive"}
    return {
        "entity_id": entity["id"],
        "first_seen": first_seen or entity.get("created_at"),
        "last_seen": last_seen or entity.get("updated_at") or entity.get("created_at"),
        "source_modules": modules,
        "finding_count": len(findings),
        "open_finding_count": sum(
            1 for finding in findings if normalize_finding_status(finding.get("status")) in ACTIVE_FINDING_STATUSES
        ),
        "expected": expected,
        "notes": entity.get("notes"),
    }


def finding_memory_label(finding: dict[str, Any], *, baseline_findings: list[dict[str, Any]] | None = None) -> str:
    """Return a concise memory label for a finding."""
    status = normalize_finding_status(finding.get("status"))
    if status in {"accepted", "false_positive"}:
        return status.replace("_", " ")
    if status == "closed":
        return "resolved"
    fingerprint = finding_fingerprint(finding)
    baseline_keys = {finding_row_fingerprint(row) for row in baseline_findings or []}
    baseline_titles = {(row.get("title") or "").strip().lower() for row in baseline_findings or []}
    title = (finding.get("title") or "").strip().lower()
    if fingerprint in baseline_keys or title in baseline_titles:
        return "repeated"
    return "new"

"""Load discovered service observations for an IP target from case data."""

from __future__ import annotations

import json
import re
from typing import Any

from database.db_setup import list_entities, list_observations, list_operations
from utils.nmap_parser import parse_nmap_open_ports
from utils.service_classifier import (
    CLASS_HTTP_CANDIDATE,
    CLASS_HTTPS_CANDIDATE,
    CLASS_TLS_CANDIDATE,
    CLASS_NON_WEB_SERVICE,
    CLASS_UNKNOWN_SERVICE,
    classify_service_observation,
    classification_label,
    recommended_checks_for_classification,
    service_advisory_label,
)
from utils.target_detection import get_target_type, normalize_target_value

_SERVICE_ENTITY_RE = re.compile(r"^(.+):(\d+)/(tcp|udp)$", re.IGNORECASE)


def _parse_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _service_key(port: int, protocol: str) -> tuple[int, str]:
    return port, protocol.lower()


def _merge_service(
    services: dict[tuple[int, str], dict[str, Any]],
    entry: dict[str, Any],
) -> None:
    port = _parse_port(entry.get("port"))
    if port is None:
        return
    protocol = str(entry.get("protocol") or "tcp").lower()
    key = _service_key(port, protocol)
    existing = services.get(key)
    if existing is None:
        services[key] = entry
        return
    for field in ("service_name", "product", "banner", "source_module", "observation_text"):
        if not existing.get(field) and entry.get(field):
            existing[field] = entry[field]
    existing["prior_tls_handshake"] = bool(
        existing.get("prior_tls_handshake") or entry.get("prior_tls_handshake")
    )
    existing["prior_certificate"] = bool(
        existing.get("prior_certificate") or entry.get("prior_certificate")
    )
    existing["prior_http_response"] = bool(
        existing.get("prior_http_response") or entry.get("prior_http_response")
    )


def _classify_entry(entry: dict[str, Any]) -> dict[str, Any]:
    classification = classify_service_observation(
        port=int(entry["port"]),
        protocol=entry.get("protocol") or "tcp",
        service_name=entry.get("service_name"),
        product=entry.get("product"),
        banner=entry.get("banner"),
        observation_text=entry.get("observation_text"),
        module_source=entry.get("source_module"),
        prior_tls_handshake=bool(entry.get("prior_tls_handshake")),
        prior_certificate=bool(entry.get("prior_certificate")),
        prior_http_response=bool(entry.get("prior_http_response")),
    )
    check_label, reason = recommended_checks_for_classification(classification)
    enriched = dict(entry)
    enriched["classification"] = classification
    enriched["classification_label"] = classification_label(classification)
    enriched["recommended_check"] = check_label
    enriched["recommendation_reason"] = reason
    if classification == CLASS_NON_WEB_SERVICE:
        enriched["advisory"] = service_advisory_label(entry.get("service_name"), int(entry["port"]))
    return enriched


def build_http_url(host: str, port: int, *, scheme: str = "http") -> str:
    if (scheme == "https" and port == 443) or (scheme == "http" and port == 80):
        return f"{scheme}://{host}/"
    return f"{scheme}://{host}:{port}/"


def scheme_for_classification(classification: str, port: int) -> str:
    if classification in {CLASS_HTTPS_CANDIDATE, CLASS_TLS_CANDIDATE}:
        return "https"
    if classification == CLASS_HTTP_CANDIDATE:
        return "http"
    if port in {443, 8443, 9443}:
        return "https"
    return "http"


def load_discovered_services(
    case_id: int,
    target: str,
    *,
    conn: Any,
    latest_results: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Return classified service rows discovered for an IPv4 target."""
    cleaned = target.strip()
    if get_target_type(cleaned) != "ipv4":
        return []

    normalized = normalize_target_value(cleaned, "ipv4")
    services: dict[tuple[int, str], dict[str, Any]] = {}

    for entity in list_entities(case_id, conn=conn):
        if entity.get("entity_type") != "service":
            continue
        value = entity.get("value") or ""
        match = _SERVICE_ENTITY_RE.match(value)
        if not match:
            continue
        host, port_text, protocol = match.groups()
        if host.strip().lower() not in {cleaned.lower(), normalized.lower()}:
            continue
        port = _parse_port(port_text)
        if port is None:
            continue
        label = entity.get("label") or ""
        parts = label.split()
        service_name = parts[1] if len(parts) > 1 else ""
        _merge_service(
            services,
            {
                "port": port,
                "protocol": protocol,
                "service_name": service_name,
                "product": " ".join(parts[2:]) if len(parts) > 2 else "",
                "source_module": entity.get("source") or "entity",
            },
        )

    entity_ids = {
        entity["id"]
        for entity in list_entities(case_id, conn=conn)
        if (entity.get("value") or "").strip().lower() in {cleaned.lower(), normalized.lower()}
    }

    for observation in list_observations(case_id=case_id, conn=conn):
        entity_id = observation.get("entity_id")
        if entity_id is not None and entity_id not in entity_ids:
            continue
        module_id = observation.get("module_id") or ""
        obs_type = observation.get("observation_type") or ""
        if module_id not in {"infra_nmap", "infra_tls_review", "infra_http_security"} and obs_type != "network_scan":
            continue
        raw_json = observation.get("data_json")
        if not raw_json:
            continue
        try:
            data = json.loads(raw_json) if isinstance(raw_json, str) else raw_json
        except (json.JSONDecodeError, TypeError):
            continue
        for port_info in data.get("parsed_ports") or []:
            _merge_service(
                services,
                {
                    "port": port_info.get("port"),
                    "protocol": port_info.get("protocol") or "tcp",
                    "service_name": port_info.get("service"),
                    "product": port_info.get("version"),
                    "source_module": observation.get("module_id") or "infra_nmap",
                },
            )

    for operation in list_operations(case_id, conn=conn):
        if (operation.get("target") or "").strip().lower() not in {cleaned.lower(), normalized.lower()}:
            continue
        if operation.get("module_id") != "infra_nmap":
            continue
        summary = operation.get("summary") or ""
        for port_info in parse_nmap_open_ports(summary):
            _merge_service(
                services,
                {
                    "port": port_info.get("port"),
                    "protocol": port_info.get("protocol") or "tcp",
                    "service_name": port_info.get("service"),
                    "product": port_info.get("version"),
                    "source_module": "infra_nmap",
                    "observation_text": summary[:500],
                },
            )

    for result in latest_results or []:
        module_id = result.get("module_id") or ""
        parsed = result.get("parsed_data") or {}
        if module_id == "infra_nmap":
            for port_info in parsed.get("parsed_ports") or []:
                _merge_service(
                    services,
                    {
                        "port": port_info.get("port"),
                        "protocol": port_info.get("protocol") or "tcp",
                        "service_name": port_info.get("service"),
                        "product": port_info.get("version"),
                        "source_module": "infra_nmap",
                    },
                )
        elif module_id == "infra_tls_review":
            conn_info = parsed.get("connection") or {}
            if conn_info.get("success"):
                port = _parse_port(parsed.get("port")) or 443
                _merge_service(
                    services,
                    {
                        "port": port,
                        "protocol": "tcp",
                        "service_name": "https" if port in {443, 8443, 9443} else "ssl",
                        "source_module": "infra_tls_review",
                        "prior_tls_handshake": True,
                        "prior_certificate": bool((parsed.get("certificate") or {}).get("subject")),
                    },
                )
        elif module_id == "infra_http_security":
            response = parsed.get("response") or {}
            if response.get("success"):
                port = _parse_port(parsed.get("port")) or 443
                scheme = (parsed.get("scheme") or "https").lower()
                _merge_service(
                    services,
                    {
                        "port": port,
                        "protocol": "tcp",
                        "service_name": scheme,
                        "source_module": "infra_http_security",
                        "prior_http_response": True,
                    },
                )

    classified = [_classify_entry(entry) for entry in services.values()]
    classified.sort(key=lambda row: (int(row["port"]), row.get("protocol", "tcp")))
    return classified


def has_actionable_service_data(services: list[dict[str, Any]]) -> bool:
    return bool(services)


def web_tls_service_rows(services: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [
        row
        for row in services
        if row.get("classification")
        in {CLASS_HTTP_CANDIDATE, CLASS_HTTPS_CANDIDATE, CLASS_TLS_CANDIDATE}
    ]


def build_service_recommendation_table(services: list[dict[str, Any]], host: str) -> list[dict[str, Any]]:
    """Rows for journey UI: port, service, classification, recommended check, reason."""
    rows: list[dict[str, Any]] = []
    for service in services:
        port = int(service["port"])
        scheme = scheme_for_classification(service["classification"], port)
        rows.append(
            {
                "port": port,
                "protocol": service.get("protocol") or "tcp",
                "detected_service": service.get("service_name") or "unknown",
                "classification": service.get("classification_label"),
                "recommended_check": service.get("recommended_check"),
                "reason": service.get("recommendation_reason"),
                "http_url": build_http_url(host, port, scheme=scheme),
                "classification_code": service.get("classification"),
                "advisory": service.get("advisory"),
            }
        )
    return rows

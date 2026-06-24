"""Suppress follow-up actions for expected / known-good case items."""

from __future__ import annotations

from typing import Any

from database.db_setup import is_expected_item
from utils.memory_keys import device_item_key, finding_fingerprint, service_item_key
from utils.remote_access_classifier import filter_remote_access_services, nmap_ports_to_service_rows


def _host_from_target(target: str) -> str:
    return str(target or "").strip().lower().split(":")[0]


def is_nmap_followup_expected(
    case_id: int,
    action: dict[str, Any],
    *,
    target: str,
    parsed: dict[str, Any],
    conn: Any,
) -> bool:
    """Return True when an Nmap follow-up should be suppressed as expected."""
    module_id = action.get("module_id")
    host = _host_from_target(target)
    ports = parsed.get("parsed_ports") or []

    if is_expected_item(case_id, item_type="device", item_key=host, conn=conn):
        if module_id in {"infra_ssh_review", "infra_remote_access_review", "infra_http_security", "infra_tls_review"}:
            return True

    if module_id == "infra_ssh_review":
        for row in ports:
            try:
                port_num = int(row.get("port"))
            except (TypeError, ValueError):
                continue
            service = str(row.get("service") or "").lower()
            if service == "ssh" or port_num == 22:
                key = service_item_key(host, port_num, str(row.get("protocol") or "tcp"))
                if is_expected_item(case_id, item_type="service", item_key=key, conn=conn):
                    return True
                if is_expected_item(case_id, item_type="remote_access", item_key=key, conn=conn):
                    return True
        return False

    if module_id == "infra_remote_access_review":
        remote_rows = filter_remote_access_services(nmap_ports_to_service_rows(ports))
        if not remote_rows:
            return is_expected_item(case_id, item_type="remote_access", item_key=host, conn=conn)
        for row in remote_rows:
            key = service_item_key(host, row.get("port") or 0, str(row.get("protocol") or "tcp"))
            if not is_expected_item(case_id, item_type="remote_access", item_key=key, conn=conn):
                if not is_expected_item(case_id, item_type="service", item_key=key, conn=conn):
                    return False
        return True

    return False


def is_pcap_followup_expected(
    case_id: int,
    action: dict[str, Any],
    *,
    conn: Any,
) -> bool:
    """Return True when a PCAP investigation follow-up targets an expected device/IP."""
    target = str(action.get("target") or "").strip().lower()
    if not target:
        return False
    module_id = action.get("module_id")
    if module_id == "infra_nmap" and is_expected_item(case_id, item_type="device", item_key=target, conn=conn):
        return True
    if module_id == "infra_nmap" and is_expected_item(case_id, item_type="service", item_key=target, conn=conn):
        return True
    return is_expected_item(case_id, item_type="device", item_key=device_item_key(target), conn=conn)


def is_finding_followup_expected(
    case_id: int,
    finding: dict[str, Any],
    *,
    conn: Any,
) -> bool:
    fingerprint = finding_fingerprint(finding)
    if is_expected_item(case_id, item_type="finding", item_key=fingerprint, conn=conn):
        return True
    title = (finding.get("title") or "").strip().lower()
    return bool(title) and is_expected_item(case_id, item_type="finding", item_key=title, conn=conn)


def filter_nmap_followup_actions(
    actions: list[dict[str, Any]],
    *,
    case_id: int | None,
    target: str,
    parsed: dict[str, Any],
    conn: Any | None,
) -> list[dict[str, Any]]:
    if case_id is None or conn is None or case_id <= 0:
        return actions
    return [
        action
        for action in actions
        if not is_nmap_followup_expected(case_id, action, target=target, parsed=parsed, conn=conn)
    ]


def filter_pcap_followup_actions(
    actions: list[dict[str, Any]],
    *,
    case_id: int,
    conn: Any,
) -> list[dict[str, Any]]:
    if case_id <= 0:
        return actions
    return [
        action
        for action in actions
        if not is_pcap_followup_expected(case_id, action, conn=conn)
    ]


def filter_autopilot_actions(
    actions: list[dict[str, Any]],
    *,
    case_id: int | None,
    target: str,
    latest_results: list[dict[str, Any]],
    conn: Any | None,
) -> list[dict[str, Any]]:
    if case_id is None or conn is None or case_id <= 0:
        return actions

    parsed_by_module = {
        result.get("module_id"): result.get("parsed_data") or {}
        for result in latest_results
        if result.get("success")
    }
    filtered: list[dict[str, Any]] = []
    for action in actions:
        module_id = action.get("module_id")
        action_target = action.get("target") or target
        if module_id in {"infra_ssh_review", "infra_remote_access_review", "infra_http_security", "infra_tls_review"}:
            parsed = parsed_by_module.get("infra_nmap") or {}
            if is_nmap_followup_expected(
                case_id,
                action,
                target=action_target,
                parsed=parsed,
                conn=conn,
            ):
                continue
        if module_id == "infra_nmap" and is_pcap_followup_expected(case_id, action, conn=conn):
            continue
        filtered.append(action)
    return filtered

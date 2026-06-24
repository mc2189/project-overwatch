"""Baseline comparison and change detection for Project Overwatch."""

from __future__ import annotations

from typing import Any

from database.db_setup import (
    ACTIVE_FINDING_STATUSES,
    get_latest_case_baseline,
    is_expected_item,
    normalize_finding_status,
)
from utils.case_memory import build_baseline_snapshot, build_case_memory
from utils.memory_keys import finding_row_fingerprint

CHANGE_IMPORTANCE = {
    "new_device": "medium",
    "missing_device": "low",
    "new_ip": "medium",
    "new_hostname": "info",
    "new_mac": "info",
    "new_service": "high",
    "closed_service": "medium",
    "new_remote_access_service": "high",
    "new_web_technology": "info",
    "removed_web_technology": "info",
    "new_finding": "high",
    "resolved_finding": "info",
    "repeated_finding": "info",
    "accepted_finding_present": "info",
    "new_public_contact": "medium",
    "new_sensitive_metadata": "high",
    "new_web_path_response": "medium",
}


def _index_by_key(rows: list[dict[str, Any]], *key_fields: str) -> dict[str, dict[str, Any]]:
    indexed: dict[str, dict[str, Any]] = {}
    for row in rows:
        parts = [str(row.get(field) or "").strip().lower() for field in key_fields if row.get(field) not in (None, "")]
        if not parts:
            continue
        key = "|".join(parts)
        indexed[key] = row
    return indexed


def _device_key(row: dict[str, Any]) -> str:
    return str(row.get("ip") or row.get("value") or "").strip().lower()


def _service_key(row: dict[str, Any]) -> str:
    host = str(row.get("host") or row.get("ip") or row.get("value") or "").strip().lower()
    port = row.get("port")
    protocol = str(row.get("protocol") or "tcp").lower()
    if host and port is not None:
        return f"{host}:{port}/{protocol}"
    return host


def _make_change(
    *,
    change_type: str,
    title: str,
    summary: str,
    target: str | None = None,
    previous: Any = None,
    current: Any = None,
    severity: str | None = None,
    suggested_action: str | None = None,
    source_module: str | None = None,
    expected: bool = False,
) -> dict[str, Any]:
    return {
        "change_type": change_type,
        "title": title,
        "summary": summary,
        "target": target,
        "previous_state": previous,
        "current_state": current,
        "severity": severity or CHANGE_IMPORTANCE.get(change_type, "info"),
        "importance": severity or CHANGE_IMPORTANCE.get(change_type, "info"),
        "suggested_action": suggested_action,
        "source_module": source_module,
        "expected": expected,
        "category": _change_category(change_type, expected=expected),
    }


def _change_category(change_type: str, *, expected: bool) -> str:
    if expected:
        return "expected"
    if change_type in {"resolved_finding", "closed_service", "missing_device", "removed_web_technology"}:
        return "resolved"
    if change_type in {"repeated_finding", "accepted_finding_present"}:
        return "expected"
    if change_type.startswith("new_"):
        return "new"
    return "changed"


def compare_baseline_to_current(
    case_id: int,
    *,
    baseline_summary: dict[str, Any] | None = None,
    current_summary: dict[str, Any] | None = None,
    conn: Any,
) -> dict[str, Any]:
    """Compare a baseline snapshot to the current case state."""
    if baseline_summary is None:
        baseline_row = get_latest_case_baseline(case_id, conn=conn)
        baseline_summary = (baseline_row or {}).get("summary") or {}
    if current_summary is None:
        current_summary = build_baseline_snapshot(case_id, conn=conn)

    if not baseline_summary:
        return {
            "baseline_id": None,
            "baseline_name": None,
            "has_baseline": False,
            "changes": [],
            "grouped": {"new": [], "changed": [], "resolved": [], "expected": []},
            "summary_text": "No baseline exists yet — create one after a meaningful assessment run.",
        }

    changes: list[dict[str, Any]] = []

    baseline_devices = _index_by_key(baseline_summary.get("devices") or baseline_summary.get("lan_devices") or [], "ip", "value")
    current_devices = _index_by_key(current_summary.get("devices") or current_summary.get("lan_devices") or [], "ip", "value")
    for key, row in current_devices.items():
        if key not in baseline_devices:
            expected = is_expected_item(case_id, item_type="device", item_key=key, conn=conn)
            hostname = row.get("hostname") or ""
            role = row.get("role_hint") or ""
            detail = f"{row.get('ip') or key}"
            if hostname:
                detail += f", hostname {hostname}"
            if role:
                detail += f", role hint {role}"
            changes.append(
                _make_change(
                    change_type="new_device",
                    title=f"New LAN device observed: {row.get('ip') or key}",
                    summary=f"New LAN device observed: {detail}. This was not in the previous baseline.",
                    target=row.get("ip") or key,
                    current=row,
                    suggested_action="Review whether the device is expected on this network.",
                    source_module="net_pcap_review",
                    expected=expected,
                )
            )
    for key, row in baseline_devices.items():
        if key not in current_devices:
            expected = is_expected_item(case_id, item_type="device", item_key=key, conn=conn)
            changes.append(
                _make_change(
                    change_type="missing_device",
                    title=f"Device not seen this time: {row.get('ip') or key}",
                    summary=f"Device {row.get('ip') or key} was in the baseline but was not observed in the latest capture or service data.",
                    target=row.get("ip") or key,
                    previous=row,
                    suggested_action="Confirm whether the device was offline or out of capture scope.",
                    expected=expected,
                )
            )

    baseline_hostnames = _index_by_key(baseline_summary.get("hostnames") or [], "hostname")
    current_hostnames = _index_by_key(current_summary.get("hostnames") or [], "hostname")
    for key, row in current_hostnames.items():
        if key not in baseline_hostnames:
            changes.append(
                _make_change(
                    change_type="new_hostname",
                    title=f"New hostname observed: {row.get('hostname') or key}",
                    summary=f"Hostname {row.get('hostname') or key} was not recorded in the previous baseline.",
                    target=row.get("hostname") or key,
                    current=row,
                    suggested_action="Confirm whether the hostname belongs to an expected device.",
                    source_module="net_pcap_review",
                )
            )

    baseline_macs = _index_by_key(baseline_summary.get("macs") or [], "mac")
    current_macs = _index_by_key(current_summary.get("macs") or [], "mac")
    for key, row in current_macs.items():
        if key not in baseline_macs:
            changes.append(
                _make_change(
                    change_type="new_mac",
                    title=f"New MAC observed: {row.get('mac') or key}",
                    summary=f"MAC address {row.get('mac') or key} was not in the previous baseline.",
                    target=row.get("mac") or key,
                    current=row,
                    suggested_action="Review whether the device is expected on this network.",
                    source_module="net_pcap_review",
                )
            )

    def _tech_key(row: dict[str, Any]) -> str:
        return f"{row.get('target') or ''}:{row.get('name') or ''}".strip(":").lower()

    baseline_tech = {_tech_key(row): row for row in baseline_summary.get("web_technologies") or [] if _tech_key(row)}
    current_tech = {_tech_key(row): row for row in current_summary.get("web_technologies") or [] if _tech_key(row)}
    for key, row in current_tech.items():
        if key not in baseline_tech:
            expected = is_expected_item(case_id, item_type="technology", item_key=key, conn=conn)
            changes.append(
                _make_change(
                    change_type="new_web_technology",
                    title=f"New web technology: {row.get('name') or key}",
                    summary=f"Web technology {row.get('name') or key} was not in the previous baseline.",
                    target=key,
                    current=row,
                    suggested_action="Review whether the technology is expected for this target.",
                    source_module="infra_web_stack_identifier",
                    expected=expected,
                )
            )
    for key, row in baseline_tech.items():
        if key not in current_tech:
            changes.append(
                _make_change(
                    change_type="removed_web_technology",
                    title=f"Web technology no longer observed: {row.get('name') or key}",
                    summary=f"Technology {row.get('name') or key} was in the baseline but not observed recently.",
                    target=key,
                    previous=row,
                    source_module="infra_web_stack_identifier",
                )
            )

    baseline_services = {_service_key(row): row for row in baseline_summary.get("services") or [] if _service_key(row)}
    current_services = {_service_key(row): row for row in current_summary.get("services") or [] if _service_key(row)}
    for key, row in current_services.items():
        if key not in baseline_services:
            expected = is_expected_item(case_id, item_type="service", item_key=key, conn=conn)
            product = " ".join(
                part
                for part in (row.get("service"), row.get("product"), row.get("version"))
                if part
            ).strip()
            changes.append(
                _make_change(
                    change_type="new_service",
                    title=f"New service observed: {key}",
                    summary=(
                        f"New service observed: {key}"
                        + (f" ({product})" if product else "")
                        + ". This was not in the previous baseline."
                    ),
                    target=key.split("/")[0].split(":")[0] if key else None,
                    current=row,
                    suggested_action="Run targeted follow-up review on the new service.",
                    source_module="infra_nmap",
                    expected=expected,
                )
            )
        else:
            previous = baseline_services[key]
            prev_product = " ".join(
                part for part in (previous.get("product"), previous.get("version")) if part
            ).strip()
            curr_product = " ".join(part for part in (row.get("product"), row.get("version")) if part).strip()
            if prev_product and curr_product and prev_product != curr_product:
                changes.append(
                    _make_change(
                        change_type="changed_service",
                        title=f"Service version changed: {key}",
                        summary=f"Service {key} product/version changed from {prev_product} to {curr_product}.",
                        target=key,
                        previous=prev_product,
                        current=curr_product,
                        suggested_action="Review whether the service change is expected.",
                        source_module="infra_nmap",
                    )
                )
    for key, row in baseline_services.items():
        if key not in current_services:
            expected = is_expected_item(case_id, item_type="service", item_key=key, conn=conn)
            changes.append(
                _make_change(
                    change_type="closed_service",
                    title=f"Service no longer observed: {key}",
                    summary=f"Service {key} was open in the baseline but was not observed in the latest review.",
                    target=key.split("/")[0].split(":")[0] if key else None,
                    previous=row,
                    suggested_action="Confirm whether the service was closed, filtered, or simply not rescanned.",
                    source_module="infra_nmap",
                    expected=expected,
                )
            )

    baseline_remote = {_service_key(row): row for row in baseline_summary.get("remote_access_services") or [] if _service_key(row)}
    current_remote = {_service_key(row): row for row in current_summary.get("remote_access_services") or [] if _service_key(row)}
    for key, row in current_remote.items():
        if key not in baseline_remote:
            expected = is_expected_item(case_id, item_type="remote_access", item_key=key, conn=conn)
            changes.append(
                _make_change(
                    change_type="new_remote_access_service",
                    title=f"New remote access service: {key}",
                    summary=f"New remote access service observed at {key}. Review whether administration exposure is expected.",
                    target=key,
                    current=row,
                    suggested_action="Run Remote Access Exposure Review and add to report if material.",
                    source_module="infra_remote_access_review",
                    expected=expected,
                )
            )

    baseline_findings = {
        finding_row_fingerprint(row): row for row in baseline_summary.get("findings") or []
    }
    current_findings = current_summary.get("findings") or []
    for row in current_findings:
        fingerprint = finding_row_fingerprint(row)
        title_key = (row.get("title") or "").strip().lower()
        status = normalize_finding_status(row.get("status"))
        if status in ACTIVE_FINDING_STATUSES and fingerprint not in baseline_findings and title_key not in {
            (item.get("title") or "").strip().lower() for item in baseline_summary.get("findings") or []
        }:
            expected = is_expected_item(case_id, item_type="finding", item_key=fingerprint, conn=conn) or is_expected_item(
                case_id, item_type="finding", item_key=title_key, conn=conn
            )
            changes.append(
                _make_change(
                    change_type="new_finding",
                    title=f"New finding: {row.get('title')}",
                    summary=f"Finding '{row.get('title')}' was not present in the previous baseline.",
                    target=row.get("entity_value"),
                    current=row,
                    suggested_action="Review finding and update report if needed.",
                    source_module=row.get("module_id"),
                    expected=expected,
                )
            )
        elif fingerprint in baseline_findings and status in ACTIVE_FINDING_STATUSES:
            changes.append(
                _make_change(
                    change_type="repeated_finding",
                    title=f"Repeated finding: {row.get('title')}",
                    summary=f"Finding '{row.get('title')}' remains present since the previous baseline.",
                    target=row.get("entity_value"),
                    previous=baseline_findings[fingerprint],
                    current=row,
                    suggested_action="Review whether remediation is still required.",
                    source_module=row.get("module_id"),
                )
            )
        elif status in {"accepted", "false_positive"}:
            changes.append(
                _make_change(
                    change_type="accepted_finding_present",
                    title=f"Accepted finding still recorded: {row.get('title')}",
                    summary=f"Finding '{row.get('title')}' is marked {status} and remains in case memory.",
                    target=row.get("entity_value"),
                    current=row,
                    suggested_action="No action required unless context changed.",
                    source_module=row.get("module_id"),
                    expected=True,
                )
            )
    for fingerprint, row in baseline_findings.items():
        current_rows = [
            item
            for item in current_findings
            if finding_row_fingerprint(item) == fingerprint
            or (item.get("title") or "").strip().lower() == (row.get("title") or "").strip().lower()
        ]
        if current_rows:
            continue
        if normalize_finding_status(row.get("status")) in ACTIVE_FINDING_STATUSES:
            changes.append(
                _make_change(
                    change_type="resolved_finding",
                    title=f"Finding resolved since baseline: {row.get('title')}",
                    summary=f"Finding '{row.get('title')}' was active in the baseline but is no longer present.",
                    target=row.get("entity_value"),
                    previous=row,
                    suggested_action="Confirm closure in findings workflow.",
                    source_module=row.get("module_id"),
                )
            )

    baseline_sensitive = _index_by_key(baseline_summary.get("sensitive_metadata") or [], "fingerprint")
    current_sensitive = _index_by_key(current_summary.get("sensitive_metadata") or [], "fingerprint")
    for key, row in current_sensitive.items():
        if key not in baseline_sensitive:
            filename = row.get("filename") or key
            changes.append(
                _make_change(
                    change_type="new_sensitive_metadata",
                    title=f"New sensitive metadata: {filename}",
                    summary=f"Sensitive metadata observed in {filename} that was not in the previous baseline.",
                    target=filename,
                    current=row,
                    suggested_action="Review privacy impact before external reporting.",
                    source_module="evidence_file_metadata",
                )
            )

    baseline_public = _index_by_key(baseline_summary.get("public_contacts") or [], "value")
    current_public = _index_by_key(current_summary.get("public_contacts") or [], "value")
    for key, row in current_public.items():
        if key not in baseline_public:
            changes.append(
                _make_change(
                    change_type="new_public_contact",
                    title=f"New public contact observed: {row.get('value') or key}",
                    summary=f"Public IP/domain contact {row.get('value') or key} was not in the previous baseline.",
                    target=row.get("value") or key,
                    suggested_action="Review whether external contact is expected.",
                    source_module="net_pcap_review",
                )
            )

    baseline_paths = _index_by_key(baseline_summary.get("web_paths") or [], "url")
    current_paths = _index_by_key(current_summary.get("web_paths") or [], "url")
    for key, row in current_paths.items():
        if key not in baseline_paths and row.get("notable"):
            changes.append(
                _make_change(
                    change_type="new_web_path_response",
                    title=f"New notable web path response: {key}",
                    summary=f"Notable web path response observed at {key}.",
                    target=key,
                    current=row,
                    suggested_action="Review path exposure and add to report if material.",
                    source_module="infra_web_path_review",
                )
            )

    grouped = {"new": [], "changed": [], "resolved": [], "expected": []}
    for change in changes:
        grouped.setdefault(change.get("category") or "changed", []).append(change)

    notable = [change for change in changes if not change.get("expected") and change.get("category") == "new"]
    summary_text = (
        f"{len(notable)} new change(s), {len(grouped['resolved'])} resolved, "
        f"{len(grouped['expected'])} expected/accepted."
        if changes
        else "No material changes detected since the latest baseline."
    )

    return {
        "baseline_id": baseline_summary.get("baseline_id"),
        "baseline_name": baseline_summary.get("name"),
        "has_baseline": True,
        "changes": changes,
        "grouped": grouped,
        "summary_text": summary_text,
        "notable_changes": notable[:12],
    }


def compare_case_to_latest_baseline(case_id: int, *, conn: Any) -> dict[str, Any]:
    memory = build_case_memory(case_id, conn=conn)
    baseline_row = get_latest_case_baseline(case_id, conn=conn)
    comparison = compare_baseline_to_current(
        case_id,
        baseline_summary=(baseline_row or {}).get("summary"),
        conn=conn,
    )
    comparison["memory"] = memory
    comparison["baseline_updated_at"] = (baseline_row or {}).get("updated_at")
    return comparison

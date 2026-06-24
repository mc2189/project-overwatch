"""One-line baseline change hints for assessment result cards."""

from __future__ import annotations

from typing import Any


def baseline_hints_for_result(
    case_id: int,
    result: dict[str, Any],
    *,
    comparison: dict[str, Any] | None = None,
    conn: Any | None = None,
) -> list[str]:
    """Return short hint strings to show on a result card after a run."""
    if case_id <= 0:
        return []

    if comparison is None:
        if conn is None:
            from database.db_setup import get_db_conn

            conn = get_db_conn()
            own_conn = True
        else:
            own_conn = False
        try:
            from utils.baseline_compare import compare_case_to_latest_baseline

            comparison = compare_case_to_latest_baseline(case_id, conn=conn)
        finally:
            if own_conn:
                conn.close()

    if not comparison.get("has_baseline"):
        return []

    module_id = result.get("module_id") or ""
    changes = [
        change
        for change in comparison.get("changes") or []
        if not change.get("expected")
    ]
    hints: list[str] = []

    if module_id == "infra_nmap":
        new_services = [row for row in changes if row.get("change_type") == "new_service"]
        closed_services = [row for row in changes if row.get("change_type") == "closed_service"]
        changed_services = [row for row in changes if row.get("change_type") == "changed_service"]
        new_remote = [row for row in changes if row.get("change_type") == "new_remote_access_service"]
        if new_services:
            hints.append(f"{len(new_services)} new service(s) since baseline")
        if new_remote:
            hints.append(f"{len(new_remote)} new remote access service(s) since baseline")
        if changed_services:
            hints.append(f"{len(changed_services)} service version change(s) since baseline")
        if closed_services:
            hints.append(f"{len(closed_services)} service(s) no longer observed since baseline")

    elif module_id in {"net_pcap_review", "net_live_capture"}:
        new_devices = [row for row in changes if row.get("change_type") == "new_device"]
        missing_devices = [row for row in changes if row.get("change_type") == "missing_device"]
        new_contacts = [row for row in changes if row.get("change_type") == "new_public_contact"]
        if new_devices:
            sample = new_devices[0]
            detail = sample.get("target") or sample.get("title") or "device"
            extra = f" (+{len(new_devices) - 1} more)" if len(new_devices) > 1 else ""
            hints.append(f"New LAN device since baseline: {detail}{extra}")
        if missing_devices:
            hints.append(f"{len(missing_devices)} baseline device(s) not seen this capture")
        if new_contacts:
            hints.append(f"{len(new_contacts)} new public contact(s) since baseline")

    elif module_id == "evidence_file_metadata":
        new_meta = [row for row in changes if row.get("change_type") == "new_sensitive_metadata"]
        if new_meta:
            hints.append(f"{len(new_meta)} new sensitive metadata finding(s) since baseline")

    elif module_id == "infra_web_stack_identifier":
        new_tech = [row for row in changes if row.get("change_type") == "new_web_technology"]
        if new_tech:
            hints.append(f"{len(new_tech)} new web technology indicator(s) since baseline")

    return hints[:3]

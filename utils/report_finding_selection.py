"""Finding selection helpers for Report Builder v2."""

from __future__ import annotations

from typing import Any

from database.db_setup import REPORT_EXCLUDED_STATUSES, effective_finding_severity, normalize_finding_status
from utils.finding_interpreter import is_source_notice
from utils.report_types import FindingSelectionMode


def filter_findings_for_report(
    findings: list[dict[str, Any]],
    *,
    mode: FindingSelectionMode = "active",
    include_closed: bool = False,
    selected_ids: set[int] | frozenset[int] | None = None,
    module_filter: set[str] | frozenset[str] | None = None,
    severity_filter: set[str] | frozenset[str] | None = None,
) -> list[dict[str, Any]]:
    """Filter findings according to report selection rules."""
    selected_ids = set(selected_ids or [])
    module_filter = set(module_filter or [])
    severity_filter = {item.lower() for item in (severity_filter or set())}

    filtered: list[dict[str, Any]] = []
    for finding in findings:
        status = normalize_finding_status(finding.get("status"))
        severity = effective_finding_severity(finding).lower()

        if mode == "selected":
            if finding.get("id") not in selected_ids:
                continue
        elif mode == "all" or include_closed:
            pass
        elif mode == "active":
            if status in REPORT_EXCLUDED_STATUSES:
                continue
        else:
            if status in REPORT_EXCLUDED_STATUSES and not include_closed:
                continue

        if mode == "exclude_info":
            if severity == "info" or is_source_notice(finding):
                continue

        if mode == "by_module" and module_filter:
            if (finding.get("module_id") or "") not in module_filter:
                continue

        if mode == "by_severity" and severity_filter:
            if severity not in severity_filter:
                continue

        if mode not in {"exclude_info", "by_module", "by_severity", "selected", "all", "active"}:
            if status in REPORT_EXCLUDED_STATUSES and not include_closed:
                continue

        filtered.append({**finding, "severity": severity})
    return filtered

"""Combined run result summaries for Latest Results."""

from __future__ import annotations

from typing import Any

from ui.constants import SEVERITY_RANK
from utils.finding_interpreter import is_source_notice, risk_findings
from utils.result_status import (
    STATUS_BLOCKED,
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_WARNINGS,
    STATUS_ERROR,
    STATUS_PARTIAL,
    is_success_status,
    normalize_run_status,
)


def _highest_severity(findings: list[dict[str, Any]]) -> str | None:
    best = None
    best_rank = -1
    for finding in findings:
        severity = (finding.get("severity") or "info").lower()
        rank = SEVERITY_RANK.get(severity, 0)
        if rank > best_rank:
            best_rank = rank
            best = severity
    return best


def summarize_run_results(results: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a combined summary across module run results."""
    modules_run = len(results)
    completed = 0
    completed_with_warnings = 0
    partial = 0
    failed = 0
    warnings_count = 0
    total_findings = 0
    highest_severity = None
    best_rank = -1

    for result in results:
        status = normalize_run_status(result.get("status"))
        if status == STATUS_COMPLETED:
            completed += 1
        elif status == STATUS_COMPLETED_WITH_WARNINGS:
            completed_with_warnings += 1
        elif status == STATUS_PARTIAL:
            partial += 1
        elif status in {STATUS_ERROR, STATUS_BLOCKED} or not result.get("success"):
            failed += 1
        elif is_success_status(status):
            completed += 1

        warnings_count += len(result.get("warnings") or [])
        interpreter_findings = result.get("interpreter_findings") or []
        risk = risk_findings(interpreter_findings)
        total_findings += len(risk)
        severity = _highest_severity(risk)
        if severity:
            rank = SEVERITY_RANK.get(severity, 0)
            if rank > best_rank:
                best_rank = rank
                highest_severity = severity

    return {
        "modules_run": modules_run,
        "completed": completed,
        "completed_with_warnings": completed_with_warnings,
        "partial": partial,
        "failed": failed,
        "warnings_count": warnings_count,
        "total_findings": total_findings,
        "highest_severity": highest_severity,
    }

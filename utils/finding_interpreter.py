"""Shared helpers for module finding interpreters."""

from __future__ import annotations

from typing import Any

FINDING_KIND_OBSERVATION = "observation"
FINDING_KIND_SOURCE_NOTICE = "source_notice"

SOURCE_NOTICE_TITLES: frozenset[str] = frozenset(
    {
        "Certificate transparency source unavailable",
        "Certificate transparency lookup incomplete",
        "Wayback lookup unavailable",
        "Homepage metadata unavailable",
        "Website metadata collected with warnings",
    }
)


def make_finding(
    title: str,
    severity: str,
    confidence: int,
    explanation: str,
    suggested_actions: list[str],
    *,
    finding_kind: str = FINDING_KIND_OBSERVATION,
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "explanation": explanation,
        "suggested_actions": suggested_actions,
        "finding_kind": finding_kind,
    }


def is_source_notice(finding: dict[str, Any]) -> bool:
    if finding.get("finding_kind") == FINDING_KIND_SOURCE_NOTICE:
        return True
    return finding.get("title") in SOURCE_NOTICE_TITLES


def risk_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [finding for finding in findings if not is_source_notice(finding)]


def source_notice_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [finding for finding in findings if is_source_notice(finding)]

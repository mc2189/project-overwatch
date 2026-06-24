"""Advisory interpretation of controlled web path review results."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding
from utils.web_path_catalog import (
    CATEGORY_API_DOCS,
    CATEGORY_CMS,
    CATEGORY_LOGIN_ADMIN,
    CATEGORY_POLICY_INFO,
    CATEGORY_SENSITIVE,
    CATEGORY_STATUS_HEALTH,
    is_notable_response,
)


def _notable_rows(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    return [row for row in (parsed_data.get("path_results") or []) if is_notable_response(row)]


def interpret_web_path_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    base_url = parsed_data.get("base_url") or parsed_data.get("requested_url") or parsed_data.get("target") or "target"
    path_results = list(parsed_data.get("path_results") or [])
    reachable = bool(parsed_data.get("reachable"))
    checked = int(parsed_data.get("paths_checked") or len(path_results))
    notable = _notable_rows(parsed_data)

    if parsed_data.get("scope_blocked"):
        findings.append(
            make_finding(
                "Web path review could not complete",
                "info",
                90,
                parsed_data.get("scope_blocked_reason")
                or "Web path review was blocked before connecting.",
                ["Confirm scope and authorisation before retrying."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if not reachable and not path_results:
        findings.append(
            make_finding(
                "Web path review could not complete",
                "info",
                88,
                f"No HTTP responses were received from {base_url}. Path review could not proceed.",
                [
                    "Run Network Service Check to find the correct web port.",
                    "Try HTTP on an alternate port if service discovery shows one.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    findings.append(
        make_finding(
            "Web path review completed",
            "info",
            85,
            f"Controlled review of {checked} curated path(s) on {base_url} completed sequentially. "
            f"{len(notable)} notable response(s) observed — review whether paths are expected.",
            [
                "This is a small curated check, not a full site map.",
                "Validate notable paths against asset inventory and access-control expectations.",
            ],
            finding_kind=FINDING_KIND_SOURCE_NOTICE,
        )
    )

    if not notable:
        findings.append(
            make_finding(
                "No notable paths observed",
                "info",
                80,
                "Curated paths were checked, but no notable responses were observed beyond baseline behaviour.",
                ["Absence of a response does not prove a path is unavailable on other ports or hosts."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    category_findings = {
        CATEGORY_POLICY_INFO: ("Informational path observed", "info", 78),
        CATEGORY_LOGIN_ADMIN: ("Login/admin path observed", "low", 80),
        CATEGORY_API_DOCS: ("API documentation path observed", "low", 82),
        CATEGORY_STATUS_HEALTH: ("Status/health path observed", "low", 82),
        CATEGORY_SENSITIVE: ("Sensitive-name path responded", "medium", 85),
        CATEGORY_CMS: ("Common CMS path observed", "low", 80),
    }
    emitted: set[str] = set()
    for row in notable:
        category = row.get("category") or ""
        title, severity, confidence = category_findings.get(
            category,
            ("Informational path observed", "info", 75),
        )
        if title in emitted:
            continue
        emitted.add(title)
        path = row.get("path") or "path"
        status = row.get("status_code")
        explanation = (
            f"{path} responded with status {status}. "
            f"{row.get('note') or 'Review whether this path is expected and appropriately restricted.'}"
        )
        if category == CATEGORY_SENSITIVE:
            explanation += " Response metadata only — body content was not stored."
        findings.append(
            make_finding(
                title,
                severity,
                confidence,
                explanation,
                ["Review whether this path should be publicly reachable."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    return findings

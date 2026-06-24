"""Advisory interpretation of web stack identifier results."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding
from utils.web_stack_indicators import (
    CATEGORY_ANALYTICS,
    CATEGORY_CDN,
    CATEGORY_CMS,
    CATEGORY_HOSTING,
    CATEGORY_JS_FRAMEWORK,
    CATEGORY_WEB_SERVER,
)


def interpret_web_stack_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    response = parsed_data.get("response") or {}
    url = parsed_data.get("requested_url") or parsed_data.get("target") or "target"
    indicators = list(parsed_data.get("indicators") or [])
    headers = parsed_data.get("headers") or {}

    if parsed_data.get("scope_blocked"):
        findings.append(
            make_finding(
                "Web stack identifier could not complete",
                "info",
                90,
                parsed_data.get("scope_blocked_reason")
                or "Web stack identification was blocked before connecting.",
                ["Confirm scope and authorisation before retrying."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if not response.get("success"):
        error = response.get("error") or "no response"
        findings.append(
            make_finding(
                "Web stack identifier could not complete",
                "info",
                88,
                f"No HTTP response from {url} ({error}). This means stack indicators could not be collected.",
                [
                    "Run Network Service Check to find the correct web port.",
                    "Try HTTP on an alternate port if service discovery shows one.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if not indicators:
        findings.append(
            make_finding(
                "No strong indicators observed",
                "info",
                80,
                "A normal HTTP response was received, but no strong web stack indicators were identified "
                "from headers or capped page preview.",
                [
                    "Review raw headers and page preview manually if needed.",
                    "Some stacks hide indicators or load assets from separate domains.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    findings.append(
        make_finding(
            "Web stack indicators observed",
            "info",
            85,
            f"{len(indicators)} visible web stack indicator(s) observed for {url}. "
            "Indicators suggest possible technologies — review whether they are expected.",
            [
                "Validate indicators against asset inventory.",
                "Use findings as review prompts, not confirmed fingerprinting.",
            ],
            finding_kind=FINDING_KIND_SOURCE_NOTICE,
        )
    )

    if headers.get("server"):
        findings.append(
            make_finding(
                "Server header observed",
                "info",
                82,
                f"Server header observed: {headers['server']}. Review whether server disclosure is expected.",
                ["Consider whether version disclosure should be minimised."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    if headers.get("x-powered-by"):
        findings.append(
            make_finding(
                "X-Powered-By header observed",
                "low",
                80,
                f"X-Powered-By header observed: {headers['x-powered-by']}. "
                "This may disclose application stack details.",
                ["Review whether this header should be removed or genericised."],
            )
        )

    category_findings = {
        CATEGORY_CMS: "CMS indicator observed",
        CATEGORY_JS_FRAMEWORK: "Framework indicator observed",
        CATEGORY_HOSTING: "Platform indicator observed",
        CATEGORY_CDN: "Platform indicator observed",
        CATEGORY_ANALYTICS: "Analytics indicator observed",
        CATEGORY_WEB_SERVER: "Server header observed",
    }
    emitted: set[str] = set()
    for row in indicators:
        category = row.get("category")
        title = category_findings.get(category)
        if not title or title in emitted:
            continue
        if category == CATEGORY_WEB_SERVER and "Server header observed" in emitted:
            continue
        emitted.add(title)
        findings.append(
            make_finding(
                title,
                "info",
                75,
                f"{row.get('name')} indicator observed via {row.get('source')}. "
                f"{row.get('reason') or 'Review whether this technology is expected.'}",
                ["Review whether this technology is expected on the assessed target."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    return findings

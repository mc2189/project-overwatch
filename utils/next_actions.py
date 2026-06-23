"""Next best action recommendations for the assessment workspace."""

from __future__ import annotations

from typing import Any

from database.engagements import get_engagement_for_case
from modules.module_registry import get_module
from ui.constants import MODULE_CARD_TITLES
from utils.assessment_goals import (
    GOAL_CUSTOM,
    GOAL_EMAIL_SPOOFING,
    GOAL_EVIDENCE_REVIEW,
    GOAL_EXTERNAL_EXPOSURE,
    GOAL_THREAT_REPUTATION,
    GOAL_WEBSITE_POSTURE,
    goal_label,
)
from utils.module_compatibility import get_compatible_modules
from utils.module_testing_levels import get_module_testing_level, is_active_testing_level
from utils.operating_context import CLIENT_ENGAGEMENT, PASSIVE_RESEARCH, PERSONAL_LAB
from utils.pivot_discovery import discover_pivots_from_results
from utils.security import is_private_or_local_ip
from utils.target_detection import get_target_type

ActionType = str
Priority = str


def _action(
    *,
    title: str,
    reason: str,
    action_type: ActionType,
    priority: Priority = "medium",
    module_id: str | None = None,
    target: str | None = None,
    entity_id: int | None = None,
    goal_id: str | None = None,
) -> dict[str, Any]:
    return {
        "title": title,
        "reason": reason,
        "action_type": action_type,
        "priority": priority,
        "module_id": module_id,
        "module_display_name": (
            MODULE_CARD_TITLES.get(module_id) or (get_module(module_id).display_name if module_id and get_module(module_id) else None)
        ),
        "target": target,
        "entity_id": entity_id,
        "goal_id": goal_id,
    }


def _module_ran(module_id: str, latest_results: list[dict[str, Any]]) -> bool:
    return any(
        result.get("module_id") == module_id and result.get("success")
        for result in latest_results
    )


def _finding_titles(latest_results: list[dict[str, Any]], needle: str) -> list[str]:
    titles: list[str] = []
    needle_lower = needle.lower()
    for result in latest_results:
        for finding in result.get("interpreter_findings") or []:
            title = (finding.get("title") or "").lower()
            explanation = (finding.get("explanation") or "").lower()
            if needle_lower in title or needle_lower in explanation:
                titles.append(finding.get("title") or "Finding")
    return titles


def suggest_next_actions(
    *,
    case_id: int,
    target: str,
    goal_id: str,
    target_profile: dict[str, Any],
    latest_results: list[dict[str, Any]] | None = None,
    operating_context: str = PASSIVE_RESEARCH,
    conn: Any | None = None,
) -> list[dict[str, Any]]:
    """Return ordered next-best-action suggestions."""
    latest_results = latest_results or []
    cleaned = target.strip()
    target_type = get_target_type(cleaned) if cleaned else "unknown"
    compatible_ids = set(target_profile.get("compatible_module_ids") or [])
    actions: list[dict[str, Any]] = []

    if not cleaned:
        return [
            _action(
                title="Enter an investigation target",
                reason="The workspace needs a target before it can recommend checks.",
                action_type="note_only",
                priority="high",
            )
        ]

    if goal_id == GOAL_EVIDENCE_REVIEW:
        actions.append(
            _action(
                title="Open Evidence Locker",
                reason="Uploaded artefacts are reviewed from Evidence Locker rather than live target modules.",
                action_type="note_only",
                priority="high",
            )
        )
        return actions

    ran_module_ids = {
        result.get("module_id")
        for result in latest_results
        if result.get("success")
    }

    goal_modules = {
        "infra_email_security": GOAL_EMAIL_SPOOFING,
        "infra_http_security": GOAL_WEBSITE_POSTURE,
        "infra_tls_review": GOAL_WEBSITE_POSTURE,
        "infra_shodan": GOAL_EXTERNAL_EXPOSURE,
        "intel_virustotal": GOAL_THREAT_REPUTATION,
        "intel_abuseipdb": GOAL_THREAT_REPUTATION,
        "intel_urlhaus": GOAL_THREAT_REPUTATION,
    }
    for module_id, suggested_goal in goal_modules.items():
        if module_id in compatible_ids and module_id not in ran_module_ids:
            actions.append(
                _action(
                    title=f"Run {MODULE_CARD_TITLES.get(module_id, module_id)}",
                    reason=f"Compatible with this {target_profile.get('target_type_label', 'target')} and not run in the latest batch.",
                    action_type="run_module",
                    priority="medium",
                    module_id=module_id,
                    target=cleaned,
                    goal_id=suggested_goal,
                )
            )

    if target_type in {"domain", "url"} and "infra_email_security" in compatible_ids:
        dmarc_findings = _finding_titles(latest_results, "dmarc")
        if dmarc_findings or not _module_ran("infra_email_security", latest_results):
            actions.append(
                _action(
                    title="Review email security posture",
                    reason="SPF and DMARC gaps are a common spoofing risk for domains.",
                    action_type="run_module",
                    priority="high" if dmarc_findings else "medium",
                    module_id="infra_email_security",
                    target=cleaned,
                    goal_id=GOAL_EMAIL_SPOOFING,
                )
            )

    if target_type in {"domain", "url"} and "infra_http_security" in compatible_ids:
        if not _module_ran("infra_http_security", latest_results):
            actions.append(
                _action(
                    title="Run HTTP header review",
                    reason="Quick active check for security headers and cookie flags when authorised.",
                    action_type="run_module",
                    priority="medium",
                    module_id="infra_http_security",
                    target=cleaned,
                )
            )

    if target_type in {"domain", "url", "ipv4"} and "infra_tls_review" in compatible_ids:
        if not _module_ran("infra_tls_review", latest_results):
            actions.append(
                _action(
                    title="Run TLS configuration review",
                    reason="Validates certificate and negotiated TLS settings on the service port.",
                    action_type="run_module",
                    priority="medium",
                    module_id="infra_tls_review",
                    target=cleaned,
                )
            )

    if any(
        is_active_testing_level(get_module_testing_level(module_id))
        for module_id in compatible_ids
    ) and operating_context == PASSIVE_RESEARCH:
        actions.append(
            _action(
                title="Switch to Personal Lab mode",
                reason="Active checks require Personal Lab or Client Engagement operating context.",
                action_type="note_only",
                priority="high",
            )
        )

    engagement = get_engagement_for_case(case_id, conn=conn) if conn is not None else get_engagement_for_case(case_id)
    if engagement is None and operating_context == CLIENT_ENGAGEMENT:
        actions.append(
            _action(
                title="Link a client engagement",
                reason="Client Engagement mode requires a linked engagement on this case.",
                action_type="note_only",
                priority="high",
            )
        )
    elif engagement is None and target_type in {"domain", "url", "ipv4"}:
        actions.append(
            _action(
                title="Create client engagement for formal work",
                reason="Use Client Engagements when moving from lab testing to documented client assessment.",
                action_type="note_only",
                priority="low",
            )
        )

    if target_profile.get("needs_lab_scope"):
        actions.append(
            _action(
                title="Add target to Personal Lab scope",
                reason="Personal Lab active checks require the target in lab scope.",
                action_type="update_scope",
                priority="high",
                target=cleaned,
            )
        )

    pivots = discover_pivots_from_results(latest_results)
    for pivot in pivots[:6]:
        actions.append(
            _action(
                title=f"Pivot: {pivot['pivot_type']} — {pivot['value']}",
                reason=f"Discovered from {pivot.get('source_module', 'latest run')}.",
                action_type="add_to_queue",
                priority="medium",
                target=pivot["value"],
                module_id=(pivot.get("suggested_checks") or [None])[0],
            )
        )

    if latest_results:
        actions.append(
            _action(
                title="Generate case report",
                reason="Summarise findings and evidence after completing the recommended journey.",
                action_type="create_report",
                priority="medium",
            )
        )
        actions.append(
            _action(
                title="Review findings triage",
                reason="Confirm severity, dismiss false positives, and add analyst notes.",
                action_type="review_finding",
                priority="medium",
            )
        )

    if target_type == "ipv4" and is_private_or_local_ip(cleaned) and "infra_nmap" in compatible_ids:
        if not _module_ran("infra_nmap", latest_results):
            actions.append(
                _action(
                    title="Run network service check",
                    reason="Private/local IP — conservative port scan when authorised.",
                    action_type="run_module",
                    priority="high",
                    module_id="infra_nmap",
                    target=cleaned,
                )
            )

    priority_rank = {"high": 0, "medium": 1, "low": 2}
    actions.sort(key=lambda item: priority_rank.get(item.get("priority", "medium"), 1))

    seen_titles: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for action in actions:
        key = action["title"]
        if key in seen_titles:
            continue
        seen_titles.add(key)
        deduped.append(action)
    return deduped[:12]

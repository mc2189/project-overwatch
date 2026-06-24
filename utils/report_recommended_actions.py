"""Ranked recommended actions for Report Builder v2."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from utils.finding_interpreter import is_source_notice


@dataclass
class RecommendedAction:
    title: str
    reason: str
    priority: str
    related_finding: str | None = None
    related_evidence: str | None = None
    owner: str = "TBC"
    status: str = "Open"
    source: str = "finding"


PRIORITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _parse_suggested_actions(finding: dict[str, Any]) -> list[str]:
    try:
        actions = json.loads(finding.get("suggested_actions_json") or "[]")
    except (json.JSONDecodeError, TypeError):
        return []
    return [action for action in actions if action]


def _linked_evidence_for_finding(
    finding: dict[str, Any],
    evidence_items: list[dict[str, Any]],
    evidence_links: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    finding_id = finding.get("id")
    observation_id = finding.get("observation_id")
    linked_ids = {
        link["evidence_id"]
        for link in evidence_links
        if link.get("finding_id") == finding_id
    }
    linked: list[dict[str, Any]] = []
    seen: set[int] = set()
    for item in evidence_items:
        if item["id"] in linked_ids or item.get("finding_id") == finding_id:
            linked.append(item)
            seen.add(item["id"])
    if observation_id is not None:
        for item in evidence_items:
            if item.get("observation_id") == observation_id and item["id"] not in seen:
                linked.append(item)
    return linked


def build_recommended_actions(
    *,
    findings: list[dict[str, Any]],
    evidence_items: list[dict[str, Any]],
    evidence_links: list[dict[str, Any]],
    operating_context: str,
) -> list[RecommendedAction]:
    """Build ranked recommended actions from findings and evidence."""
    actions: list[RecommendedAction] = []
    seen_titles: set[str] = set()

    ranked_findings = sorted(
        [item for item in findings if not is_source_notice(item)],
        key=lambda item: PRIORITY_RANK.get((item.get("severity") or "info").lower(), 0),
        reverse=True,
    )

    for finding in ranked_findings[:20]:
        severity = (finding.get("severity") or "info").lower()
        title = (finding.get("title") or "Review finding").strip()
        if title in seen_titles:
            continue
        seen_titles.add(title)
        explanation = (finding.get("explanation") or "").strip()
        reason = explanation.split(".")[0].strip() if explanation else "Review whether this observation is expected."
        if not reason.endswith("."):
            reason += "."
        if operating_context == "personal_lab":
            reason += " Confirm in your Personal Lab context before applying outside self-owned systems."
        elif operating_context == "client_engagement":
            reason += " Confirm against client scope and ROE before external communication."

        linked = _linked_evidence_for_finding(finding, evidence_items, evidence_links)
        evidence_ref = None
        if linked:
            evidence_ref = linked[0].get("title") or linked[0].get("source_name")

        actions.append(
            RecommendedAction(
                title=title,
                reason=reason,
                priority=severity if severity in PRIORITY_RANK else "medium",
                related_finding=title,
                related_evidence=evidence_ref,
                source="finding",
            )
        )

        for suggested in _parse_suggested_actions(finding)[:2]:
            normalized = suggested.strip()
            if not normalized or normalized in seen_titles:
                continue
            seen_titles.add(normalized)
            actions.append(
                RecommendedAction(
                    title=normalized[:120],
                    reason=f"Suggested follow-up related to finding: {title}.",
                    priority=severity if severity in PRIORITY_RANK else "medium",
                    related_finding=title,
                    related_evidence=evidence_ref,
                    source="suggested_action",
                )
            )

    if not actions:
        actions.append(
            RecommendedAction(
                title="Review observations and confirm expected posture",
                reason="No selected findings produced ranked actions. Review stored observations before sharing.",
                priority="low",
                source="default",
            )
        )

    actions.sort(key=lambda item: PRIORITY_RANK.get(item.priority, 0), reverse=True)
    return actions[:15]


def recommended_actions_markdown(actions: list[RecommendedAction]) -> list[str]:
    lines = ["## Recommended Actions", ""]
    lines.append(
        "_Ranked advisory actions based on selected findings and suggested follow-ups. "
        "Review whether each item is expected before acting._"
    )
    lines.append("")
    if not actions:
        lines.append("_No recommended actions generated._")
        lines.append("")
        return lines

    for index, action in enumerate(actions, start=1):
        lines.append(f"### {index}. {action.title}")
        lines.append("")
        lines.append(f"- **Priority:** {action.priority}")
        lines.append(f"- **Reason:** {action.reason}")
        if action.related_finding:
            lines.append(f"- **Related finding:** {action.related_finding}")
        if action.related_evidence:
            lines.append(f"- **Related evidence:** {action.related_evidence}")
        lines.append(f"- **Owner:** {action.owner}")
        lines.append(f"- **Status:** {action.status}")
        lines.append("")
    return lines

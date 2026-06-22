"""Case report export from findings and observations."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any


SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _entity_label(entity_id: int | None, entity_lookup: dict[int, str]) -> str:
    if entity_id is None:
        return "-"
    return entity_lookup.get(entity_id, str(entity_id))


def build_case_report_markdown(
    case: dict[str, Any],
    entities: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    relationships: list[dict[str, Any]] | None = None,
) -> str:
    """Build a Markdown case summary for analyst review."""
    entity_lookup = {
        entity["id"]: entity.get("label") or entity.get("value", str(entity["id"]))
        for entity in entities
    }
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        f"# Case report: {case.get('name', 'Unnamed')}",
        "",
        f"- Case ID: {case.get('id')}",
        f"- Status: {case.get('status', 'open')}",
        f"- Generated: {generated_at}",
        "",
        "> Findings are analyst aids, not final proof of risk. Validate before acting.",
        "",
    ]

    open_findings = [f for f in findings if f.get("status") == "open"]
    lines.extend(
        [
            "## Summary",
            "",
            f"- Entities: {len(entities)}",
            f"- Observations: {len(observations)}",
            f"- Findings: {len(findings)} ({len(open_findings)} open)",
        ]
    )
    if relationships is not None:
        lines.append(f"- Relationships: {len(relationships)}")
    lines.append("")

    lines.extend(["## Findings", ""])
    if not findings:
        lines.append("_No findings recorded._")
    else:
        sorted_findings = sorted(
            findings,
            key=lambda item: (
                -SEVERITY_ORDER.get(item.get("severity", "info"), 0),
                item.get("title", ""),
            ),
        )
        for finding in sorted_findings:
            severity = (finding.get("severity") or "info").upper()
            entity = _entity_label(finding.get("entity_id"), entity_lookup)
            lines.append(f"### [{severity}] {finding.get('title', 'Finding')}")
            lines.append("")
            lines.append(
                f"- Module: `{finding.get('module_id')}` · Entity: {entity} · "
                f"Status: {finding.get('status', 'open')} · Confidence: {finding.get('confidence', 0)}"
            )
            lines.append("")
            lines.append(finding.get("explanation", ""))
            lines.append("")
            try:
                actions = json.loads(finding.get("suggested_actions_json") or "[]")
            except json.JSONDecodeError:
                actions = []
            if actions:
                lines.append("**Suggested next actions:**")
                for action in actions:
                    lines.append(f"- {action}")
                lines.append("")

    lines.extend(["## Observations", ""])
    if not observations:
        lines.append("_No observations recorded._")
    else:
        for observation in observations[:50]:
            entity = _entity_label(observation.get("entity_id"), entity_lookup)
            lines.append(
                f"- **{observation.get('title', 'Observation')}** "
                f"(`{observation.get('module_id')}` · {entity}) — "
                f"{observation.get('summary') or 'No summary'}"
            )
        if len(observations) > 50:
            lines.append(f"- _…and {len(observations) - 50} more observations._")

    lines.append("")
    return "\n".join(lines)


def build_case_report_json(
    case: dict[str, Any],
    entities: list[dict[str, Any]],
    observations: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    relationships: list[dict[str, Any]] | None = None,
) -> str:
    """Build a JSON case export."""
    payload: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "case": case,
        "entities": entities,
        "observations": observations,
        "findings": [
            {
                **finding,
                "suggested_actions": json.loads(finding.get("suggested_actions_json") or "[]")
                if finding.get("suggested_actions_json")
                else [],
            }
            for finding in findings
        ],
    }
    if relationships is not None:
        payload["relationships"] = relationships
    return json.dumps(payload, indent=2, default=str)

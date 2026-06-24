"""Next-action and autopilot suggestions from case memory and baseline comparison."""

from __future__ import annotations

from typing import Any

from database.db_setup import get_latest_case_baseline, list_operations
from utils.baseline_compare import compare_case_to_latest_baseline
from utils.case_memory import build_case_memory
from utils.next_actions import make_action
from utils.settings_manager import auto_suggest_baseline_creation, change_meets_sensitivity

IMPORTANCE_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _meaningful_assessment(case_id: int, *, conn: Any) -> bool:
    memory = build_case_memory(case_id, conn=conn)
    if memory.get("known_devices") or memory.get("known_services"):
        return True
    if memory.get("open_findings"):
        return True
    operations = list_operations(case_id=case_id, conn=conn)
    return any(op.get("status") == "completed" for op in operations)


def _filter_notable_changes(changes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    notable: list[dict[str, Any]] = []
    for change in changes:
        if change.get("expected"):
            continue
        importance = (change.get("importance") or change.get("severity") or "info").lower()
        if not change_meets_sensitivity(importance):
            continue
        notable.append(change)
    return notable


def suggest_case_memory_actions(
    case_id: int,
    *,
    conn: Any,
    target: str | None = None,
) -> list[dict[str, Any]]:
    """Return baseline and change-detection next actions for a case."""
    if case_id <= 0:
        return []

    actions: list[dict[str, Any]] = []
    latest_baseline = get_latest_case_baseline(case_id, conn=conn)
    comparison = compare_case_to_latest_baseline(case_id, conn=conn)
    notable = _filter_notable_changes(comparison.get("changes") or [])

    if latest_baseline is None:
        if auto_suggest_baseline_creation() and _meaningful_assessment(case_id, conn=conn):
            actions.append(
                make_action(
                    title="Create baseline from current case",
                    reason="Capture devices, services, and findings as a comparison point for future runs.",
                    action_type="navigate_page",
                    priority="medium",
                    navigate_page="Assessment Workspace",
                    button_label="Create baseline",
                )
            )
        return actions

    if notable:
        actions.append(
            make_action(
                title="Compare with previous baseline",
                reason=comparison.get("summary_text") or "Review what changed since the last baseline.",
                action_type="navigate_page",
                priority="high",
                navigate_page="Assessment Workspace",
                button_label="Review changes",
            )
        )

    from utils.baseline_ops import baseline_snapshot_summary, is_baseline_snapshot_ready

    if is_baseline_snapshot_ready(comparison) and _meaningful_assessment(case_id, conn=conn):
        actions.insert(
            0,
            make_action(
                title="Snapshot & replace latest baseline",
                reason=baseline_snapshot_summary(comparison),
                action_type="snapshot_baseline",
                priority="high",
                button_label="Snapshot baseline",
            ),
        )

    new_devices = [change for change in notable if change.get("change_type") == "new_device"]
    if new_devices:
        actions.append(
            make_action(
                title="Review new devices",
                reason=new_devices[0].get("summary") or "New LAN devices were observed since the baseline.",
                action_type="navigate_page",
                priority="high" if len(new_devices) > 1 else "medium",
                target=new_devices[0].get("target") or target,
                navigate_page="Assessment Workspace",
                button_label="Review devices",
            )
        )

    new_services = [
        change
        for change in notable
        if change.get("change_type") in {"new_service", "new_remote_access_service"}
    ]
    for change in new_services[:2]:
        module_id = "infra_remote_access_review"
        if change.get("change_type") == "new_service":
            module_id = "infra_nmap"
        actions.append(
            make_action(
                title=f"Review new service: {change.get('target') or change.get('title', 'service')[:40]}",
                reason=change.get("summary") or "New open service since baseline.",
                action_type="run_module",
                priority="high" if change.get("change_type") == "new_remote_access_service" else "medium",
                module_id=module_id,
                target=change.get("target") or target,
                button_label="Run follow-up",
            )
        )

    remote_access = [change for change in notable if change.get("change_type") == "new_remote_access_service"]
    if remote_access and not any(action.get("module_id") == "infra_remote_access_review" for action in actions):
        actions.append(
            make_action(
                title="Review new remote access exposure",
                reason=remote_access[0].get("summary") or "New remote administration service observed.",
                action_type="run_module",
                priority="high",
                module_id="infra_remote_access_review",
                target=remote_access[0].get("target") or target,
                button_label="Remote access review",
            )
        )

    if notable:
        actions.append(
            make_action(
                title="Add change summary to report",
                reason="Material changes since baseline may belong in the assessment pack.",
                action_type="create_report",
                priority="medium",
                button_label="Generate report",
            )
        )
        actions.append(
            make_action(
                title="Mark expected items",
                reason="Reduce repeated noise by marking known-good devices, services, or findings.",
                action_type="navigate_page",
                priority="low",
                navigate_page="Assessment Workspace",
                button_label="Mark expected",
            )
        )

    return actions


def propose_case_memory_autopilot_actions(
    case_id: int,
    *,
    target: str,
    conn: Any,
    playbook_id: str | None = None,
) -> list[dict[str, Any]]:
    """Autopilot suggestions derived from baseline comparison (no silent active runs)."""
    from utils.autopilot_rules import make_autopilot_action

    if case_id <= 0:
        return []

    actions: list[dict[str, Any]] = []
    latest_baseline = get_latest_case_baseline(case_id, conn=conn)
    comparison = compare_case_to_latest_baseline(case_id, conn=conn)
    notable = _filter_notable_changes(comparison.get("changes") or [])

    if latest_baseline is None and _meaningful_assessment(case_id, conn=conn):
        actions.append(
            make_autopilot_action(
                title="Create assessment baseline",
                reason="No baseline exists — capture current devices and services before follow-ups.",
                action_type="note_only",
                priority="medium",
                target=target,
                playbook_id=playbook_id,
                source_module_id="case_memory",
                why_detail="Case memory recommends a baseline after meaningful assessment data.",
            )
        )
        return actions

    for change in sorted(
        notable,
        key=lambda row: IMPORTANCE_RANK.get((row.get("importance") or "info").lower(), 0),
        reverse=True,
    )[:4]:
        change_type = change.get("change_type") or ""
        if change_type == "new_remote_access_service":
            actions.append(
                make_autopilot_action(
                    title="Review new remote access service",
                    reason=change.get("summary") or change.get("title") or "New remote access since baseline.",
                    action_type="add_to_queue",
                    priority="high",
                    target=change.get("target") or target,
                    module_id="infra_remote_access_review",
                    playbook_id=playbook_id,
                    source_module_id=change.get("source_module") or "case_memory",
                    requires_confirmation=True,
                    why_detail=change.get("suggested_action"),
                )
            )
        elif change_type == "new_service":
            host = (change.get("target") or target or "").split(":")[0]
            actions.append(
                make_autopilot_action(
                    title=f"Follow up new service on {host}",
                    reason=change.get("summary") or change.get("title") or "New service since baseline.",
                    action_type="add_to_queue",
                    priority="high",
                    target=host or target,
                    module_id="infra_nmap",
                    playbook_id=playbook_id,
                    source_module_id="infra_nmap",
                    requires_confirmation=True,
                    why_detail=change.get("suggested_action"),
                )
            )
        elif change_type == "new_finding":
            actions.append(
                make_autopilot_action(
                    title="Review new finding since baseline",
                    reason=change.get("summary") or change.get("title") or "New finding detected.",
                    action_type="open_finding",
                    priority="high",
                    target=target,
                    playbook_id=playbook_id,
                    source_module_id=change.get("source_module") or "case_memory",
                    requires_confirmation=True,
                    why_detail=change.get("suggested_action"),
                )
            )

    if len(notable) >= 2:
        actions.append(
            make_autopilot_action(
                title="Update report with change summary",
                reason=comparison.get("summary_text") or "Material baseline changes detected.",
                action_type="create_report",
                priority="medium",
                target=target,
                playbook_id=playbook_id,
                source_module_id="case_memory",
                requires_confirmation=True,
                why_detail="Include baseline comparison in the assessment pack.",
            )
        )

    return actions

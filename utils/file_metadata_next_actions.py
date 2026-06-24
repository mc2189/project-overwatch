"""Next-action suggestions from local file metadata review results."""

from __future__ import annotations

from typing import Any

from utils.next_actions import make_action


def suggest_file_metadata_primary_action(
    result: dict[str, Any],
    *,
    case_id: int,
    workspace_target: str = "",
) -> dict[str, Any]:
    """Return one practical next step for a file metadata result card."""
    parsed = result.get("parsed_data") or {}
    files = list(parsed.get("files") or [])
    module_id = result.get("module_id") or "evidence_file_metadata"
    target = workspace_target or parsed.get("target") or (files[0].get("filename") if files else "")

    gps_files = [row for row in files if (row.get("privacy_flags") or {}).get("gps_present")]
    if gps_files:
        names = ", ".join(row.get("filename", "file") for row in gps_files[:3])
        return make_action(
            title="Review GPS/location metadata",
            reason=f"Location metadata present in: {names}.",
            action_type="open_finding",
            priority="medium",
            target=target,
            module_id=module_id,
            button_label="Review findings",
        )

    author_files = [row for row in files if (row.get("privacy_flags") or {}).get("author_present")]
    if author_files:
        return make_action(
            title="Add privacy note to report",
            reason="Author/creator metadata is present — note before external sharing.",
            action_type="add_note",
            priority="low",
            target=target,
            module_id=module_id,
            button_label="Add note",
        )

    notable = [row for row in files if row.get("notable")]
    if notable:
        return make_action(
            title="Remove metadata before sharing externally",
            reason=f"{len(notable)} file(s) contain metadata that may warrant stripping before release.",
            action_type="add_note",
            priority="low",
            target=target,
            module_id=module_id,
            button_label="Add note",
        )

    partial = [row for row in files if row.get("extraction_status") in {"partial", "unavailable"}]
    if partial:
        return make_action(
            title="Review extraction limitations",
            reason="Some files could not be fully parsed — check optional library notes.",
            action_type="no_action",
            priority="low",
            target=target,
            module_id=module_id,
            button_label="Info",
        )

    return make_action(
        title="Open file evidence",
        reason="Review stored hashes and metadata evidence in the locker.",
        action_type="review_evidence",
        priority="medium",
        target=target,
        module_id=module_id,
        button_label="Review evidence",
    )


def suggest_file_metadata_investigation_actions(
    result: dict[str, Any],
    *,
    case_id: int,
    workspace_target: str = "",
) -> list[dict[str, Any]]:
    """Return ordered follow-up actions from a file metadata review result."""
    parsed = result.get("parsed_data") or {}
    files = list(parsed.get("files") or [])
    module_id = result.get("module_id") or "evidence_file_metadata"
    target = workspace_target or parsed.get("target") or (files[0].get("filename") if files else "")
    actions: list[dict[str, Any]] = []

    gps_files = [row for row in files if (row.get("privacy_flags") or {}).get("gps_present")]
    if gps_files:
        actions.append(
            make_action(
                title="Review GPS/location metadata",
                reason="GPS/location metadata present — review before sharing externally.",
                action_type="open_finding",
                priority="medium",
                target=target,
                module_id=module_id,
                button_label="Review findings",
            )
        )

    if any(row.get("notable") for row in files):
        actions.append(
            make_action(
                title="Remove metadata before sharing externally",
                reason="Metadata may reveal device, author, or internal details.",
                action_type="add_note",
                priority="low",
                target=target,
                module_id=module_id,
                button_label="Add note",
            )
        )

    if any((row.get("privacy_flags") or {}).get("author_present") for row in files):
        actions.append(
            make_action(
                title="Add privacy note to report",
                reason="Author/creator names are privacy-sensitive in external reports.",
                action_type="add_note",
                priority="low",
                target=target,
                module_id=module_id,
                button_label="Add note",
            )
        )

    actions.append(
        make_action(
            title="Open file evidence",
            reason="Review file hashes and extracted metadata evidence.",
            action_type="review_evidence",
            priority="medium",
            target=target,
            module_id=module_id,
            button_label="Review evidence",
        )
    )
    actions.append(
        make_action(
            title="Generate report",
            reason="Include File Metadata Review Summary in the case report.",
            action_type="create_report",
            priority="medium",
            target=target,
            module_id=module_id,
            button_label="Generate report",
        )
    )
    return actions

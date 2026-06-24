"""Build a capture recon artifact from triage, devices, and follow-up runs."""

from __future__ import annotations

from typing import Any

from utils.pcap_device_map import lan_device_summary
from utils.pcap_followup_runner import build_recon_progress_summary
from utils.pcap_next_actions import suggest_post_followup_actions
from utils.pcap_synthesis import build_capture_followup_synthesis


def _followup_results_as_operations(followup_results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    operations: list[dict[str, Any]] = []
    for row in followup_results:
        module_id = row.get("module_id")
        if not module_id:
            continue
        operations.append(
            {
                "module_id": module_id,
                "target": row.get("target") or "",
                "status": row.get("status") or ("completed" if row.get("success") else "error"),
                "summary": row.get("summary") or "",
            }
        )
    return operations


def build_capture_recon_artifact(
    capture_result: dict[str, Any],
    *,
    followup_results: list[dict[str, Any]] | None = None,
    pcap_parsed: dict[str, Any] | None = None,
    triage: dict[str, Any] | None = None,
    case_id: int | None = None,
) -> dict[str, Any]:
    """Aggregate capture context into a single recon result snapshot."""
    parsed = capture_result.get("parsed_data") or {}
    pcap_parsed = pcap_parsed or (parsed.get("pcap_review") or {}).get("parsed_data") or parsed
    triage = triage or parsed.get("triage") or pcap_parsed.get("triage") or {}
    followup_results = followup_results or []

    progress = build_recon_progress_summary(capture_result, followup_results)
    devices = list(pcap_parsed.get("lan_devices") or [])
    ranked = list(triage.get("ranked_entities") or [])
    synthesis = build_capture_followup_synthesis(
        pcap_parsed,
        _followup_results_as_operations(followup_results),
        capture_sha256=(parsed.get("capture") or {}).get("sha256"),
    )
    next_steps = (
        suggest_post_followup_actions(followup_results, case_id=case_id or 0) if followup_results else []
    )

    device_lines = []
    for device in devices[:12]:
        label = device.get("hostname") or device.get("ip") or device.get("mac") or "device"
        role = device.get("role_label") or "Unknown"
        ip = device.get("ip") or "—"
        device_lines.append(f"{label} ({ip}) — {role}")

    return {
        "artifact_version": "1",
        "capture_summary": capture_result.get("summary") or progress.get("capture_summary") or "",
        "network_picture": (triage.get("network_picture") or {}).get("one_liner") or "",
        "lan_device_summary": lan_device_summary(devices),
        "lan_devices": devices,
        "device_lines": device_lines,
        "ranked_entities": ranked[:12],
        "progress": progress,
        "synthesis_lines": [row.get("summary_line") for row in synthesis if row.get("summary_line")],
        "suggested_next_steps": [
            {
                "title": action.get("title"),
                "module_id": action.get("module_id"),
                "target": action.get("target"),
                "button_label": action.get("button_label"),
                "enabled": action.get("enabled", True),
            }
            for action in next_steps[:8]
        ],
        "ready_for_report": bool(progress.get("modules_completed") or devices or synthesis),
    }

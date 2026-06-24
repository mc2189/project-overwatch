"""Personal Lab Packet Capture — bounded live capture with PCAP Evidence Review handoff."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from typing import Any

from utils.live_capture import (
    PERSONAL_LAB_CAPTURE_CONFIRMATION,
    build_bpf_filter,
    capture_backend_status,
    default_interface,
    list_capture_interfaces,
    preview_output_filename,
    run_live_packet_capture,
    validate_duration,
    validate_packet_cap,
)
from utils.live_capture_interpreter import interpret_live_capture_results
from utils.pcap_interpreter import interpret_pcap_results
from utils.pcap_resilience import attach_resilience_to_findings
from utils.result_status import (
    STATUS_BLOCKED,
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_WARNINGS,
    STATUS_ERROR,
    STATUS_PARTIAL,
)
from utils.security import redact_secrets_from_text

MODULE_ID = "net_live_capture"
PCAP_REVIEW_PATH = Path(__file__).resolve().parent / "net_pcap_review.py"


def _merge_findings(*groups: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: list[dict[str, Any]] = []
    seen: set[str] = set()
    for group in groups:
        for finding in group:
            title = str(finding.get("title") or "")
            if title in seen:
                continue
            seen.add(title)
            merged.append(finding)
    return merged


def _load_pcap_review():
    spec = importlib.util.spec_from_file_location("net_pcap_review_handoff", PCAP_REVIEW_PATH)
    if spec is None or spec.loader is None:
        raise ImportError("Could not load PCAP Evidence Review module.")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.run_pcap_review


def build_live_capture_summary(parsed_data: dict[str, Any], *, finding_count: int) -> str:
    capture = parsed_data.get("capture") or {}
    if parsed_data.get("backend_unavailable"):
        return "Live capture unavailable — install tshark or tcpdump."
    if capture.get("permission_denied"):
        return "Live capture blocked — local capture permission is required."
    if not parsed_data.get("capture_success"):
        errors = parsed_data.get("errors") or []
        return errors[0] if errors else "Live capture failed."
    duration = capture.get("duration_seconds")
    packets = (parsed_data.get("pcap_review") or {}).get("parsed_data") or {}
    packet_count = packets.get("packets_analysed")
    if packet_count is None:
        packet_count = packets.get("packet_count")
    if packet_count is None:
        packet_count = capture.get("packets_captured")
    analysis_note = "hashed and analysed" if parsed_data.get("analysis_success") else "saved"
    duration_text = f"{duration} seconds" if duration else "bounded duration"
    packet_text = f", {int(packet_count):,} packets" if packet_count is not None else ""
    triage = parsed_data.get("triage") or {}
    investigate = int(triage.get("investigate_count") or 0)
    investigate_text = f" {investigate} prioritised for follow-up." if investigate else ""
    return (
        f"Capture complete: {duration_text}{packet_text}, file {analysis_note}.{investigate_text} "
        f"{finding_count} advisory finding(s) created."
    )


def run_live_capture(target: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Execute a bounded Personal Lab live capture and analyse the result."""
    options = options or {}

    if options.get("mock_capture_result") is not None:
        parsed_data = dict(options["mock_capture_result"])
        findings = interpret_live_capture_results(parsed_data)
        status = str(options.get("mock_status") or STATUS_COMPLETED)
        summary = build_live_capture_summary(parsed_data, finding_count=len(findings))
        return {
            "success": status not in {STATUS_BLOCKED, STATUS_ERROR},
            "status": status,
            "parsed_data": parsed_data,
            "warnings": list(options.get("mock_warnings") or []),
            "errors": list(options.get("mock_errors") or []),
            "raw_output": redact_secrets_from_text(summary),
            "interpreter_findings": findings,
            "summary": summary,
        }

    if not options.get("personal_lab_confirmed"):
        return {
            "success": False,
            "status": STATUS_BLOCKED,
            "parsed_data": {"confirmation_required": True},
            "warnings": [],
            "errors": ["Personal Lab capture confirmation is required."],
            "raw_output": "Capture blocked — confirmation required.",
            "interpreter_findings": [],
            "summary": "Confirm Personal Lab capture authorisation before starting.",
        }

    backend_status = capture_backend_status()
    if not backend_status["any_available"]:
        parsed = {"backend_unavailable": True, "backend_status": backend_status}
        findings = interpret_live_capture_results(parsed)
        return {
            "success": False,
            "status": STATUS_BLOCKED,
            "parsed_data": parsed,
            "warnings": [],
            "errors": ["Capture backend unavailable — install tshark or tcpdump."],
            "raw_output": "Capture backend unavailable.",
            "interpreter_findings": findings,
            "summary": build_live_capture_summary(parsed, finding_count=len(findings)),
        }

    interfaces = options.get("interfaces")
    if interfaces is None:
        interfaces, iface_error = list_capture_interfaces()
        if iface_error and not interfaces:
            parsed = {"backend_status": backend_status, "interface_error": iface_error}
            return {
                "success": False,
                "status": STATUS_BLOCKED,
                "parsed_data": parsed,
                "warnings": [],
                "errors": [iface_error],
                "raw_output": iface_error,
                "interpreter_findings": interpret_live_capture_results(parsed),
                "summary": "Could not list network interfaces.",
            }

    interface_id = str(options.get("interface_id") or default_interface(interfaces) or "").strip()
    duration_seconds, _ = validate_duration(options.get("duration_seconds", 30))
    packet_cap, _ = validate_packet_cap(options.get("packet_cap", 1000))
    filter_preset = str(options.get("filter_preset") or "all_traffic")
    bpf_filter, filter_error = build_bpf_filter(
        filter_preset,
        target_host=str(options.get("filter_target_host") or ""),
        custom_filter=str(options.get("custom_bpf_filter") or ""),
    )
    if filter_error:
        return {
            "success": False,
            "status": STATUS_BLOCKED,
            "parsed_data": {"filter_preset": filter_preset},
            "warnings": [],
            "errors": [filter_error],
            "raw_output": filter_error,
            "interpreter_findings": [],
            "summary": "Capture blocked — invalid capture filter.",
        }

    case_id = int(options.get("case_id") or 0)
    output_filename = options.get("output_filename") or preview_output_filename(interface_id)

    if options.get("dry_run"):
        cmd_backend = backend_status["selected_backend"]
        from utils.live_capture import build_tcpdump_command, build_tshark_command

        output_path = Path(options.get("dry_run_output") or f"/tmp/{output_filename}")
        if cmd_backend == "tshark":
            cmd = build_tshark_command(
                interface_id=interface_id,
                output_path=output_path,
                duration_seconds=duration_seconds,
                packet_cap=packet_cap,
                bpf_filter=bpf_filter,
            )
        else:
            cmd = build_tcpdump_command(
                interface_id=interface_id,
                output_path=output_path,
                packet_cap=packet_cap,
                bpf_filter=bpf_filter,
            )
        return {
            "success": True,
            "status": STATUS_COMPLETED,
            "parsed_data": {
                "dry_run": True,
                "command": cmd,
                "shell_false": True,
            },
            "warnings": [],
            "errors": [],
            "raw_output": " ".join(cmd),
            "interpreter_findings": [],
            "summary": "Dry-run command built.",
        }

    capture_result = run_live_packet_capture(
        case_id=case_id,
        interface_id=interface_id,
        interfaces=interfaces,
        duration_seconds=duration_seconds,
        packet_cap=packet_cap,
        bpf_filter=bpf_filter,
        filter_preset=filter_preset,
        backend=options.get("backend"),
        output_filename=output_filename,
    )

    capture_meta = capture_result.get("capture") or {}
    parsed_data: dict[str, Any] = {
        "capture": capture_meta,
        "backend_status": backend_status,
        "confirmation_text": PERSONAL_LAB_CAPTURE_CONFIRMATION,
        "capture_success": bool(capture_result.get("success")),
        "analysis_success": False,
        "errors": list(capture_result.get("errors") or []),
    }

    if not capture_result.get("success"):
        status = str(capture_result.get("status") or STATUS_ERROR)
        findings = interpret_live_capture_results(parsed_data)
        summary = build_live_capture_summary(parsed_data, finding_count=len(findings))
        return {
            "success": False,
            "status": status,
            "parsed_data": parsed_data,
            "warnings": list(capture_result.get("warnings") or []),
            "errors": list(capture_result.get("errors") or []),
            "raw_output": redact_secrets_from_text(summary),
            "interpreter_findings": findings,
            "summary": summary,
        }

    pcap_review = {}
    try:
        run_pcap_review = _load_pcap_review()
        pcap_review = run_pcap_review(
            capture_meta.get("filename") or output_filename,
            options={
                "pcap_file_path": capture_meta.get("storage_path"),
                "pcap_filename": capture_meta.get("filename"),
                "pcap_sha256": capture_meta.get("sha256"),
                "pcap_size": capture_meta.get("file_size_bytes"),
                "case_id": case_id,
            },
        )
        parsed_data["pcap_review"] = {
            "success": pcap_review.get("success"),
            "status": pcap_review.get("status"),
            "summary": pcap_review.get("summary"),
            "parsed_data": pcap_review.get("parsed_data"),
            "warnings": pcap_review.get("warnings"),
            "sensitive_detected": pcap_review.get("sensitive_detected"),
        }
        parsed_data["analysis_success"] = bool(pcap_review.get("success"))
        pcap_parsed = pcap_review.get("parsed_data") or {}
        if pcap_parsed:
            from utils.pcap_fingerprint import enrich_pcap_parsed_data

            enrich_pcap_parsed_data(
                pcap_parsed,
                case_id=case_id,
                workspace_target=str(options.get("workspace_target") or ""),
                capture_meta=capture_meta,
            )
            parsed_data["triage"] = pcap_parsed.get("triage")
            parsed_data["fingerprint"] = pcap_parsed.get("fingerprint")
            parsed_data["fingerprint_diff"] = pcap_parsed.get("fingerprint_diff")
    except Exception as exc:
        parsed_data["pcap_review"] = {"error": str(exc)}
        capture_result.setdefault("warnings", []).append(
            f"PCAP Evidence Review handoff failed: {exc}"
        )

    findings = attach_resilience_to_findings(
        _merge_findings(
            interpret_live_capture_results(parsed_data),
            interpret_pcap_results((parsed_data.get("pcap_review") or {}).get("parsed_data") or {}),
        )
    )
    status = str(capture_result.get("status") or STATUS_COMPLETED)
    if capture_result.get("warnings") or not parsed_data.get("analysis_success"):
        status = STATUS_COMPLETED_WITH_WARNINGS if parsed_data.get("analysis_success") else STATUS_PARTIAL
    summary = build_live_capture_summary(parsed_data, finding_count=len(findings))
    raw_lines = [
        summary,
        f"Backend: {capture_meta.get('backend')}",
        f"Interface: {capture_meta.get('interface')}",
        f"Filter: {capture_meta.get('filter_preset')}",
    ]
    if capture_meta.get("manual_command"):
        raw_lines.append(f"Command: {capture_meta['manual_command']}")

    return {
        "success": True,
        "status": status,
        "parsed_data": parsed_data,
        "warnings": list(capture_result.get("warnings") or []),
        "errors": [],
        "raw_output": redact_secrets_from_text("\n".join(raw_lines)),
        "interpreter_findings": findings,
        "summary": summary,
    }

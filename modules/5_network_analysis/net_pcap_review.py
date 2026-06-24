"""PCAP Evidence Review — local-only packet capture analysis for Project Overwatch."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from utils.pcap_analysis import (
    analyze_pcap_file,
    is_supported_pcap_filename,
    pcap_target_type,
    sha256_bytes,
    sha256_file,
)
from utils.pcap_interpreter import interpret_pcap_results
from utils.result_status import STATUS_BLOCKED, STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_PARTIAL
from utils.security import redact_secrets_from_text
from utils.target_detection import get_target_type

MODULE_ID = "net_pcap_review"


def _format_duration(seconds: float | int | None) -> str:
    if seconds is None:
        return ""
    total = int(float(seconds))
    if total < 60:
        return f"{total} seconds"
    minutes, secs = divmod(total, 60)
    if minutes < 60:
        return f"{minutes} minute{'s' if minutes != 1 else ''}" + (f" {secs}s" if secs else "")
    hours, minutes = divmod(minutes, 60)
    return f"{hours}h {minutes}m"


def build_pcap_result_summary(
    parsed_data: dict[str, Any],
    *,
    status: str,
    finding_count: int,
) -> str:
    """Concise one-line summary for result cards and operations log."""
    filename = parsed_data.get("filename") or "capture"
    if not parsed_data.get("parser_available"):
        packets = int(parsed_data.get("packets_analysed") or parsed_data.get("packet_count") or 0)
        if packets > 0 and parsed_data.get("basic_metadata_available"):
            duration = parsed_data.get("duration_seconds")
            duration_text = f" over {_format_duration(duration)}" if duration else ""
            return (
                f"PCAP hashed with basic metadata: {packets:,} packet(s){duration_text}. "
                f"Install pyshark for deeper DNS/HTTP/TLS review. "
                f"{finding_count} advisory finding(s) created."
            )
        if not parsed_data.get("basic_metadata_available") and packets == 0:
            from utils.pcap_analysis import tshark_available

            if not tshark_available():
                return (
                    "PCAP uploaded and hashed, but parsing is unavailable because "
                    "tshark is not installed."
                )
            return (
                "PCAP uploaded and hashed, but deep parsing is unavailable because "
                "pyshark is not installed."
            )
    if status == STATUS_BLOCKED:
        return f"PCAP review blocked for {filename!r}."
    packets = int(parsed_data.get("packets_analysed") or parsed_data.get("packet_count") or 0)
    duration = parsed_data.get("duration_seconds")
    protocols = [item.get("protocol") for item in (parsed_data.get("protocols") or [])[:6] if item.get("protocol")]
    proto_names: list[str] = []
    for name in protocols:
        upper = str(name).upper()
        if upper not in {p.upper() for p in proto_names}:
            proto_names.append(upper)
    proto_text = ", ".join(proto_names) if proto_names else "limited protocol metadata"
    duration_text = f" over {_format_duration(duration)}" if duration else ""
    qualifier = "partially analysed" if status == STATUS_PARTIAL else "analysed"
    return (
        f"PCAP {qualifier}: {packets:,} packet{'s' if packets != 1 else ''}{duration_text}. "
        f"{proto_text} traffic observed. {finding_count} advisory finding(s) created."
    )


def run_pcap_review(target: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Analyse an uploaded PCAP/PCAPNG file from local storage."""
    options = options or {}
    filename = str(options.get("pcap_filename") or target or "").strip()
    target_type = options.get("target_type") or get_target_type(filename)

    if options.get("mock_parsed_data") is not None:
        parsed_data = dict(options["mock_parsed_data"])
        parsed_data.setdefault("filename", filename or "mock.pcap")
        parsed_data.setdefault("parser_available", True)
        status = str(options.get("mock_status") or STATUS_COMPLETED)
        findings = interpret_pcap_results(parsed_data)
        summary = build_pcap_result_summary(parsed_data, status=status, finding_count=len(findings))
        return {
            "success": status != STATUS_BLOCKED,
            "status": status,
            "parsed_data": parsed_data,
            "warnings": list(options.get("mock_warnings") or []),
            "errors": list(options.get("mock_errors") or []),
            "raw_output": redact_secrets_from_text(summary),
            "interpreter_findings": findings,
            "summary": summary,
        }

    if not filename:
        return {
            "success": False,
            "status": STATUS_BLOCKED,
            "parsed_data": {"filename": "", "target_type": target_type},
            "warnings": [],
            "errors": ["No capture filename was supplied."],
            "raw_output": "PCAP review blocked — no filename.",
            "interpreter_findings": [],
            "summary": "PCAP review blocked — upload a .pcap or .pcapng file.",
        }

    if not is_supported_pcap_filename(filename):
        parsed = {
            "filename": filename,
            "target_type": target_type,
            "unsupported_file_type": True,
            "parser_available": False,
        }
        return {
            "success": False,
            "status": STATUS_BLOCKED,
            "parsed_data": parsed,
            "warnings": [],
            "errors": ["Unsupported file type — only .pcap and .pcapng are accepted."],
            "raw_output": "Unsupported file type for PCAP Evidence Review.",
            "interpreter_findings": interpret_pcap_results(parsed),
            "summary": f"Unsupported file type for PCAP review: {filename!r}.",
        }

    file_path_raw = options.get("pcap_file_path")
    file_hash = options.get("pcap_sha256")
    file_size = options.get("pcap_size")
    file_bytes = options.get("pcap_file_bytes")

    path: Path | None = None
    if file_path_raw:
        path = Path(str(file_path_raw))
    elif file_bytes:
        file_hash = file_hash or sha256_bytes(file_bytes)
        file_size = file_size or len(file_bytes)

    if path is None and not file_bytes:
        return {
            "success": False,
            "status": STATUS_BLOCKED,
            "parsed_data": {
                "filename": filename,
                "target_type": pcap_target_type(filename),
                "sha256": file_hash,
                "file_size_bytes": file_size,
            },
            "warnings": [],
            "errors": ["Capture file content was not available for analysis."],
            "raw_output": "PCAP review blocked — file not available.",
            "interpreter_findings": [],
            "summary": "PCAP review blocked — re-upload the capture file.",
        }

    if path is not None:
        if not path.is_file():
            return {
                "success": False,
                "status": STATUS_BLOCKED,
                "parsed_data": {"filename": filename, "target_type": pcap_target_type(filename)},
                "warnings": [],
                "errors": ["Capture file is not available on disk."],
                "raw_output": "Capture file missing.",
                "interpreter_findings": [],
                "summary": "PCAP review blocked — capture file missing.",
            }
        file_hash = file_hash or sha256_file(path)
        file_size = file_size or path.stat().st_size
        analysis = analyze_pcap_file(
            path,
            filename=filename,
            file_hash=file_hash,
            file_size=int(file_size),
        )
    else:
        from utils.pcap_storage import write_temporary_pcap_bytes

        stored = write_temporary_pcap_bytes(
            int(options.get("case_id") or 0),
            filename,
            file_bytes,
            sha256=file_hash,
        )
        path = Path(stored["storage_path"])
        file_hash = stored["sha256"]
        file_size = stored["size_bytes"]
        analysis = analyze_pcap_file(
            path,
            filename=filename,
            file_hash=file_hash,
            file_size=file_size,
        )

    parsed_data = analysis.get("parsed_data") or {}
    parsed_data["target_type"] = pcap_target_type(filename)
    parsed_data["module_id"] = MODULE_ID
    case_id = int(options.get("case_id") or 0)
    if case_id and parsed_data.get("parser_available"):
        from utils.pcap_fingerprint import enrich_pcap_parsed_data

        enrich_pcap_parsed_data(
            parsed_data,
            case_id=case_id,
            workspace_target=str(options.get("workspace_target") or target or ""),
            save_fingerprint=options.get("save_fingerprint", True),
        )
    status = str(analysis.get("status") or STATUS_PARTIAL)
    if status == "completed_with_warnings":
        status = STATUS_COMPLETED_WITH_WARNINGS
    elif status == "completed":
        status = STATUS_COMPLETED
    elif status == "partial":
        status = STATUS_PARTIAL
    elif status == "blocked":
        status = STATUS_BLOCKED
    elif status == "error":
        status = STATUS_BLOCKED

    findings = interpret_pcap_results(parsed_data)
    from utils.pcap_resilience import attach_resilience_to_findings

    findings = attach_resilience_to_findings(findings)

    success = bool(analysis.get("success")) and status != STATUS_BLOCKED
    summary = build_pcap_result_summary(parsed_data, status=status, finding_count=len(findings))

    return {
        "success": success,
        "status": status,
        "parsed_data": parsed_data,
        "warnings": list(analysis.get("warnings") or []),
        "errors": list(analysis.get("errors") or []),
        "raw_output": analysis.get("raw_output") or redact_secrets_from_text(summary),
        "interpreter_findings": findings,
        "summary": summary,
        "sensitive_detected": bool(analysis.get("sensitive_detected")),
    }

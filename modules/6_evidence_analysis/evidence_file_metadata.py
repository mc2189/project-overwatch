"""Local document and image metadata review for Project Overwatch."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from utils.file_metadata_extractors import extract_file_metadata
from utils.file_metadata_interpreter import interpret_file_metadata_results
from utils.file_metadata_storage import is_supported_metadata_filename
from utils.result_status import STATUS_BLOCKED, STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_PARTIAL
from utils.security import redact_secrets_from_text
from utils.target_detection import file_target_type, get_target_type

MODULE_ID = "evidence_file_metadata"


def _privacy_notes(files: list[dict[str, Any]]) -> list[str]:
    notes: list[str] = []
    if any((row.get("privacy_flags") or {}).get("gps_present") for row in files):
        notes.append("GPS/location metadata present — review before sharing externally.")
    if any((row.get("privacy_flags") or {}).get("author_present") for row in files):
        notes.append("Author/creator metadata present — treat names as privacy-sensitive.")
    if any((row.get("privacy_flags") or {}).get("company_present") for row in files):
        notes.append("Company/template metadata present — review internal exposure risk.")
    return notes


def _build_summary(parsed_data: dict[str, Any], *, finding_count: int) -> str:
    files = list(parsed_data.get("files") or [])
    if not files:
        return "File metadata review could not complete — no files were supplied."
    notable = int(parsed_data.get("notable_count") or 0)
    names = ", ".join(row.get("filename", "file") for row in files[:3])
    suffix = f" (+{len(files) - 3} more)" if len(files) > 3 else ""
    privacy = _privacy_notes(files)
    privacy_text = f" Privacy notes: {privacy[0]}" if privacy else ""
    return (
        f"File metadata review completed for {len(files)} file(s) ({names}{suffix}). "
        f"{notable} file(s) with notable metadata. {finding_count} advisory finding(s) created."
        f"{privacy_text}"
    )


def _build_raw_output(parsed_data: dict[str, Any]) -> str:
    lines = [f"File metadata review — {parsed_data.get('file_count', 0)} file(s)"]
    for row in parsed_data.get("files") or []:
        flags = row.get("privacy_flags") or {}
        gps = "GPS=yes" if flags.get("gps_present") else "GPS=no"
        lines.append(
            f"- {row.get('filename')} [{row.get('extension')}] "
            f"status={row.get('extraction_status')} notable={row.get('notable')} {gps}"
        )
    return "\n".join(lines)


def run_file_metadata_review(target: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Review metadata for one or more locally uploaded files."""
    options = options or {}
    uploaded_files = list(options.get("uploaded_files") or [])
    target_type = options.get("target_type") or get_target_type(target)

    if options.get("mock_data") is not None:
        parsed_data = dict(options["mock_data"])
        findings = interpret_file_metadata_results(parsed_data)
        status = str(options.get("mock_status") or STATUS_COMPLETED)
        return {
            "module_id": MODULE_ID,
            "success": status != STATUS_BLOCKED,
            "status": status,
            "summary": _build_summary(parsed_data, finding_count=len(findings)),
            "raw_output": _build_raw_output(parsed_data),
            "findings": [],
            "warnings": list(options.get("mock_warnings") or []),
            "errors": list(options.get("mock_errors") or []),
            "data": parsed_data,
            "interpreter_findings": findings,
        }

    if not uploaded_files:
        message = "No uploaded files were supplied for metadata review."
        return {
            "module_id": MODULE_ID,
            "success": False,
            "status": STATUS_BLOCKED,
            "summary": message,
            "raw_output": message,
            "findings": [],
            "warnings": [],
            "errors": [message],
            "data": {"files": [], "file_count": 0, "target": target, "target_type": target_type},
            "interpreter_findings": interpret_file_metadata_results({"files": []}),
        }

    warnings: list[str] = []
    file_rows: list[dict[str, Any]] = []
    for item in uploaded_files:
        filename = str(item.get("filename") or target or "upload")
        storage_path = item.get("storage_path")
        if not storage_path:
            warnings.append(f"No storage path for {filename} — skipped.")
            continue
        path = Path(storage_path)
        if not path.is_file():
            warnings.append(f"Stored file missing for {filename} — skipped.")
            continue
        row = extract_file_metadata(path, filename=filename)
        if item.get("sha256"):
            row["sha256"] = item["sha256"]
        if item.get("size_bytes") is not None:
            row["size_bytes"] = item["size_bytes"]
        if not is_supported_metadata_filename(filename):
            row["extraction_status"] = "unsupported"
            row["supported"] = False
        file_rows.append(row)

    if not file_rows:
        message = "No readable uploaded files were available for metadata review."
        return {
            "module_id": MODULE_ID,
            "success": False,
            "status": STATUS_BLOCKED,
            "summary": message,
            "raw_output": message,
            "findings": [],
            "warnings": warnings,
            "errors": [message],
            "data": {"files": [], "file_count": 0, "target": target, "target_type": target_type},
            "interpreter_findings": interpret_file_metadata_results({"files": []}),
        }

    notable_count = sum(1 for row in file_rows if row.get("notable"))
    partial_count = sum(1 for row in file_rows if row.get("extraction_status") in {"partial", "unavailable"})
    unsupported_count = sum(1 for row in file_rows if row.get("extraction_status") == "unsupported")
    parsed_data = {
        "target": target,
        "target_type": file_target_type(file_rows[0]["filename"]) if file_rows else target_type,
        "files": file_rows,
        "file_count": len(file_rows),
        "notable_count": notable_count,
        "partial_count": partial_count,
        "unsupported_count": unsupported_count,
        "privacy_notes": _privacy_notes(file_rows),
        "filenames": [row.get("filename") for row in file_rows],
    }
    findings = interpret_file_metadata_results(parsed_data)
    status = STATUS_COMPLETED
    if partial_count or unsupported_count:
        status = STATUS_COMPLETED_WITH_WARNINGS
    if partial_count == len(file_rows):
        status = STATUS_PARTIAL

    summary = _build_summary(parsed_data, finding_count=len(findings))
    return {
        "module_id": MODULE_ID,
        "success": True,
        "status": status,
        "summary": redact_secrets_from_text(summary),
        "raw_output": redact_secrets_from_text(_build_raw_output(parsed_data)),
        "findings": [],
        "warnings": warnings,
        "errors": [],
        "data": parsed_data,
        "interpreter_findings": findings,
    }

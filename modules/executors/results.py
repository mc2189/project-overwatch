"""Standard module result construction for executor handlers."""

from __future__ import annotations

from typing import Any

from utils.evidence_model import observation_evidence_for_module
from utils.module_sdk import build_module_result, normalise_result, validate_module_result

def _observation_evidence_kwargs(module_id: str, result: dict[str, Any]) -> dict[str, Any]:
    """Build observation evidence fields from module defaults and run result."""
    meta = observation_evidence_for_module(module_id, result)
    return {
        key: meta[key]
        for key in (
            "evidence_type",
            "source_name",
            "source_url",
            "reliability",
            "collection_method",
            "collected_at",
            "module_version",
        )
        if meta.get(key) is not None
    }


def _prepare_module_result(result: dict[str, Any]) -> dict[str, Any]:
    """Normalise and attach non-fatal validation notes to a module result."""
    normalized = normalise_result(result)
    validation = validate_module_result(normalized)
    if validation["errors"]:
        for message in validation["errors"]:
            note = f"Result validation error: {message}"
            if note not in normalized["warnings"]:
                normalized["warnings"].append(note)
    for message in validation["warnings"]:
        note = f"Result validation: {message}"
        if note not in normalized["warnings"]:
            normalized["warnings"].append(note)
    return normalized


def make_result(
    module_id: str,
    *,
    success: bool,
    status: str,
    summary: str,
    raw_output: str = "",
    findings: list[str] | None = None,
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
    parsed_data: dict[str, Any] | None = None,
    interpreter_findings: list[dict[str, Any]] | None = None,
    selected_options: dict[str, Any] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a standard execution result payload."""
    result = build_module_result(
        module_id,
        status,
        summary,
        success=success,
        data=data or parsed_data,
        findings=findings,
        warnings=warnings,
        errors=errors,
        raw_output=raw_output,
        evidence=evidence,
    )
    if interpreter_findings is not None:
        result["interpreter_findings"] = interpreter_findings
    if selected_options is not None:
        result["selected_options"] = selected_options
    if parsed_data is not None:
        result["parsed_data"] = parsed_data
        if not result.get("data"):
            result["data"] = parsed_data
    return _prepare_module_result(result)


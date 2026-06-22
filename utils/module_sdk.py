"""Module development SDK — standard result contract and registry validation."""

from __future__ import annotations

from typing import Any

from modules.module_registry import MODULES, ModuleEntry
from utils.result_status import (
    STATUS_BLOCKED,
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_WARNINGS,
    STATUS_ERROR,
    STATUS_PARTIAL,
    is_success_status,
    normalize_run_status,
)

# Standard result statuses (aligned with utils.result_status)
STATUS_COMPLETED = STATUS_COMPLETED
STATUS_COMPLETED_WITH_WARNINGS = STATUS_COMPLETED_WITH_WARNINGS
STATUS_PARTIAL = STATUS_PARTIAL
STATUS_BLOCKED = STATUS_BLOCKED
STATUS_ERROR = STATUS_ERROR

STANDARD_STATUSES: frozenset[str] = frozenset(
    {
        STATUS_COMPLETED,
        STATUS_COMPLETED_WITH_WARNINGS,
        STATUS_PARTIAL,
        STATUS_BLOCKED,
        STATUS_ERROR,
    }
)

REQUIRED_REGISTRY_FIELDS: tuple[str, ...] = (
    "module_id",
    "display_name",
    "category",
    "status",
    "mode",
    "risk_level",
    "implemented",
    "requires_authorisation",
    "requires_api_key",
    "accepted_target_types",
)


def build_module_result(
    module_id: str,
    status: str,
    summary: str,
    *,
    success: bool = True,
    data: dict[str, Any] | None = None,
    findings: list[Any] | None = None,
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
    raw_output: str | None = None,
    evidence: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build a standard module execution result dictionary."""
    normalized_status = normalize_run_status(status)
    return {
        "module_id": module_id,
        "success": success,
        "status": normalized_status,
        "summary": summary or "",
        "raw_output": raw_output or "",
        "findings": list(findings or []),
        "warnings": list(warnings or []),
        "errors": list(errors or []),
        "data": dict(data or {}),
        "evidence": list(evidence or []),
    }


def add_warning(result: dict[str, Any], warning: str) -> dict[str, Any]:
    if warning:
        result.setdefault("warnings", []).append(warning)
    return result


def add_error(result: dict[str, Any], error: str) -> dict[str, Any]:
    if error:
        result.setdefault("errors", []).append(error)
    return result


def add_finding(result: dict[str, Any], finding: Any) -> dict[str, Any]:
    if finding is not None:
        result.setdefault("findings", []).append(finding)
    return result


def is_successful_result(result: dict[str, Any]) -> bool:
    if "success" in result:
        return bool(result["success"]) and is_success_status(result.get("status"))
    return is_success_status(result.get("status"))


def normalise_result(result: dict[str, Any]) -> dict[str, Any]:
    """Normalise a module result, preserving legacy extension fields."""
    normalized: dict[str, Any] = dict(result)

    normalized["module_id"] = str(normalized.get("module_id") or "unknown")
    normalized["status"] = normalize_run_status(normalized.get("status"))
    normalized["summary"] = str(normalized.get("summary") or "")
    normalized["raw_output"] = str(normalized.get("raw_output") or "")

    for key in ("findings", "warnings", "errors", "evidence"):
        value = normalized.get(key)
        if value is None:
            normalized[key] = []
        elif isinstance(value, list):
            normalized[key] = list(value)
        else:
            normalized[key] = [value]

    parsed_data = normalized.get("parsed_data")
    data = normalized.get("data")
    if isinstance(parsed_data, dict) and not data:
        normalized["data"] = dict(parsed_data)
    elif isinstance(data, dict) and not parsed_data:
        normalized["parsed_data"] = dict(data)
    elif isinstance(data, dict):
        normalized["data"] = dict(data)
        if parsed_data is None:
            normalized["parsed_data"] = dict(data)
    elif isinstance(parsed_data, dict):
        normalized["parsed_data"] = dict(parsed_data)
        if not normalized.get("data"):
            normalized["data"] = dict(parsed_data)
    else:
        normalized["data"] = {}

    if "success" not in normalized:
        normalized["success"] = is_success_status(normalized["status"]) and not normalized["errors"]
    else:
        normalized["success"] = bool(normalized["success"])

    return normalized


def validate_module_result(result: dict[str, Any]) -> dict[str, Any]:
    """Validate a normalised module result. Returns warnings/errors without raising."""
    warnings: list[str] = []
    errors: list[str] = []

    if not result.get("module_id") or result.get("module_id") == "unknown":
        errors.append("missing module_id")
    if not result.get("summary"):
        warnings.append("missing summary")
    status = normalize_run_status(result.get("status"))
    if status not in STANDARD_STATUSES:
        warnings.append(f"non-standard status: {status}")
    for key in ("findings", "warnings", "errors", "evidence"):
        if key in result and result[key] is not None and not isinstance(result[key], list):
            warnings.append(f"{key} should be a list")
    if "data" in result and result["data"] is not None and not isinstance(result["data"], dict):
        warnings.append("data should be a dict")
    if result.get("success") and status in {STATUS_BLOCKED, STATUS_ERROR}:
        warnings.append("success=True but status indicates failure")
    if not result.get("success") and status in {STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_PARTIAL}:
        warnings.append("success=False but status indicates success")

    return {"ok": not errors, "warnings": warnings, "errors": errors}


def validate_module_metadata(module: ModuleEntry) -> dict[str, Any]:
    """Validate a single registry entry. Returns warnings/errors without raising."""
    warnings: list[str] = []
    errors: list[str] = []

    for field in REQUIRED_REGISTRY_FIELDS:
        if not hasattr(module, field):
            errors.append(f"missing field: {field}")

    if not module.module_id:
        errors.append("empty module_id")
    if not module.display_name:
        errors.append("empty display_name")
    if not module.category:
        warnings.append("missing category")
    if module.status not in {"active", "planned", "disabled"}:
        warnings.append(f"unexpected status: {module.status}")
    if not module.short_help and not module.description:
        warnings.append("missing short_help and description")
    if module.implemented and not module.accepted_target_types:
        errors.append("implemented module has no accepted_target_types")
    if module.implemented and module.status != "active":
        warnings.append("implemented module is not active")
    if module.requires_api_key and not module.api_key_names:
        warnings.append("requires_api_key but api_key_names is empty")

    return {
        "ok": not errors,
        "warnings": warnings,
        "errors": errors,
        "module_id": module.module_id,
    }


def validate_module_registry(modules: list[ModuleEntry] | None = None) -> dict[str, Any]:
    """Validate all registry entries. Returns aggregate warnings/errors without raising."""
    entries = modules if modules is not None else MODULES
    by_module: dict[str, dict[str, Any]] = {}
    warnings: list[str] = []
    errors: list[str] = []
    seen_ids: set[str] = set()

    for module in entries:
        if module.module_id in seen_ids:
            errors.append(f"duplicate module_id: {module.module_id}")
        seen_ids.add(module.module_id)
        result = validate_module_metadata(module)
        by_module[module.module_id] = result
        for warning in result["warnings"]:
            warnings.append(f"{module.module_id}: {warning}")
        for error in result["errors"]:
            errors.append(f"{module.module_id}: {error}")

    return {
        "ok": not errors,
        "module_count": len(entries),
        "modules": by_module,
        "warnings": warnings,
        "errors": errors,
    }


def validate_implemented_modules(modules: list[ModuleEntry] | None = None) -> dict[str, Any]:
    """Validate only implemented modules — used by smoke checks and runtime health."""
    entries = [module for module in (modules or MODULES) if module.implemented]
    return validate_module_registry(entries)

"""Module execution dispatcher for Project Overwatch."""

from __future__ import annotations

import importlib.util
import json
import sqlite3
from pathlib import Path
from typing import Any

from database.db_setup import create_observation, create_operation_log
from modules.module_registry import get_module, is_executable

PROJECT_ROOT = Path(__file__).resolve().parent.parent
NMAP_MODULE_PATH = PROJECT_ROOT / "modules" / "2_infrastructure" / "infra_nmap.py"

_nmap_handlers: tuple[Any, Any] | None = None
_nmap_load_error: str | None = None
_nmap_load_attempted = False


def make_result(
    module_id: str,
    *,
    success: bool,
    status: str,
    summary: str,
    raw_output: str = "",
    findings: list[str] | None = None,
    errors: list[str] | None = None,
) -> dict[str, Any]:
    """Build a standard execution result payload."""
    return {
        "module_id": module_id,
        "success": success,
        "status": status,
        "summary": summary,
        "raw_output": raw_output,
        "findings": findings or [],
        "errors": errors or [],
    }


def _load_nmap_handlers() -> None:
    global _nmap_handlers, _nmap_load_error, _nmap_load_attempted

    if _nmap_load_attempted:
        return

    _nmap_load_attempted = True

    if not NMAP_MODULE_PATH.is_file():
        _nmap_load_error = f"Module file not found: {NMAP_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("infra_nmap", NMAP_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {NMAP_MODULE_PATH}")
        infra_nmap = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(infra_nmap)
        _nmap_handlers = (infra_nmap.run_nmap_scan, infra_nmap.parse_nmap_problems)
    except Exception as exc:
        _nmap_load_error = str(exc)


def is_runtime_ready(module_id: str) -> bool:
    """Return True when a module's backend is loaded and ready to run."""
    if module_id == "infra_nmap":
        _load_nmap_handlers()
        return _nmap_handlers is not None
    return False


def get_runtime_error(module_id: str) -> str | None:
    """Return a load-time error message for a module, if any."""
    if module_id == "infra_nmap":
        _load_nmap_handlers()
        return _nmap_load_error
    return None


def _save_recon_output(conn: sqlite3.Connection, target: str, raw_output: str) -> None:
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM targets WHERE domain_or_ip = ?", (target,))
    target_row = cursor.fetchone()
    if target_row:
        cursor.execute(
            "INSERT INTO recon_data (target_id, open_ports) VALUES (?, ?)",
            (target_row[0], raw_output),
        )
        conn.commit()


def _persist_investigation_records(
    conn: sqlite3.Connection,
    *,
    case_id: int,
    entity_id: int | None,
    module_id: str,
    target: str,
    result: dict[str, Any],
    authorisation_confirmed: bool,
    options: dict[str, Any],
) -> None:
    """Save operation and observation records for a completed module run."""
    create_operation_log(
        case_id,
        module_id,
        target,
        result["status"],
        authorisation_confirmed=authorisation_confirmed,
        summary=result["summary"],
        conn=conn,
    )

    if entity_id is None or result["status"] != "completed":
        return

    create_observation(
        case_id,
        entity_id,
        module_id,
        "network_scan",
        "Nmap scan result",
        summary=result["summary"],
        data_json=json.dumps(
            {
                "module_id": module_id,
                "success": result["success"],
                "status": result["status"],
                "findings_count": len(result["findings"]),
                "findings": result["findings"],
                "options": {
                    "nmap_fast": bool(options.get("nmap_fast", False)),
                    "nmap_scripts": bool(options.get("nmap_scripts", False)),
                },
            }
        ),
        raw_output=result["raw_output"],
        conn=conn,
    )


def _execute_nmap(
    module_id: str,
    target: str,
    options: dict[str, Any],
    db_context: sqlite3.Connection | None,
    authorisation_confirmed: bool,
    case_id: int | None,
    entity_id: int | None,
) -> dict[str, Any]:
    _load_nmap_handlers()
    if _nmap_handlers is None:
        error_message = _nmap_load_error or "Nmap module is not available."
        return make_result(
            module_id,
            success=False,
            status="error",
            summary="Nmap module is not available.",
            errors=[error_message],
        )

    run_nmap_scan, _parse_nmap_problems = _nmap_handlers
    nmap_fast = bool(options.get("nmap_fast", False))
    nmap_scripts = bool(options.get("nmap_scripts", False))

    if nmap_scripts and not authorisation_confirmed:
        return make_result(
            module_id,
            success=False,
            status="blocked",
            summary="Nmap vuln scripts require authorisation confirmation.",
            errors=["authorisation_required_for_vuln_scripts"],
        )

    flags = ["-sV"]
    if nmap_fast:
        flags.append("-F")
    if nmap_scripts:
        flags.append("--script vuln")

    raw_output, findings = run_nmap_scan(target, flags)
    is_error = raw_output.startswith("Error")

    if is_error:
        result = make_result(
            module_id,
            success=False,
            status="error",
            summary=f"Nmap scan failed for {target}.",
            raw_output=raw_output,
            findings=findings,
            errors=[raw_output],
        )
    else:
        result = make_result(
            module_id,
            success=True,
            status="completed",
            summary=f"Nmap scan completed for {target}.",
            raw_output=raw_output,
            findings=findings,
        )

    if db_context is not None:
        if not is_error:
            _save_recon_output(db_context, target, raw_output)
        if case_id is not None:
            _persist_investigation_records(
                db_context,
                case_id=case_id,
                entity_id=entity_id,
                module_id=module_id,
                target=target,
                result=result,
                authorisation_confirmed=authorisation_confirmed,
                options=options,
            )

    return result


def execute_module(
    module_id: str,
    target: str,
    options: dict[str, Any] | None = None,
    db_context: sqlite3.Connection | None = None,
    authorisation_confirmed: bool = False,
    case_id: int | None = None,
    entity_id: int | None = None,
) -> dict[str, Any]:
    """
    Execute a registered module and return a structured result dictionary.

    Execution is blocked when the module is missing, not implemented, not active,
    not executable, or requires authorisation that has not been confirmed.
    """
    options = options or {}

    module = get_module(module_id)
    if module is None:
        return make_result(
            module_id,
            success=False,
            status="blocked",
            summary="Module is not registered.",
            errors=["unknown_module_id"],
        )

    if not module.implemented:
        return make_result(
            module_id,
            success=False,
            status="blocked",
            summary=f"{module.display_name} is not implemented.",
            errors=["implemented=False"],
        )

    if module.status != "active":
        return make_result(
            module_id,
            success=False,
            status="blocked",
            summary=f"{module.display_name} is not active.",
            errors=[f"status={module.status}"],
        )

    if not is_executable(module):
        return make_result(
            module_id,
            success=False,
            status="blocked",
            summary=f"{module.display_name} is not executable.",
            errors=["not_executable"],
        )

    if module.requires_authorisation and not authorisation_confirmed:
        return make_result(
            module_id,
            success=False,
            status="blocked",
            summary="Authorisation confirmation is required before running this module.",
            errors=["authorisation_required"],
        )

    if module_id == "infra_nmap":
        if not is_runtime_ready(module_id):
            error_message = get_runtime_error(module_id) or "Nmap runtime is not ready."
            return make_result(
                module_id,
                success=False,
                status="error",
                summary="Nmap module is not available.",
                errors=[error_message],
            )
        return _execute_nmap(
            module_id,
            target,
            options,
            db_context,
            authorisation_confirmed,
            case_id,
            entity_id,
        )

    # TODO(v0.5): Route additional implemented modules here.
    return make_result(
        module_id,
        success=False,
        status="blocked",
        summary=f"{module.display_name} is registered but not wired in the executor yet.",
        errors=["not_wired"],
    )

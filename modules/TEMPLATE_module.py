"""
TEMPLATE — example module skeleton for Project Overwatch.

This file is NOT registered in modules/module_registry.py and is NOT executed by the app.
Copy and adapt when building a new collection module.

Checklist before registering:
  1. Add a ModuleEntry to modules/module_registry.py (module_id, target types, mode, etc.)
  2. Implement run_<your_module>() returning a standard result via build_module_result()
  3. Wire the executor in modules/executor.py (preflight + persistence hooks)
  4. Add a findings interpreter if the module produces advisory findings
  5. Add evidence capture in utils/evidence_capture.py if raw artefacts should be stored
  6. Run: python scripts/smoke_check.py
"""

from __future__ import annotations

from typing import Any

from utils.module_sdk import (
    STATUS_BLOCKED,
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_WARNINGS,
    add_error,
    add_finding,
    add_warning,
    build_module_result,
    normalise_result,
)


def run_template_example(
    target: str,
    *,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Expected run function signature pattern for a passive lookup module.

    Parameters
    ----------
    target:
        Normalised target string (domain, IPv4, URL, etc.) from the executor.
    options:
        Module-specific options from Run Operation / Entity Workspace.

    Returns
    -------
    dict
        Standard module result — always pass through normalise_result() before returning.
    """
    options = options or {}

    if not target.strip():
        result = build_module_result(
            "template_example",
            STATUS_BLOCKED,
            "No target provided.",
            success=False,
            errors=["empty_target"],
        )
        return normalise_result(result)

    # --- collection logic would go here (no network in this template) ---
    collected_data = {
        "target": target,
        "example_field": "example value",
        "options_used": options,
    }
    raw_output = f"Template lookup for {target}\nexample_field=example value\n"

    result = build_module_result(
        "template_example",
        STATUS_COMPLETED,
        f"Template lookup completed for {target}.",
        success=True,
        data=collected_data,
        raw_output=raw_output,
        findings=[
            "Example human-readable finding line (legacy string form).",
        ],
        evidence=[
            {
                "title": "Template raw summary",
                "summary": "Example evidence locker artefact metadata.",
                "content_text": raw_output,
                "source_name": "template_source",
                "evidence_type": "direct_observation",
                "reliability": "medium",
            }
        ],
    )

    add_warning(result, "This is an example warning — collection was simulated.")
    add_finding(result, "Additional finding added via add_finding().")

    # Example advisory finding dict (interpreter-style — usually produced by a separate interpreter)
    result["interpreter_findings"] = [
        {
            "title": "Example advisory finding",
            "severity": "info",
            "confidence": 60,
            "explanation": "Replace with interpret_<module>_results() output in real modules.",
            "suggested_actions": ["Review the collected data manually."],
        }
    ]

    if options.get("simulate_error"):
        add_error(result, "Simulated error for testing.")
        result["status"] = STATUS_COMPLETED_WITH_WARNINGS
        result["success"] = True

    return normalise_result(result)


# Compatibility reminder:
# - accepted_target_types in the registry must match get_target_type() values
# - active modules that touch the target require authorisation_confirmed in the executor
# - API-key modules must declare api_key_names and pass settings preflight
# - Use utils/evidence_capture.capture_module_evidence() from the executor for locker storage

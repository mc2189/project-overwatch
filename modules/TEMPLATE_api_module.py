"""
TEMPLATE — API-backed passive module skeleton for Project Overwatch.

NOT registered in module_registry.py and NOT executed by the app.
Copy when implementing modules such as AbuseIPDB, GreyNoise, or Shodan.

Checklist:
  1. ModuleEntry in modules/module_registry.py (requires_api_key=True, api_key_names)
  2. Module file under modules/4_threat_intelligence/ (or appropriate category folder)
  3. utils/<provider>_interpreter.py for cautious advisory findings
  4. Executor wiring + persistence hooks in modules/executor.py
  5. evidence_capture helper in utils/evidence_capture.py
  6. Settings provider row in utils/settings_manager.py API_PROVIDERS
  7. Run: python scripts/smoke_check.py && python scripts/security_audit.py

See intel_virustotal.py for a complete reference implementation.
"""

from __future__ import annotations

from typing import Any

import requests

from utils.api_module_helpers import (
    api_key_header,
    classify_provider_http_status,
    missing_api_key_blocked_result,
    redact_api_error_text,
    request_timeout_seconds,
)
from utils.result_status import STATUS_COMPLETED, resolve_collection_status
from utils.security import is_private_or_local_ip, redact_secrets_from_text


MODULE_ID = "template_api_example"
ENV_KEY_NAME = "EXAMPLE_API_KEY"
PROVIDER_LABEL = "Example Provider"
API_BASE = "https://api.example.com/v1"


def _request_json(
    path: str,
    *,
    api_key: str,
    session: requests.Session | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    http = session or requests
    url = f"{API_BASE}/{path.lstrip('/')}"
    meta: dict[str, Any] = {"status_code": None, "path": path}
    try:
        response = http.get(
            url,
            headers=api_key_header(api_key, header_name="Authorization"),
            timeout=request_timeout_seconds(),
        )
    except requests.Timeout:
        meta["error"] = f"{PROVIDER_LABEL} request timed out."
        return None, meta
    except requests.RequestException as exc:
        meta["error"] = redact_api_error_text(str(exc))
        return None, meta

    meta["status_code"] = response.status_code
    try:
        payload = response.json()
    except ValueError:
        payload = None
        meta["error"] = redact_api_error_text(response.text[:500])

    if response.status_code >= 400:
        meta["error"] = redact_api_error_text(
            payload.get("message", "") if isinstance(payload, dict) else response.text[:300]
        )
        return payload if isinstance(payload, dict) else None, meta
    return payload if isinstance(payload, dict) else None, meta


def run_template_api_example(
    target: str,
    *,
    api_key: str,
    target_type: str | None = None,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Example API module run function — replace with real provider logic."""
    from utils.target_detection import get_target_type

    options = options or {}
    cleaned = target.strip()
    resolved_type = target_type or get_target_type(cleaned)

    if not cleaned:
        return {
            "success": False,
            "status": "blocked",
            "errors": ["No target provided."],
            "parsed_data": {"target": cleaned, "target_type": resolved_type},
            "raw_output": "Error: no target provided.",
            "findings": [],
            "warnings": [],
            "evidence": [],
        }

    if resolved_type == "ipv4" and is_private_or_local_ip(cleaned):
        message = "Private/local IP address — public reputation lookup is not applicable."
        return {
            "success": True,
            "status": STATUS_COMPLETED,
            "parsed_data": {"target": cleaned, "target_type": resolved_type, "private_local_ip": True},
            "raw_output": message,
            "findings": [message],
            "warnings": [],
            "errors": [],
            "evidence": [],
        }

    if not api_key or not api_key.strip():
        return missing_api_key_blocked_result(
            module_id=MODULE_ID,
            env_key_name=ENV_KEY_NAME,
            provider_label=PROVIDER_LABEL,
            target=cleaned,
            target_type=resolved_type,
        )

    if options.get("mock_response") is not None:
        payload = options["mock_response"]
        api_meta = {"status_code": 200, "path": "mock", "mock": True}
    else:
        payload, api_meta = _request_json(f"lookup/{cleaned}", api_key=api_key.strip())

    http_status, _, http_warnings, http_errors = classify_provider_http_status(api_meta.get("status_code"))
    parsed_data = {
        "target": cleaned,
        "target_type": resolved_type,
        "provider_payload": payload,
        "api": api_meta,
    }
    warnings = list(http_warnings)
    errors = list(http_errors)
    has_core_data = bool(payload)
    if http_status in {"blocked", "error"} and not has_core_data:
        status = http_status
        success = False
    else:
        status = resolve_collection_status(warnings=warnings, errors=errors, has_core_data=has_core_data)
        success = status in {"completed", "completed_with_warnings", "partial"}

    return {
        "success": success,
        "status": status,
        "parsed_data": parsed_data,
        "raw_output": redact_secrets_from_text(f"{PROVIDER_LABEL} lookup: {cleaned}"),
        "findings": [f"{PROVIDER_LABEL} lookup completed for {cleaned}."],
        "warnings": warnings,
        "errors": errors if not success and not has_core_data else [],
        "evidence": [],
    }

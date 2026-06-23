"""Shared helpers for API-backed passive intelligence modules."""

from __future__ import annotations

import time
from typing import Any

from utils.result_status import (
    STATUS_BLOCKED,
    STATUS_COMPLETED,
    STATUS_COMPLETED_WITH_WARNINGS,
    STATUS_ERROR,
    STATUS_PARTIAL,
)
from utils.security import redact_secrets_from_text
from version import PROJECT_VERSION

API_REPUTATION_MODULE_IDS: frozenset[str] = frozenset({
    "intel_virustotal",
    "intel_abuseipdb",
    "intel_greynoise",
    "intel_shodan",
    "intel_urlhaus",
})

_LAST_API_REQUEST_MONOTONIC: float | None = None


def project_user_agent() -> str:
    """Return the standard Project Overwatch HTTP User-Agent."""
    return f"ProjectOverwatch/{PROJECT_VERSION}"


def request_timeout_seconds() -> int:
    """Return the configured default HTTP timeout for API modules."""
    try:
        from utils.settings_manager import default_timeout_seconds

        return default_timeout_seconds()
    except Exception:
        return 30


def respect_api_courtesy_delay() -> None:
    """Pause before a live API request if the previous lookup was too recent.

    Uses PROJECT_OVERWATCH_RATE_LIMIT_SECONDS (default 1.5s). Applies across
    VirusTotal, AbuseIPDB, GreyNoise, Shodan and future API reputation modules so
    Run Operation, Entity Workspace, and Batch Queue do not hammer providers.
    """
    global _LAST_API_REQUEST_MONOTONIC

    delay = rate_limit_seconds()
    if delay <= 0:
        return

    now = time.monotonic()
    if _LAST_API_REQUEST_MONOTONIC is not None:
        elapsed = now - _LAST_API_REQUEST_MONOTONIC
        remaining = delay - elapsed
        if remaining > 0:
            time.sleep(remaining)
    _LAST_API_REQUEST_MONOTONIC = time.monotonic()


def rate_limit_seconds() -> float:
    """Return configured courtesy delay between API reputation lookups."""
    try:
        from utils.settings_manager import rate_limit_seconds as settings_rate_limit

        return settings_rate_limit()
    except Exception:
        return 1.5


def reset_api_courtesy_delay_for_tests() -> None:
    """Reset inter-request timing (smoke tests only)."""
    global _LAST_API_REQUEST_MONOTONIC
    _LAST_API_REQUEST_MONOTONIC = None


def api_key_header(api_key: str, *, header_name: str = "x-apikey") -> dict[str, str]:
    """Build common API request headers (never log the returned dict in production)."""
    return {
        header_name: api_key,
        "Accept": "application/json",
        "User-Agent": project_user_agent(),
    }


def classify_provider_http_status(status_code: int | None) -> tuple[str, bool, list[str], list[str]]:
    """Map HTTP status codes to module result status, success, warnings, and errors."""
    if status_code is None:
        return STATUS_ERROR, False, [], ["API request failed before a response was received."]
    if status_code == 200:
        return STATUS_COMPLETED, True, [], []
    if status_code in {400, 404}:
        return STATUS_COMPLETED, True, ["Provider returned no data for this resource."], []
    if status_code in {401, 403}:
        return (
            STATUS_BLOCKED,
            False,
            [],
            ["API key was rejected (unauthorised). Check your local .env configuration."],
        )
    if status_code == 429:
        return (
            STATUS_COMPLETED_WITH_WARNINGS,
            True,
            ["Provider rate limit reached — retry later or reduce batch frequency."],
            [],
        )
    if status_code >= 500:
        return STATUS_ERROR, False, [], [f"Provider error (HTTP {status_code}). Retry later."]
    return STATUS_PARTIAL, False, [], [f"Unexpected provider response (HTTP {status_code})."]


def missing_api_key_blocked_result(
    *,
    module_id: str,
    env_key_name: str,
    provider_label: str,
    target: str,
    target_type: str,
    message: str | None = None,
) -> dict[str, Any]:
    """Standard blocked result when a required API key is not configured."""
    detail = message or f"{provider_label} API key is not configured."
    guidance = f"{detail} Add {env_key_name} to your local .env file."
    return {
        "success": False,
        "status": STATUS_BLOCKED,
        "parsed_data": {
            "target": target,
            "target_type": target_type,
            "api": {"status_code": None, "error": detail},
        },
        "raw_output": redact_secrets_from_text(guidance),
        "findings": [],
        "warnings": [],
        "errors": [guidance],
        "evidence": [
            {
                "title": f"{provider_label} API key not configured",
                "summary": guidance,
                "content_text": guidance,
                "content_type": "text/plain",
                "source_name": provider_label,
                "evidence_type": "system_generated",
                "reliability": "high",
                "collection_method": "policy_skip",
            }
        ],
    }


def redact_api_error_text(text: str | None) -> str:
    """Redact secrets from API error bodies before persistence or display."""
    if not text:
        return ""
    return redact_secrets_from_text(text)

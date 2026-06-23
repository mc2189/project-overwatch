"""Display formatting helpers for Project Overwatch results."""

from __future__ import annotations

import re
from datetime import datetime, timezone


def format_wayback_timestamp(value: str | None) -> str | None:
    """Format a Wayback CDX timestamp into readable UTC text."""
    if not value:
        return None
    cleaned = str(value).strip()
    if not cleaned or cleaned.lower() == "none":
        return None
    try:
        parsed = datetime.strptime(cleaned[:14], "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        return parsed.strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return cleaned


def display_or_unavailable(value: str | None, *, unavailable: str = "not available") -> str:
    if value is None:
        return unavailable
    cleaned = str(value).strip()
    if not cleaned or cleaned.lower() == "none":
        return unavailable
    return cleaned


def format_wayback_user_error(error: str | None) -> str:
    """Return concise Wayback failure wording without raw service URLs."""
    if not error:
        return "Wayback lookup unavailable during this run."
    lowered = error.lower()
    if "timeout" in lowered or "timed out" in lowered:
        return "Wayback lookup unavailable during this run: request timed out."
    if "connection" in lowered:
        return "Wayback lookup unavailable during this run: connection error."
    status_match = re.search(r"\b(\d{3})\b", error)
    if status_match and ("error" in lowered or "for url" in lowered or "status" in lowered):
        return f"Wayback lookup unavailable during this run: service returned {status_match.group(1)}."
    return "Wayback lookup unavailable during this run."


def format_crt_sh_user_warning(
    *,
    status_code: int | None = None,
    technical_message: str | None = None,
) -> tuple[str, str | None]:
    """Return user-facing crt.sh warning and optional technical detail for raw output."""
    if status_code == 404:
        return (
            "crt.sh did not return certificate transparency rows for this query.",
            technical_message or "HTTP 404 from crt.sh",
        )
    if technical_message:
        lowered = technical_message.lower()
        if "timeout" in lowered or "timed out" in lowered:
            return (
                "Certificate transparency lookup timed out. crt.sh may be slow or unavailable.",
                technical_message,
            )
        if "rate limit" in lowered:
            return ("crt.sh rate limited the request. Try again later.", technical_message)
        if status_code and status_code >= 500:
            return (
                "crt.sh did not return certificate transparency rows for this query.",
                technical_message,
            )
        if status_code and status_code != 200:
            return (
                "crt.sh did not return certificate transparency rows for this query.",
                technical_message,
            )
        return (technical_message, None)
    return ("crt.sh did not return certificate transparency rows for this query.", None)

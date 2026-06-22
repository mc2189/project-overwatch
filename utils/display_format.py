"""Display formatting helpers for Project Overwatch results."""

from __future__ import annotations

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

"""Central target type detection for Project Overwatch."""

from __future__ import annotations

import re
from urllib.parse import urlparse

TARGET_TYPES: tuple[str, ...] = ("ipv4", "domain", "url", "email", "username", "unknown")

IPv4_PATTERN = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
DOMAIN_PATTERN = re.compile(
    r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)+$"
)
USERNAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_\-\.]{2,31}$")

TARGET_TYPE_LABELS: dict[str, str] = {
    "ipv4": "IPv4 address",
    "domain": "Domain",
    "url": "URL",
    "email": "Email address",
    "username": "Username-like value",
    "unknown": "Unknown",
}

ENTITY_TYPE_BY_TARGET: dict[str, str] = {
    "ipv4": "ip_address",
    "domain": "domain",
    "url": "domain",
    "email": "email",
    "username": "username",
    "unknown": "unknown",
}


def get_target_type(value: str) -> str:
    """Detect the target type from user input using simple local heuristics."""
    cleaned = value.strip()
    if not cleaned:
        return "unknown"

    if IPv4_PATTERN.match(cleaned):
        return "ipv4"

    if EMAIL_PATTERN.match(cleaned):
        return "email"

    lowered = cleaned.lower()
    if lowered.startswith(("http://", "https://")) or "://" in cleaned:
        return "url"

    if DOMAIN_PATTERN.match(cleaned):
        return "domain"

    if USERNAME_PATTERN.match(cleaned):
        return "username"

    return "unknown"


def target_type_label(target_type: str) -> str:
    """Return a human-readable label for a target type."""
    return TARGET_TYPE_LABELS.get(target_type, target_type.replace("_", " ").title())


def target_type_to_entity_type(target_type: str) -> str:
    """Map a detected target type to the investigation entity type."""
    return ENTITY_TYPE_BY_TARGET.get(target_type, "unknown")


def normalize_target_value(value: str, target_type: str | None = None) -> str:
    """Normalise a target for module execution where applicable."""
    cleaned = value.strip()
    detected = target_type or get_target_type(cleaned)
    if detected == "url":
        parsed = urlparse(cleaned if "://" in cleaned else f"https://{cleaned}")
        hostname = parsed.hostname or cleaned
        return hostname.lower().rstrip(".")
    if detected in {"domain", "ipv4"}:
        return cleaned.lower() if detected == "domain" else cleaned
    return cleaned

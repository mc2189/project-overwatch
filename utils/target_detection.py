"""Central target type detection for Project Overwatch."""

from __future__ import annotations

import re
from pathlib import Path
from urllib.parse import urlparse

TARGET_TYPES: tuple[str, ...] = (
    "ipv4",
    "domain",
    "url",
    "email",
    "username",
    "file",
    "image",
    "document",
    "pdf",
    "pcap",
    "pcapng",
    "unknown",
)

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
    "file": "File",
    "image": "Image file",
    "document": "Document file",
    "pdf": "PDF file",
    "pcap": "PCAP capture",
    "pcapng": "PCAPNG capture",
    "unknown": "Unknown",
}

ENTITY_TYPE_BY_TARGET: dict[str, str] = {
    "ipv4": "ip_address",
    "domain": "domain",
    "url": "domain",
    "email": "email",
    "username": "username",
    "file": "artefact",
    "image": "artefact",
    "document": "artefact",
    "pdf": "artefact",
    "pcap": "artefact",
    "pcapng": "artefact",
    "unknown": "unknown",
}

FILE_EXTENSION_TARGET_TYPES: dict[str, str] = {
    "jpg": "image",
    "jpeg": "image",
    "png": "image",
    "heic": "image",
    "heif": "image",
    "tif": "image",
    "tiff": "image",
    "pdf": "pdf",
    "docx": "document",
    "xlsx": "document",
    "pptx": "document",
    "txt": "document",
    "csv": "document",
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

    if lowered.endswith(".pcapng"):
        return "pcapng"
    if lowered.endswith(".pcap"):
        return "pcap"

    ext = Path(cleaned).suffix.lower().lstrip(".")
    if ext in FILE_EXTENSION_TARGET_TYPES:
        return FILE_EXTENSION_TARGET_TYPES[ext]

    return "unknown"


def file_target_type(filename: str) -> str:
    """Map a filename extension to a metadata review target type."""
    ext = Path(filename.strip()).suffix.lower().lstrip(".")
    return FILE_EXTENSION_TARGET_TYPES.get(ext, "file")


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

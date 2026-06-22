"""Redaction helpers for case reports before external sharing."""

from __future__ import annotations

import re
from typing import Literal

RedactionOption = Literal["ipv4", "email", "domain"]

IPV4_PATTERN = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")
DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b"
)

REDACTION_LABELS = {
    "ipv4": "[REDACTED_IP]",
    "email": "[REDACTED_EMAIL]",
    "domain": "[REDACTED_DOMAIN]",
}
CUSTOM_TERM_LABEL = "[REDACTED]"


def parse_custom_regex_patterns(raw_text: str) -> list[tuple[re.Pattern[str], str]]:
    """Parse lines of `pattern|||replacement` into compiled regex patterns."""
    patterns: list[tuple[re.Pattern[str], str]] = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if "|||" not in stripped:
            continue
        pattern_text, replacement = stripped.split("|||", 1)
        pattern_text = pattern_text.strip()
        replacement = replacement.strip() or CUSTOM_TERM_LABEL
        try:
            patterns.append((re.compile(pattern_text), replacement))
        except re.error:
            continue
    return patterns


def parse_custom_terms(raw_text: str) -> list[str]:
    """Parse one custom redaction term per line."""
    terms: list[str] = []
    for line in raw_text.splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#"):
            terms.append(stripped)
    return terms


def apply_redactions(
    text: str,
    options: set[RedactionOption],
    *,
    custom_terms: list[str] | None = None,
    custom_regex_patterns: list[tuple[re.Pattern[str], str]] | None = None,
) -> str:
    """Apply built-in and custom redaction patterns to report text."""
    if not text:
        return text

    redacted = text
    if "email" in options:
        redacted = EMAIL_PATTERN.sub(REDACTION_LABELS["email"], redacted)
    if "ipv4" in options:
        redacted = IPV4_PATTERN.sub(REDACTION_LABELS["ipv4"], redacted)
    if "domain" in options:
        redacted = DOMAIN_PATTERN.sub(REDACTION_LABELS["domain"], redacted)

    for term in custom_terms or []:
        if term:
            redacted = redacted.replace(term, CUSTOM_TERM_LABEL)

    for pattern, replacement in custom_regex_patterns or []:
        redacted = pattern.sub(replacement, redacted)

    return redacted

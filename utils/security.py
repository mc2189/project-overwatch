"""Security helpers: secret masking, redaction, env parsing, and target validation."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from typing import Any

REDACTED_SECRET = "[REDACTED_SECRET]"

# Key=value or key: value assignments (common config / log leaks).
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b("
    r"api[_-]?key|secret|token|password|passwd|authorization|auth|bearer|"
    r"access[_-]?key|client[_-]?secret|private[_-]?key"
    r")\s*[:=]\s*(\S+)"
)

_BEARER_PATTERN = re.compile(r"(?i)\bBearer\s+([A-Za-z0-9._\-+/=]{8,})")
_PRIVATE_KEY_BLOCK = re.compile(
    r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
)

# Provider-specific token shapes.
_AWS_ACCESS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_AWS_SECRET_KEY = re.compile(r"(?i)(?:aws[_-]?secret[_-]?access[_-]?key)\s*[:=]\s*([A-Za-z0-9/+=]{40})")
_GITHUB_TOKEN = re.compile(r"\b(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}\b")
_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[A-Za-z0-9\-]{10,}\b")
_VT_KEY = re.compile(r"\bvt_[a-z0-9]{20,}\b", re.IGNORECASE)
_STRIPE_KEY = re.compile(r"\b(?:sk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b")
_GENERIC_SK = re.compile(r"\bsk_[a-z0-9]{20,}\b", re.IGNORECASE)

# Standalone long high-entropy tokens (avoid matching dotted hostnames / semver).
_HIGH_ENTROPY_TOKEN = re.compile(
    r"(?<![./@])\b(?=[A-Za-z0-9+/=_\-]{32,}\b)"
    r"(?=[A-Za-z]*[0-9])(?=[0-9A-Za-z]*[A-Za-z])"
    r"[A-Za-z0-9+/=_\-]{32,}\b"
)

_PLACEHOLDER_MARKERS = (
    "your_",
    "example",
    "placeholder",
    "changeme",
    "replace_me",
    "xxx",
    "not configured",
    "insert_",
    "<",
    ">",
)

_SECRET_LIKE_PREFIXES = (
    "vt_",
    "ghp_",
    "github_pat_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "xoxs-",
    "sk_live_",
    "sk_test_",
    "pk_live_",
    "pk_test_",
    "sk-",
    "AKIA",
)

_UNSAFE_TARGET_CHARS = re.compile(r"[\x00-\x1f\x7f;|&$`<>()\\]")


def mask_secret(value: str | None, *, visible_prefix: int = 3, visible_suffix: int = 4) -> str:
    """Return a masked display value. Never use for logging or persistence."""
    if not value:
        return "not configured"
    cleaned = value.strip()
    if len(cleaned) <= visible_prefix + visible_suffix:
        return "****"
    prefix = cleaned[:visible_prefix]
    suffix = cleaned[-visible_suffix:]
    return f"{prefix}****{suffix}"


def _is_placeholder(value: str) -> bool:
    lowered = value.lower().strip()
    if not lowered:
        return True
    return any(marker in lowered for marker in _PLACEHOLDER_MARKERS)


def looks_like_secret(value: str | None) -> bool:
    """Return True when a standalone value resembles a credential or API key."""
    if value is None:
        return False
    text = str(value).strip()
    if not text or _is_placeholder(text):
        return False
    if _PRIVATE_KEY_BLOCK.search(text):
        return True
    if _AWS_ACCESS_KEY.search(text):
        return True
    if any(text.startswith(prefix) for prefix in _SECRET_LIKE_PREFIXES):
        return True
    if _GITHUB_TOKEN.search(text):
        return True
    if _SLACK_TOKEN.search(text):
        return True
    if _VT_KEY.fullmatch(text):
        return True
    if _STRIPE_KEY.fullmatch(text):
        return True
    if _GENERIC_SK.fullmatch(text):
        return True
    if len(text) >= 40 and _HIGH_ENTROPY_TOKEN.fullmatch(text):
        return True
    if _ASSIGNMENT_PATTERN.search(text) and len(text) < 256:
        return True
    return False


def redact_secrets_from_text(text: str | None) -> str:
    """Redact obvious secret patterns from free-form text."""
    if text is None:
        return ""
    if not text:
        return text

    def _replace_assignment(match: re.Match[str]) -> str:
        key = match.group(1)
        secret = match.group(2)
        if _is_placeholder(secret):
            return match.group(0)
        return f"{key}={REDACTED_SECRET}"

    redacted = _PRIVATE_KEY_BLOCK.sub(REDACTED_SECRET, text)
    redacted = _BEARER_PATTERN.sub(f"Bearer {REDACTED_SECRET}", redacted)
    redacted = _AWS_ACCESS_KEY.sub(REDACTED_SECRET, redacted)
    redacted = _AWS_SECRET_KEY.sub(lambda m: f"aws_secret_access_key={REDACTED_SECRET}", redacted)
    redacted = _GITHUB_TOKEN.sub(REDACTED_SECRET, redacted)
    redacted = _SLACK_TOKEN.sub(REDACTED_SECRET, redacted)
    redacted = _VT_KEY.sub(REDACTED_SECRET, redacted)
    redacted = _STRIPE_KEY.sub(REDACTED_SECRET, redacted)
    redacted = _GENERIC_SK.sub(REDACTED_SECRET, redacted)
    redacted = _ASSIGNMENT_PATTERN.sub(_replace_assignment, redacted)

    def _replace_entropy(match: re.Match[str]) -> str:
        token = match.group(0)
        if _is_placeholder(token):
            return token
        if looks_like_secret(token):
            return REDACTED_SECRET
        return token

    redacted = _HIGH_ENTROPY_TOKEN.sub(_replace_entropy, redacted)
    return redacted


def redact_secrets_from_dict(data: Any) -> Any:
    """Recursively redact string values in mappings and sequences."""
    if isinstance(data, dict):
        return {key: redact_secrets_from_dict(value) for key, value in data.items()}
    if isinstance(data, list):
        return [redact_secrets_from_dict(item) for item in data]
    if isinstance(data, tuple):
        return tuple(redact_secrets_from_dict(item) for item in data)
    if isinstance(data, str):
        return redact_secrets_from_text(data)
    return data


def sanitize_json_for_storage(data_json: str | None) -> str | None:
    """Parse JSON when possible, redact secrets, and return a JSON string."""
    if data_json is None:
        return None
    try:
        payload = json.loads(data_json)
    except json.JSONDecodeError:
        return redact_secrets_from_text(data_json)
    return json.dumps(redact_secrets_from_dict(payload), default=str)


def safe_bool_env(value: str | None, default: bool = False) -> bool:
    """Parse a boolean from an environment string."""
    if value is None or str(value).strip() == "":
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def safe_int_env(value: str | None, default: int) -> int:
    """Parse an integer from an environment string."""
    if value is None or str(value).strip() == "":
        return default
    try:
        return int(str(value).strip())
    except ValueError:
        return default


def is_private_or_local_ip(value: str | None) -> bool:
    """Return True for private, loopback, link-local, or reserved IPv4/IPv6 addresses."""
    if not value:
        return False
    candidate = str(value).strip()
    if candidate.startswith("[") and "]" in candidate:
        candidate = candidate[1 : candidate.index("]")]
    elif candidate.count(":") == 1 and not candidate.startswith("["):
        candidate = candidate.split(":", 1)[0]
    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
    )


def is_safe_target_string(value: str | None, *, max_length: int = 512) -> bool:
    """Return True when a target string is safe for module execution (no shell metacharacters)."""
    if value is None:
        return False
    text = str(value).strip()
    if not text or len(text) > max_length:
        return False
    if _UNSAFE_TARGET_CHARS.search(text):
        return False
    if any(ch in text for ch in ('"', "'", "\n", "\r", "\t")):
        return False
    return True


def elevated_privileges_available() -> bool:
    """Return True when the process appears to run with elevated OS privileges."""
    if os.name == "posix" and hasattr(os, "geteuid"):
        try:
            return os.geteuid() == 0
        except OSError:
            return False
    return False

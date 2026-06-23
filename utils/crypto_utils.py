"""Cryptographic helpers for integrity hashing and optional local encryption scaffolding."""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

# Optional local encryption uses a user-supplied key from environment only.
# Hashing provides integrity, not confidentiality. Full database encryption is future work.
LOCAL_ENCRYPTION_ENV = "PROJECT_OVERWATCH_LOCAL_ENCRYPTION_KEY"


def calculate_sha256(data: bytes | str | None) -> str | None:
    """Return a SHA-256 hex digest for bytes or UTF-8 text, or None when empty."""
    if data is None:
        return None
    if isinstance(data, str):
        payload = data.encode("utf-8")
    else:
        payload = data
    if not payload:
        return None
    return hashlib.sha256(payload).hexdigest()


def generate_file_hash(path: Path | str) -> str | None:
    """Return a SHA-256 hex digest for a file, or None when missing/empty."""
    file_path = Path(path)
    if not file_path.is_file():
        return None
    digest = hashlib.sha256()
    with file_path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def encrypt_text(plaintext: str, key: bytes) -> bytes | None:
    """Optional Fernet encryption when the cryptography package is installed."""
    if not plaintext or not key:
        return None
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None
    try:
        return Fernet(key).encrypt(plaintext.encode("utf-8"))
    except Exception:
        return None


def decrypt_text(token: bytes, key: bytes) -> str | None:
    """Optional Fernet decryption when the cryptography package is installed."""
    if not token or not key:
        return None
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None
    try:
        return Fernet(key).decrypt(token).decode("utf-8")
    except Exception:
        return None


def cryptography_installed() -> bool:
    """Return True when the optional cryptography package is available."""
    try:
        import cryptography  # noqa: F401

        return True
    except ImportError:
        return False


def load_local_encryption_key() -> bytes | None:
    """
    Load a Fernet-compatible key from PROJECT_OVERWATCH_LOCAL_ENCRYPTION_KEY.

    Never log or persist the returned value. Not used for database encryption yet.
    """
    raw = os.environ.get(LOCAL_ENCRYPTION_ENV)
    if not raw or not str(raw).strip():
        try:
            from utils.settings_manager import get_env

            raw = get_env(LOCAL_ENCRYPTION_ENV)
        except Exception:
            raw = None
    if not raw or not str(raw).strip():
        return None
    return str(raw).strip().encode("utf-8")


def local_encryption_configured() -> bool:
    """Return True when a local encryption key is set in the environment."""
    return load_local_encryption_key() is not None


def encryption_available() -> bool:
    """Return True when cryptography is installed and a local encryption key is configured."""
    return cryptography_installed() and local_encryption_configured()

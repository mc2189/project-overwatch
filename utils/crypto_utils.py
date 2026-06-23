"""Cryptographic helpers for integrity hashing and optional local encryption scaffolding."""

from __future__ import annotations

import hashlib
from pathlib import Path

# TODO(v2.2+): optional local evidence/database encryption using a user-supplied key
# from environment — not enabled in v2.1. Hashing provides integrity, not confidentiality.


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

"""Password-protected export encryption for sensitive case reports."""

from __future__ import annotations

import base64
import secrets
from pathlib import Path

ENCRYPTION_MAGIC = b"OWRPT1\x00"


def is_encryption_available() -> bool:
    try:
        import cryptography  # noqa: F401

        return True
    except ImportError:
        return False


def _derive_key(password: str, salt: bytes) -> bytes:
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
        backend=default_backend(),
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode("utf-8")))


def encrypt_bytes(content: bytes, password: str) -> bytes:
    """Encrypt export bytes with a password. Requires the cryptography package."""
    if not password:
        raise ValueError("Password is required for encrypted export.")
    try:
        from cryptography.fernet import Fernet
    except ImportError as exc:
        raise RuntimeError(
            "Encrypted export requires the cryptography package. Install with: pip install cryptography"
        ) from exc

    salt = secrets.token_bytes(16)
    key = _derive_key(password, salt)
    token = Fernet(key).encrypt(content)
    return ENCRYPTION_MAGIC + salt + token


def decrypt_bytes(encrypted: bytes, password: str) -> bytes:
    """Decrypt bytes produced by encrypt_bytes."""
    if not encrypted.startswith(ENCRYPTION_MAGIC):
        raise ValueError("Unrecognised encrypted export format.")
    payload = encrypted[len(ENCRYPTION_MAGIC) :]
    salt, token = payload[:16], payload[16:]
    key = _derive_key(password, salt)
    from cryptography.fernet import Fernet

    return Fernet(key).decrypt(token)


def save_encrypted_export(content: bytes, output_path: Path, password: str) -> Path:
    encrypted = encrypt_bytes(content, password)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(encrypted)
    return output_path

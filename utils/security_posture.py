"""Security posture summary for Settings / Runtime Health."""

from __future__ import annotations

from dataclasses import dataclass

from utils.crypto_utils import cryptography_installed, encryption_available, local_encryption_configured
from utils.security import elevated_privileges_available
from utils.settings_manager import active_modules_enabled, env_example_exists, env_ignored_by_git


@dataclass(frozen=True)
class SecurityPostureItem:
    label: str
    value: str
    ok: bool | None = None
    detail: str = ""


def collect_security_posture() -> list[SecurityPostureItem]:
    """Return non-secret security posture indicators for the UI."""
    return [
        SecurityPostureItem(
            ".env ignored by Git",
            "yes" if env_ignored_by_git() else "no",
            ok=env_ignored_by_git(),
            detail="`.env` should be listed in `.gitignore` and never committed.",
        ),
        SecurityPostureItem(
            ".env.example present",
            "yes" if env_example_exists() else "no",
            ok=env_example_exists(),
            detail="Placeholder template for local secret configuration.",
        ),
        SecurityPostureItem(
            "Active modules globally enabled",
            "yes" if active_modules_enabled() else "no",
            ok=None,
            detail="Controlled by PROJECT_OVERWATCH_ENABLE_ACTIVE_MODULES.",
        ),
        SecurityPostureItem(
            "Elevated privileges available",
            "yes" if elevated_privileges_available() else "no",
            ok=not elevated_privileges_available(),
            detail="Project Overwatch does not request sudo or store OS credentials.",
        ),
        SecurityPostureItem(
            "Nmap command safety",
            "allowlisted",
            ok=True,
            detail="Nmap uses list-based subprocess arguments and profile allowlists only.",
        ),
        SecurityPostureItem(
            "Secrets redaction enabled",
            "yes",
            ok=True,
            detail="Masking in Settings; redaction before persistence and in reports.",
        ),
        SecurityPostureItem(
            "Evidence hashing enabled",
            "yes",
            ok=True,
            detail="SHA-256 hashes support integrity checks — not confidentiality.",
        ),
        SecurityPostureItem(
            "Database encryption",
            "scaffold only" if not encryption_available() else "key configured (not applied to DB yet)",
            ok=None,
            detail=(
                "Optional PROJECT_OVERWATCH_LOCAL_ENCRYPTION_KEY + cryptography package. "
                "Full database encryption is not enabled yet."
                if not encryption_available()
                else "Local encryption key is set; evidence/database encryption not applied yet."
            ),
        ),
        SecurityPostureItem(
            "Local encryption library",
            "available" if cryptography_installed() else "not installed",
            ok=cryptography_installed(),
            detail="pip install cryptography for optional Fernet helpers in utils/crypto_utils.py.",
        ),
        SecurityPostureItem(
            "Security audit",
            "run manually",
            ok=None,
            detail="python scripts/security_audit.py",
        ),
    ]

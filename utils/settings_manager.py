"""Settings and API key management for Project Overwatch."""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from typing import Any

from database.db_setup import PROJECT_ROOT
from utils.security import mask_secret, safe_bool_env, safe_int_env

DEFAULTS_PATH = PROJECT_ROOT / "config" / "overwatch.defaults.json"
ENV_EXAMPLE_PATH = PROJECT_ROOT / ".env.example"

_DOTENV_LOADED = False


@dataclass(frozen=True)
class ApiProviderSpec:
    provider_id: str
    display_name: str
    env_keys: tuple[str, ...]
    future_module_ids: tuple[str, ...]
    notes: str = "Future-ready — no implemented module uses this key yet."


API_PROVIDERS: tuple[ApiProviderSpec, ...] = (
    ApiProviderSpec(
        "virustotal",
        "VirusTotal",
        ("VIRUSTOTAL_API_KEY",),
        ("intel_virustotal",),
        notes="Used by VirusTotal Reputation Intelligence — key is masked here and never stored in the database.",
    ),
    ApiProviderSpec(
        "abuseipdb",
        "AbuseIPDB",
        ("ABUSEIPDB_API_KEY",),
        ("intel_abuseipdb",),
    ),
    ApiProviderSpec(
        "greynoise",
        "GreyNoise",
        ("GREYNOISE_API_KEY",),
        ("intel_greynoise",),
    ),
    ApiProviderSpec(
        "shodan",
        "Shodan",
        ("SHODAN_API_KEY",),
        ("intel_shodan",),
    ),
    ApiProviderSpec(
        "censys",
        "Censys",
        ("CENSYS_API_ID", "CENSYS_API_SECRET"),
        ("intel_censys",),
        notes="Requires both API ID and secret. Future-ready — no implemented module uses these yet.",
    ),
    ApiProviderSpec(
        "securitytrails",
        "SecurityTrails",
        ("SECURITYTRAILS_API_KEY",),
        ("intel_securitytrails",),
    ),
    ApiProviderSpec(
        "hunter",
        "Hunter.io",
        ("HUNTER_API_KEY",),
        ("ident_hunter",),
    ),
    ApiProviderSpec(
        "hibp",
        "Have I Been Pwned",
        ("HAVEIBEENPWNED_API_KEY",),
        ("intel_hibp",),
    ),
)

GENERAL_SETTING_DEFAULTS: dict[str, Any] = {
    "PROJECT_OVERWATCH_RATE_LIMIT_SECONDS": 1.5,
    "PROJECT_OVERWATCH_DEFAULT_TIMEOUT": 30,
    "PROJECT_OVERWATCH_MAX_BATCH_ITEMS": 50,
    "PROJECT_OVERWATCH_ENABLE_ACTIVE_MODULES": True,
}


def load_dotenv_if_available() -> None:
    """Load .env from the project root once per process (never logs values)."""
    global _DOTENV_LOADED
    if _DOTENV_LOADED:
        return
    env_path = PROJECT_ROOT / ".env"
    if env_path.exists():
        try:
            from dotenv import load_dotenv

            load_dotenv(env_path, override=False)
        except ImportError:
            pass
    _DOTENV_LOADED = True


def _load_defaults_file() -> dict[str, Any]:
    if not DEFAULTS_PATH.exists():
        return {}
    try:
        data = json.loads(DEFAULTS_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError):
        return {}


def get_env(name: str, default: str | None = None) -> str | None:
    """Return an environment variable after optional .env load."""
    load_dotenv_if_available()
    value = os.environ.get(name)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def get_bool_env(name: str, default: bool = True) -> bool:
    raw = get_env(name)
    if raw is None:
        file_defaults = _load_defaults_file()
        if name in file_defaults:
            return bool(file_defaults[name])
        return safe_bool_env(None, GENERAL_SETTING_DEFAULTS.get(name, default))
    return safe_bool_env(raw, default)


def get_float_env(name: str, default: float) -> float:
    raw = get_env(name)
    if raw is None:
        file_defaults = _load_defaults_file()
        if name in file_defaults:
            try:
                return float(file_defaults[name])
            except (TypeError, ValueError):
                pass
        return float(GENERAL_SETTING_DEFAULTS.get(name, default))
    try:
        return float(raw)
    except ValueError:
        return default


def get_int_env(name: str, default: int) -> int:
    raw = get_env(name)
    if raw is None:
        file_defaults = _load_defaults_file()
        if name in file_defaults:
            try:
                return int(file_defaults[name])
            except (TypeError, ValueError):
                pass
        return safe_int_env(None, int(GENERAL_SETTING_DEFAULTS.get(name, default)))
    return safe_int_env(raw, default)


def rate_limit_seconds() -> float:
    return get_float_env("PROJECT_OVERWATCH_RATE_LIMIT_SECONDS", 1.5)


def default_timeout_seconds() -> int:
    return get_int_env("PROJECT_OVERWATCH_DEFAULT_TIMEOUT", 30)


def max_batch_items() -> int:
    return get_int_env("PROJECT_OVERWATCH_MAX_BATCH_ITEMS", 50)


def active_modules_enabled() -> bool:
    return get_bool_env("PROJECT_OVERWATCH_ENABLE_ACTIVE_MODULES", True)


def has_api_key(env_key: str) -> bool:
    """Return True when an environment key is set to a non-empty value."""
    return bool(get_env(env_key))


def mask_api_key(value: str | None, *, visible_prefix: int = 3, visible_suffix: int = 4) -> str:
    """Return a masked display value such as vt_****abcd. Never use for logging secrets."""
    return mask_secret(value, visible_prefix=visible_prefix, visible_suffix=visible_suffix)


def provider_configured(provider: ApiProviderSpec) -> bool:
    return all(has_api_key(key) for key in provider.env_keys)


def list_api_provider_status() -> list[dict[str, Any]]:
    """Return API provider configuration status for the Settings page."""
    from modules.module_registry import get_module

    rows: list[dict[str, Any]] = []
    for provider in API_PROVIDERS:
        module_labels: list[str] = []
        any_implemented = False
        for module_id in provider.future_module_ids:
            module = get_module(module_id)
            if module is None:
                module_labels.append(module_id)
                continue
            label = module.display_name
            if module.implemented:
                any_implemented = True
                label += " (implemented)"
            else:
                label += " (planned)"
            module_labels.append(label)

        key_status = []
        for env_key in provider.env_keys:
            raw = get_env(env_key)
            key_status.append(
                {
                    "env_key": env_key,
                    "configured": bool(raw),
                    "masked": mask_api_key(raw) if raw else "not configured",
                }
            )

        rows.append(
            {
                "provider_id": provider.provider_id,
                "display_name": provider.display_name,
                "configured": provider_configured(provider),
                "env_keys": list(provider.env_keys),
                "key_status": key_status,
                "future_modules": module_labels,
                "notes": provider.notes,
                "in_use": any_implemented,
            }
        )
    return rows


def module_api_key_status(module) -> dict[str, Any]:
    """Return API key configuration status for a module registry entry."""
    required_keys = tuple(module.api_key_names or ())
    if not module.requires_api_key or not required_keys:
        return {
            "required": False,
            "configured": True,
            "missing_keys": [],
            "masked_keys": {},
        }

    missing = [key for key in required_keys if not has_api_key(key)]
    masked = {key: mask_api_key(get_env(key)) for key in required_keys if has_api_key(key)}
    return {
        "required": True,
        "configured": not missing,
        "missing_keys": missing,
        "masked_keys": masked,
    }


def validate_module_settings(module_id: str) -> dict[str, Any]:
    """Validate settings required for a module."""
    from modules.module_registry import get_module

    module = get_module(module_id)
    if module is None:
        return {"ok": False, "reason": "Module is not registered.", "missing_keys": []}

    if module.mode == "active" and not active_modules_enabled():
        return {
            "ok": False,
            "reason": "Active modules are disabled in settings (PROJECT_OVERWATCH_ENABLE_ACTIVE_MODULES=false).",
            "missing_keys": [],
        }

    key_status = module_api_key_status(module)
    if key_status["required"] and not key_status["configured"]:
        missing = ", ".join(key_status["missing_keys"])
        if module.module_id == "intel_virustotal":
            return {
                "ok": False,
                "reason": (
                    "VirusTotal API key is not configured. "
                    "Add VIRUSTOTAL_API_KEY to your local .env file."
                ),
                "missing_keys": key_status["missing_keys"],
            }
        return {
            "ok": False,
            "reason": f"Missing required API key(s): {missing}. Add them to your local .env file.",
            "missing_keys": key_status["missing_keys"],
        }

    return {"ok": True, "reason": "", "missing_keys": []}


def check_module_preflight(module) -> dict[str, Any]:
    """Preflight check used by the executor before running a module."""
    validation = validate_module_settings(module.module_id)
    if validation["ok"]:
        return {"ok": True, "summary": "", "errors": []}
    return {
        "ok": False,
        "summary": validation["reason"],
        "errors": ["settings_preflight_failed", *validation.get("missing_keys", [])],
    }


def list_module_config_status() -> list[dict[str, Any]]:
    """Return configuration status for all registered modules."""
    from modules.module_registry import MODULES, is_executable

    rows: list[dict[str, Any]] = []
    for module in MODULES:
        key_status = module_api_key_status(module)
        validation = validate_module_settings(module.module_id)
        rows.append(
            {
                "module_id": module.module_id,
                "display_name": module.display_name,
                "status": module.status,
                "implemented": module.implemented,
                "executable": is_executable(module),
                "requires_api_key": module.requires_api_key,
                "api_key_names": list(module.api_key_names or ()),
                "api_keys_configured": key_status["configured"],
                "missing_keys": key_status["missing_keys"],
                "ready": validation["ok"] or not module.implemented,
                "config_notes": module.config_notes,
                "rate_limit_notes": module.rate_limit_notes,
            }
        )
    return rows


def configured_api_providers_count() -> int:
    return sum(1 for provider in API_PROVIDERS if provider_configured(provider))


def missing_optional_api_providers_count() -> int:
    return sum(1 for provider in API_PROVIDERS if not provider_configured(provider))


def general_settings_summary() -> dict[str, Any]:
    return {
        "rate_limit_seconds": rate_limit_seconds(),
        "default_timeout_seconds": default_timeout_seconds(),
        "max_batch_items": max_batch_items(),
        "active_modules_enabled": active_modules_enabled(),
        "python_version": sys.version.split()[0],
    }


def env_example_exists() -> bool:
    return ENV_EXAMPLE_PATH.exists()


def env_ignored_by_git() -> bool:
    gitignore = PROJECT_ROOT / ".gitignore"
    if not gitignore.exists():
        return False
    content = gitignore.read_text(encoding="utf-8")
    return ".env" in content

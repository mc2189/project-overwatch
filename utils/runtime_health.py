"""Runtime health checks for modules and optional export dependencies."""

from __future__ import annotations

import shutil
from dataclasses import dataclass

import streamlit as st

from modules.executor import get_runtime_error, is_runtime_ready
from utils.settings_manager import (
    active_modules_enabled,
    configured_api_providers_count,
    general_settings_summary,
    missing_optional_api_providers_count,
)
from version import PROJECT_VERSION


@dataclass
class HealthCheck:
    name: str
    ok: bool
    detail: str
    required: bool = True


def _optional_import(module_name: str) -> bool:
    try:
        __import__(module_name)
        return True
    except (ImportError, OSError):
        return False


def collect_health_checks() -> list[HealthCheck]:
    """Return health status for core and optional runtime dependencies."""
    checks: list[HealthCheck] = []
    settings = general_settings_summary()

    checks.append(
        HealthCheck(
            "Python",
            True,
            settings["python_version"],
            required=False,
        )
    )
    checks.append(
        HealthCheck(
            "Project Overwatch",
            True,
            f"v{PROJECT_VERSION}",
            required=False,
        )
    )
    checks.append(
        HealthCheck(
            "Active modules globally",
            active_modules_enabled(),
            "Enabled" if active_modules_enabled() else "Disabled via PROJECT_OVERWATCH_ENABLE_ACTIVE_MODULES",
            required=False,
        )
    )
    checks.append(
        HealthCheck(
            "API providers configured",
            configured_api_providers_count() > 0,
            f"{configured_api_providers_count()} configured · "
            f"{missing_optional_api_providers_count()} optional missing",
            required=False,
        )
    )

    nmap_on_path = shutil.which("nmap") is not None
    nmap_module_loaded = is_runtime_ready("infra_nmap")
    nmap_error = get_runtime_error("infra_nmap")
    if nmap_on_path and nmap_module_loaded:
        checks.append(HealthCheck("Nmap binary", True, "Found on PATH"))
    elif not nmap_on_path:
        checks.append(
            HealthCheck(
                "Nmap binary",
                False,
                "Not found on PATH — install from https://nmap.org/download.html",
                required=False,
            )
        )
    else:
        checks.append(
            HealthCheck(
                "Nmap module",
                False,
                nmap_error or "Nmap backend failed to load",
                required=False,
            )
        )

    domain_ready = is_runtime_ready("infra_domain_intel")
    domain_error = get_runtime_error("infra_domain_intel")
    if domain_ready:
        checks.append(HealthCheck("Domain Intelligence", True, "Backend loaded"))
    else:
        checks.append(
            HealthCheck(
                "Domain Intelligence",
                False,
                domain_error or "Backend failed to load — run pip install -r requirements.txt",
            )
        )

    cert_ready = is_runtime_ready("infra_cert_subdomain")
    cert_error = get_runtime_error("infra_cert_subdomain")
    if cert_ready:
        checks.append(HealthCheck("Certificate & Subdomain Intelligence", True, "Backend loaded"))
    else:
        checks.append(
            HealthCheck(
                "Certificate & Subdomain Intelligence",
                False,
                cert_error or "Backend failed to load — run pip install -r requirements.txt",
            )
        )

    website_ready = is_runtime_ready("infra_website_metadata")
    website_error = get_runtime_error("infra_website_metadata")
    if website_ready:
        checks.append(HealthCheck("Website Metadata Review", True, "Backend loaded"))
    else:
        checks.append(
            HealthCheck(
                "Website Metadata Review",
                False,
                website_error or "Backend failed to load — run pip install -r requirements.txt",
            )
        )

    checks.append(
        HealthCheck(
            "Graph PNG (kaleido)",
            (kaleido_ok := _optional_import("kaleido")),
            "Available" if kaleido_ok else "Optional — pip install -r requirements-optional.txt",
            required=False,
        )
    )
    weasyprint_ok = _optional_import("weasyprint")
    checks.append(
        HealthCheck(
            "PDF export (weasyprint)",
            weasyprint_ok,
            "Available" if weasyprint_ok else "Optional — pip install -r requirements-optional.txt",
            required=False,
        )
    )
    checks.append(
        HealthCheck(
            "Encrypted export (cryptography)",
            _optional_import("cryptography"),
            "Available" if _optional_import("cryptography") else "Install cryptography",
        )
    )

    return checks


def required_checks_passed(checks: list[HealthCheck] | None = None) -> bool:
    checks = checks or collect_health_checks()
    return all(check.ok for check in checks if check.required)


def render_runtime_health_panel(checks: list[HealthCheck] | None = None) -> None:
    """Render runtime health checks in Streamlit."""
    checks = checks or collect_health_checks()
    for check in checks:
        icon = "✅" if check.ok else ("⚠️" if not check.required else "❌")
        st.write(f"{icon} **{check.name}** — {check.detail}")

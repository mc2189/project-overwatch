"""Runtime health checks for modules and optional export dependencies."""

from __future__ import annotations

import shutil
from dataclasses import dataclass

from modules.executor import get_runtime_error, is_runtime_ready


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

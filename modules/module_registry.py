"""Central registry of Project Overwatch module metadata."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ModuleStatus = Literal["active", "planned", "disabled"]
ModuleMode = Literal["passive", "active", "analysis"]
RiskLevel = Literal["low", "medium", "high"]


@dataclass(frozen=True)
class ModuleEntry:
    module_id: str
    display_name: str
    category: str
    description: str
    status: ModuleStatus
    mode: ModuleMode
    risk_level: RiskLevel
    requires_authorisation: bool
    requires_api_key: bool
    implemented: bool
    accepted_target_types: tuple[str, ...] = ()
    short_help: str = ""
    detailed_help: str = ""
    example_inputs: tuple[str, ...] = ()
    output_summary: str = ""
    caution_notes: tuple[str, ...] = ()


CATEGORIES: list[dict[str, str | bool]] = [
    {"key": "Identity", "label": "1. Identity", "default_expanded": False},
    {"key": "Infrastructure", "label": "2. Infrastructure", "default_expanded": True},
    {"key": "Vulnerability", "label": "3. Vulnerability", "default_expanded": False},
    {"key": "Threat Intel", "label": "4. Threat Intel", "default_expanded": False},
    {"key": "Dark Web", "label": "5. Dark Web", "default_expanded": False},
    {"key": "Financial", "label": "6. Financial", "default_expanded": False},
    {"key": "GEOINT and Media", "label": "7. GEOINT and Media", "default_expanded": False},
    {"key": "Corporate Networks", "label": "8. Corporate Networks", "default_expanded": False},
    {"key": "Cloud Recon", "label": "9. Cloud Recon", "default_expanded": False},
    {"key": "Document Forensics", "label": "10. Document Forensics", "default_expanded": False},
    {"key": "Historical Web", "label": "11. Historical Web", "default_expanded": False},
    {"key": "Data Brokers", "label": "12. Data Brokers", "default_expanded": False},
]

MODULES: list[ModuleEntry] = [
    # Identity
    ModuleEntry(
        module_id="ident_sherlock",
        display_name="Sherlock",
        category="Identity",
        description="Username search across public platforms.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=False,
        accepted_target_types=("username",),
        short_help="Search public platforms for a username (planned).",
        detailed_help="Planned passive username enumeration across public sites.",
        example_inputs=("johndoe", "acme_admin"),
        output_summary="Platform matches and profile links.",
    ),
    ModuleEntry(
        module_id="ident_holehe",
        display_name="Holehe",
        category="Identity",
        description="Check whether an email is registered on public services.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=False,
        accepted_target_types=("email",),
        short_help="Check email registration on public services (planned).",
        detailed_help="Planned passive email registration checks using public APIs.",
        example_inputs=("analyst@example.com",),
        output_summary="Registered-service hints for an email address.",
    ),
    # Infrastructure
    ModuleEntry(
        module_id="infra_nmap",
        display_name="Nmap (Port Scan)",
        category="Infrastructure",
        description="Manual port and service discovery via Nmap.",
        status="active",
        mode="active",
        risk_level="medium",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=True,
        accepted_target_types=("ipv4", "domain"),
        short_help="Active scan of reachable network services on an IPv4 address or domain.",
        detailed_help=(
            "Runs Nmap against an IPv4 address or domain to discover open ports, services, and optional "
            "script output. Results are stored as observations and advisory findings — they indicate what "
            "was reachable at scan time, not proof of exploitability or business risk."
        ),
        example_inputs=("192.168.1.10", "example.com"),
        output_summary="Open ports, service banners, optional OS/script notes, entities and relationships.",
        caution_notes=(
            "Authorisation is required before running this active module.",
            "Use only on systems you own, lab environments, or targets with written permission.",
            "Findings are analyst aids based on scan output, not confirmed vulnerabilities.",
        ),
    ),
    ModuleEntry(
        module_id="infra_domain_intel",
        display_name="Domain Intelligence",
        category="Infrastructure",
        description="Passive DNS, HTTP/TLS, security header, and Wayback lookups for a domain.",
        status="active",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=True,
        accepted_target_types=("domain", "url"),
        short_help="Passive DNS, HTTP/TLS, security headers, and Wayback checks for a domain or URL.",
        detailed_help=(
            "Collects public DNS records, HTTP/HTTPS responses, TLS certificate details, security headers, "
            "and Wayback availability for a domain or URL. This module does not run port scans or send "
            "intrusive probes. Missing headers or TLS notes are review points for analysts, not confirmed issues."
        ),
        example_inputs=("example.com", "https://example.com/path"),
        output_summary="DNS records, HTTP/TLS metadata, header review points, Wayback snapshot hints.",
        caution_notes=(
            "Does not perform port scanning or active exploitation checks.",
            "Missing security headers are observations for review, not confirmed misconfigurations.",
            "Results depend on public DNS/HTTP responses at lookup time.",
        ),
    ),
    ModuleEntry(
        module_id="infra_amass",
        display_name="Amass",
        category="Infrastructure",
        description="Subdomain enumeration and attack surface mapping.",
        status="planned",
        mode="active",
        risk_level="medium",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=False,
    ),
    ModuleEntry(
        module_id="infra_dnsdumpster",
        display_name="DNSDumpster",
        category="Infrastructure",
        description="Passive DNS and host discovery from public records.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=False,
    ),
    ModuleEntry(
        module_id="infra_theharvester",
        display_name="TheHarvester",
        category="Infrastructure",
        description="Collect emails, hosts, and subdomains from public sources.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=False,
    ),
    # Vulnerability
    ModuleEntry(
        module_id="vuln_nuclei",
        display_name="Nuclei",
        category="Vulnerability",
        description="Template-based vulnerability scanning.",
        status="planned",
        mode="active",
        risk_level="high",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=False,
    ),
    ModuleEntry(
        module_id="vuln_ffuf",
        display_name="FFUF",
        category="Vulnerability",
        description="Web fuzzing for hidden paths and parameters.",
        status="planned",
        mode="active",
        risk_level="high",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=False,
    ),
    ModuleEntry(
        module_id="vuln_sqlmap",
        display_name="SQLMap",
        category="Vulnerability",
        description="SQL injection testing (planned; not enabled).",
        status="planned",
        mode="active",
        risk_level="high",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=False,
    ),
    ModuleEntry(
        module_id="vuln_pyshark",
        display_name="PyShark",
        category="Vulnerability",
        description="Packet capture analysis for network troubleshooting.",
        status="planned",
        mode="analysis",
        risk_level="low",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=False,
    ),
    # Threat Intel
    ModuleEntry(
        module_id="intel_virustotal",
        display_name="VirusTotal",
        category="Threat Intel",
        description="Lookup files, URLs, and IPs against threat intelligence feeds.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=False,
    ),
    ModuleEntry(
        module_id="intel_abuseipdb",
        display_name="AbuseIPDB",
        category="Threat Intel",
        description="Check IP reputation and abuse reports.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=False,
    ),
    ModuleEntry(
        module_id="intel_greynoise",
        display_name="GreyNoise",
        category="Threat Intel",
        description="Classify internet background noise and scanner activity.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=False,
    ),
    # Dark Web
    ModuleEntry(
        module_id="dark_ahmia",
        display_name="Ahmia",
        category="Dark Web",
        description="Search public Tor hidden-service indexes.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=False,
    ),
    ModuleEntry(
        module_id="dark_dehashed",
        display_name="Dehashed",
        category="Dark Web",
        description="Breach data lookup for compromised credentials.",
        status="planned",
        mode="passive",
        risk_level="medium",
        requires_authorisation=True,
        requires_api_key=True,
        implemented=False,
    ),
    # Financial
    ModuleEntry(
        module_id="fin_crypto_tracer",
        display_name="Crypto Tracer",
        category="Financial",
        description="Trace public blockchain transactions and wallet links.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=False,
    ),
    # GEOINT and Media
    ModuleEntry(
        module_id="geo_exiftool",
        display_name="EXIFTool",
        category="GEOINT and Media",
        description="Extract metadata from images and media files.",
        status="planned",
        mode="analysis",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=False,
    ),
    ModuleEntry(
        module_id="geo_vision_api",
        display_name="Vision API",
        category="GEOINT and Media",
        description="Image analysis and object detection via cloud vision APIs.",
        status="planned",
        mode="analysis",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=False,
    ),
    # Corporate Networks
    ModuleEntry(
        module_id="corp_companies_house",
        display_name="Companies House",
        category="Corporate Networks",
        description="UK company registry lookups and officer data.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=False,
    ),
    ModuleEntry(
        module_id="corp_orbis",
        display_name="Orbis",
        category="Corporate Networks",
        description="Corporate ownership and subsidiary research.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=False,
    ),
    # Cloud Recon
    ModuleEntry(
        module_id="cloud_enum",
        display_name="Cloud Enum",
        category="Cloud Recon",
        description="Enumerate public cloud storage and service exposure.",
        status="planned",
        mode="passive",
        risk_level="medium",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=False,
    ),
    # Document Forensics
    ModuleEntry(
        module_id="doc_peepdf",
        display_name="peepdf",
        category="Document Forensics",
        description="Analyse PDF structure and embedded objects.",
        status="planned",
        mode="analysis",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=False,
    ),
    # Historical Web
    ModuleEntry(
        module_id="hist_wayback",
        display_name="Wayback",
        category="Historical Web",
        description="Retrieve archived snapshots from the Wayback Machine.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=False,
    ),
    # Data Brokers
    ModuleEntry(
        module_id="broker_numverify",
        display_name="Numverify",
        category="Data Brokers",
        description="Phone number validation and carrier lookup.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=False,
    ),
    ModuleEntry(
        module_id="broker_truecaller",
        display_name="Truecaller",
        category="Data Brokers",
        description="Caller ID and phone reputation lookup.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=False,
    ),
    ModuleEntry(
        module_id="broker_pipl",
        display_name="Pipl",
        category="Data Brokers",
        description="People search and identity enrichment.",
        status="planned",
        mode="passive",
        risk_level="medium",
        requires_authorisation=True,
        requires_api_key=True,
        implemented=False,
    ),
]

_MODULE_INDEX = {module.module_id: module for module in MODULES}


def get_module(module_id: str) -> ModuleEntry | None:
    """Return a module entry by ID, or None if not registered."""
    return _MODULE_INDEX.get(module_id)


def get_modules_by_category() -> dict[str, list[ModuleEntry]]:
    """Return registered modules grouped by category, preserving category order."""
    grouped: dict[str, list[ModuleEntry]] = {str(cat["key"]): [] for cat in CATEGORIES}
    for module in MODULES:
        grouped[module.category].append(module)
    return grouped


def is_executable(module: ModuleEntry) -> bool:
    """Return True only for modules that are implemented and marked active."""
    return module.implemented and module.status == "active"


def module_ui_label(module: ModuleEntry) -> str:
    """Build a sidebar label with mode and status for clarity."""
    if is_executable(module):
        mode_label = {"active": "Active", "passive": "Passive", "analysis": "Analysis"}.get(
            module.mode, module.mode.title()
        )
        return f"{module.display_name} [{mode_label}]"
    return f"{module.display_name} (planned)"


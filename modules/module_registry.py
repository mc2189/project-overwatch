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
    api_key_names: tuple[str, ...] = ()
    config_notes: str = ""
    rate_limit_notes: str = ""
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
        config_notes="No API key required. Requires Nmap on PATH and authorisation before running.",
        rate_limit_notes="Active scan — use sparingly; not subject to passive lookup rate limits.",
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
        config_notes="No API key required. Uses public DNS/HTTP/TLS/Wayback lookups only.",
        rate_limit_notes="Respect public source rate limits; batch queue courtesy delay applies.",
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
        module_id="infra_cert_subdomain",
        display_name="Certificate & Subdomain Intelligence",
        category="Infrastructure",
        description="Passive discovery of public certificate names and related subdomains.",
        status="active",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=True,
        accepted_target_types=("domain", "url"),
        config_notes="No API key required. Queries public certificate transparency data (crt.sh).",
        rate_limit_notes="crt.sh may rate limit or timeout — handled as source notices, not hard failures.",
        short_help="Passive certificate transparency lookup for related public subdomain names.",
        detailed_help=(
            "Queries public certificate transparency data (crt.sh) to discover hostnames that have appeared "
            "in certificates related to the target domain or URL. This module does not run port scans, "
            "service checks, or intrusive probes. Certificate-derived names are leads for review — they "
            "do not confirm that a host is live, reachable, or in scope."
        ),
        example_inputs=("example.com", "https://www.example.com/path"),
        output_summary="Discovered subdomain names, certificate references, and cautious advisory findings.",
        caution_notes=(
            "Passive public lookup only — no active scanning.",
            "Certificate-derived names are leads, not proof of live systems.",
            "Results depend on public transparency logs and may be incomplete or rate limited.",
        ),
    ),
    ModuleEntry(
        module_id="infra_website_metadata",
        display_name="Website Metadata Review",
        category="Infrastructure",
        description="Passive homepage metadata, robots.txt, and sitemap review for a domain or URL.",
        status="active",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=True,
        accepted_target_types=("domain", "url"),
        config_notes="No API key required. Performs passive HTTP GET requests only.",
        rate_limit_notes="Uses PROJECT_OVERWATCH_RATE_LIMIT_SECONDS between batch queue passive runs.",
        short_help="Passive homepage title, meta tags, headers, link/form counts, robots.txt, and sitemap hints.",
        detailed_help=(
            "Fetches the public homepage for a domain or URL and extracts page title, meta description, "
            "canonical URL, selected response headers, link and form counts, robots.txt summary, and sitemap hints. "
            "This module performs a single passive HTTP GET (plus robots.txt and lightweight sitemap probes). "
            "It does not submit forms, brute-force paths, or run port scans."
        ),
        example_inputs=("example.com", "https://www.example.com/"),
        output_summary="Homepage metadata, basic headers, robots.txt summary, sitemap hints, advisory findings.",
        caution_notes=(
            "Passive HTTP lookups only — no form submission or intrusive crawling.",
            "Link/form counts depend on the fetched HTML at review time.",
            "robots.txt and sitemap hints are public signals, not proof of hidden or live content.",
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
        status="active",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=True,
        accepted_target_types=("ipv4", "domain", "url"),
        api_key_names=("VIRUSTOTAL_API_KEY",),
        config_notes="Requires VIRUSTOTAL_API_KEY in local .env.",
        rate_limit_notes="Public API rate limits apply — batch queue courtesy delay applies.",
        short_help="Passive VirusTotal lookup for an IPv4 address, domain, or URL.",
        detailed_help=(
            "Queries the VirusTotal API v3 for third-party engine detections and community metadata. "
            "Detection counts are leads for analyst review — they do not confirm compromise or benign status."
        ),
        example_inputs=("203.0.113.10", "example.com", "https://example.com/path"),
        output_summary="Engine detection counts, reputation hints, and advisory findings.",
        caution_notes=(
            "Third-party engine labels require manual verification.",
            "Clean VirusTotal results do not prove a target is safe or in scope.",
            "Respect VirusTotal API rate limits and terms of use.",
        ),
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
        api_key_names=("ABUSEIPDB_API_KEY",),
        config_notes="Requires ABUSEIPDB_API_KEY in local .env. Planned — not available in this release.",
        rate_limit_notes="Daily query limits depend on your AbuseIPDB plan.",
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
        api_key_names=("GREYNOISE_API_KEY",),
        config_notes="Requires GREYNOISE_API_KEY in local .env. Planned — not available in this release.",
        rate_limit_notes="Community/enterprise tiers have different rate limits.",
    ),
    ModuleEntry(
        module_id="intel_shodan",
        display_name="Shodan",
        category="Threat Intel",
        description="Internet-wide device and service exposure search.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=False,
        api_key_names=("SHODAN_API_KEY",),
        config_notes="Requires SHODAN_API_KEY in local .env. Planned — not available in this release.",
        rate_limit_notes="Query credits depend on your Shodan membership.",
    ),
    ModuleEntry(
        module_id="intel_censys",
        display_name="Censys",
        category="Threat Intel",
        description="Internet asset and certificate search via Censys API.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=False,
        api_key_names=("CENSYS_API_ID", "CENSYS_API_SECRET"),
        config_notes="Requires CENSYS_API_ID and CENSYS_API_SECRET in local .env. Planned — not available yet.",
        rate_limit_notes="API quota depends on your Censys account.",
    ),
    ModuleEntry(
        module_id="intel_securitytrails",
        display_name="SecurityTrails",
        category="Threat Intel",
        description="DNS and domain history intelligence.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=False,
        api_key_names=("SECURITYTRAILS_API_KEY",),
        config_notes="Requires SECURITYTRAILS_API_KEY in local .env. Planned — not available in this release.",
        rate_limit_notes="Monthly API allowance depends on your plan.",
    ),
    ModuleEntry(
        module_id="ident_hunter",
        display_name="Hunter.io",
        category="Identity",
        description="Email discovery and verification for a domain.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=False,
        accepted_target_types=("domain", "email"),
        api_key_names=("HUNTER_API_KEY",),
        config_notes="Requires HUNTER_API_KEY in local .env. Planned — not available in this release.",
        rate_limit_notes="Search credits depend on your Hunter.io plan.",
    ),
    ModuleEntry(
        module_id="intel_hibp",
        display_name="Have I Been Pwned",
        category="Threat Intel",
        description="Check emails and domains against known breach data.",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=False,
        accepted_target_types=("email", "domain"),
        api_key_names=("HAVEIBEENPWNED_API_KEY",),
        config_notes="Requires HAVEIBEENPWNED_API_KEY in local .env. Planned — not available in this release.",
        rate_limit_notes="HIBP API rate limits apply per key tier.",
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


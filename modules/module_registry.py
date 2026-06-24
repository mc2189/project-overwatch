"""Central registry of Project Overwatch module metadata."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

ModuleStatus = Literal["active", "planned", "disabled"]
ModuleMode = Literal["passive", "active", "analysis", "local-capture"]
RiskLevel = Literal["low", "medium", "high"]

# High-risk placeholders quarantined from execution even if accidentally marked implemented.
QUARANTINED_MODULE_IDS: frozenset[str] = frozenset(
    {
        "vuln_nuclei",
        "vuln_ffuf",
        "vuln_sqlmap",
        "intel_hibp",
        "dark_ahmia",
        "dark_dehashed",
        "cloud_enum",
    }
)


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
    {"key": "Network Analysis", "label": "5. Network Analysis", "default_expanded": False},
    {"key": "Dark Web", "label": "6. Dark Web", "default_expanded": False},
    {"key": "Financial", "label": "7. Financial", "default_expanded": False},
    {"key": "GEOINT and Media", "label": "8. GEOINT and Media", "default_expanded": False},
    {"key": "Corporate Networks", "label": "9. Corporate Networks", "default_expanded": False},
    {"key": "Cloud Recon", "label": "10. Cloud Recon", "default_expanded": False},
    {"key": "Document Forensics", "label": "11. Document Forensics", "default_expanded": False},
    {"key": "Historical Web", "label": "12. Historical Web", "default_expanded": False},
    {"key": "Data Brokers", "label": "13. Data Brokers", "default_expanded": False},
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
        display_name="Network Service Check (Nmap Profile Runner)",
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
        short_help="Active Nmap profile runner for controlled port and service discovery on an IPv4 address or domain.",
        detailed_help=(
            "Runs guided Nmap profiles against an IPv4 address or domain to discover open ports, services, "
            "and optional script output. Choose Quick Service Check, Standard Service Detection, Web Surface "
            "Discovery, or other bounded profiles. Results are stored as observations and advisory findings — "
            "they indicate what was reachable at scan time, not proof of exploitability or business risk."
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
        module_id="infra_tls_review",
        display_name="SSL / TLS Configuration Review",
        category="Infrastructure",
        description="Controlled active TLS certificate and configuration review for a single authorised host.",
        status="active",
        mode="active",
        risk_level="medium",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=True,
        accepted_target_types=("domain", "url", "ipv4"),
        config_notes=(
            "No API key required. Opens a single TLS connection to the target host:port (default 443). "
            "Requires authorisation and engagement/scope alignment for active testing."
        ),
        rate_limit_notes=(
            "Active TLS handshake — single host/port per run; not subject to passive lookup rate limits."
        ),
        short_help="Controlled TLS certificate and protocol review for a domain, URL, or public IPv4 target.",
        detailed_help=(
            "Performs a normal TLS handshake to a single authorised host and port (default 443), inspects "
            "certificate metadata, negotiated protocol/cipher, and optional safe per-version protocol probes. "
            "Does not exploit vulnerabilities, fuzz endpoints, perform denial-of-service testing, or scan port ranges."
        ),
        example_inputs=("example.com", "https://example.com:8443/path", "8.8.8.8"),
        output_summary=(
            "TLS handshake summary, certificate metadata, protocol probe notes, entities, and cautious findings."
        ),
        caution_notes=(
            "This module opens a normal TLS connection to the target — use only on owned or authorised assets.",
            "Authorisation and engagement/scope controls apply before execution.",
            "Does not exploit vulnerabilities, fuzz, or perform denial-of-service testing.",
            "Results reflect the point in time tested and require client validation before remediation.",
        ),
    ),
    ModuleEntry(
        module_id="infra_http_security",
        display_name="HTTP Security Header Review",
        category="Infrastructure",
        description="Controlled active HTTP response and security header review for a single authorised URL.",
        status="active",
        mode="active",
        risk_level="medium",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=True,
        accepted_target_types=("domain", "url", "ipv4"),
        config_notes=(
            "No API key required. Performs GET/HEAD requests with a short timeout and limited redirects. "
            "Requires authorisation and engagement/scope alignment for active testing."
        ),
        rate_limit_notes="Active HTTP request — single target URL per run; optional security.txt and robots.txt checks only.",
        short_help="Controlled HTTP security header, cookie flag, and well-known file review for domain, URL, or IPv4.",
        detailed_help=(
            "Reviews a single authorised HTTP(S) response for security headers, cookie flags (names only), "
            "server banners, and optional security.txt / robots.txt at standard paths. Uses GET or HEAD only — "
            "does not submit forms, browse beyond the supplied URL except exact well-known paths, or store full page bodies."
        ),
        example_inputs=("example.com", "https://example.com/login", "8.8.8.8"),
        output_summary=(
            "HTTP status, redirects, security header presence, cookie flag summary, banners, and cautious findings."
        ),
        caution_notes=(
            "This module performs live HTTP requests to the target — use only on owned or authorised assets.",
            "Authorisation and engagement/scope controls apply before execution.",
            "Cookie values and page bodies are not stored; only names, flags, and small redacted previews.",
            "Missing headers are advisory review points, not confirmed misconfigurations.",
            "Results reflect the point in time tested.",
        ),
    ),
    ModuleEntry(
        module_id="infra_remote_access_review",
        display_name="Remote Access Exposure Review",
        category="Infrastructure",
        description="Review remote administration and file-sharing services from Nmap and service observations.",
        status="active",
        mode="active",
        risk_level="medium",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=True,
        accepted_target_types=("ipv4", "domain", "url"),
        config_notes=(
            "No API key required. Uses existing Nmap/service observations — does not authenticate, "
            "guess credentials, or change remote services."
        ),
        rate_limit_notes="Analysis-assisted review of observed service data; optional manual port context only.",
        short_help="Summarise SSH, RDP, VNC, SMB, Telnet, FTP and similar exposure from observed service data.",
        detailed_help=(
            "Turns Nmap and stored service observations into cautious remote-access exposure findings. "
            "Does not log in, scan broadly, or send unsafe payloads. Run Network Service Check first when "
            "no service data exists. Suitable after Nmap identifies administrative or file-sharing ports."
        ),
        example_inputs=("192.168.1.10", "10.0.0.5", "server.example.com"),
        output_summary="Remote/admin service table, exposure context, classifications, and advisory findings.",
        caution_notes=(
            "Authorisation is required before running this module.",
            "Findings are based on observed service data and require validation.",
            "Absence of a listed service does not prove it is not exposed.",
            "Does not perform authentication or intrusive protocol testing.",
        ),
    ),
    ModuleEntry(
        module_id="infra_web_stack_identifier",
        display_name="Web Stack Identifier",
        category="Infrastructure",
        description="Identify visible web stack indicators from a normal HTTP page response.",
        status="active",
        mode="active",
        risk_level="low",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=True,
        accepted_target_types=("domain", "url", "ipv4"),
        config_notes=(
            "No API key required. Performs a single authorised HTTP GET with capped preview — "
            "does not store full page bodies."
        ),
        rate_limit_notes="Active HTTP request — single target URL per run; headers and capped HTML preview only.",
        short_help="Identify web server, CMS, framework, hosting, CDN, and analytics indicators from HTTP response metadata.",
        detailed_help=(
            "Collects response headers, meta generator, script/stylesheet references, and a small capped page "
            "preview to suggest possible web technologies. Uses cautious language — indicators are review prompts, "
            "not confirmed fingerprinting. Does not browse beyond the supplied URL except redirects during the GET."
        ),
        example_inputs=("example.com", "https://example.com", "8.8.8.8"),
        output_summary=(
            "Final URL, status, header banners, stack indicator table with confidence/source, and advisory findings."
        ),
        caution_notes=(
            "This module performs a live HTTP GET to the target — use only on owned or authorised assets.",
            "Authorisation and engagement/scope controls apply before execution.",
            "Full page bodies are not stored; only capped preview text used for detection.",
            "Indicators suggest possible technologies — validate against asset inventory.",
            "Results reflect the point in time tested.",
        ),
    ),
    ModuleEntry(
        module_id="infra_web_path_review",
        display_name="Controlled Web Path Review",
        category="Infrastructure",
        description="Sequential review of a small curated list of common public web paths on an authorised target.",
        status="active",
        mode="active",
        risk_level="medium",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=True,
        accepted_target_types=("domain", "url", "ipv4"),
        config_notes=(
            "No API key required. Checks up to 24 curated paths sequentially with short timeouts. "
            "Sensitive-name paths use HEAD only — no body content stored."
        ),
        rate_limit_notes="Active sequential HTTP requests — one path at a time; no wordlists or path mutations.",
        short_help="Check a small curated set of common web paths for posture review on an authorised target.",
        detailed_help=(
            "Performs a controlled, sequential review of common informational, admin/login, API/docs, "
            "status/health, CMS, and sensitive-name paths. Uses GET or HEAD only — does not submit forms, "
            "log in, follow discovered links, or browse the full site. Findings are cautious review prompts."
        ),
        example_inputs=("example.com", "https://example.com", "8.8.8.8"),
        output_summary=(
            "Path table with status codes, categories, redirect targets, capped previews, and advisory findings."
        ),
        caution_notes=(
            "This module performs live HTTP requests to multiple paths — use only on owned or authorised assets.",
            "Authorisation and engagement/scope controls apply before execution.",
            "Not a discovery tool — curated list only, no wordlists or mutations.",
            "Sensitive-name paths store response metadata only, not body content.",
            "A response does not confirm exposure unless content clearly supports it.",
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
        module_id="infra_email_security",
        display_name="Domain Email Security Posture",
        category="Infrastructure",
        description="Passive DNS-based review of SPF, DMARC, MX, CAA, MTA-STS, TLS-RPT and BIMI posture.",
        status="active",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=True,
        accepted_target_types=("domain", "url"),
        config_notes="No API key required. Passive DNS lookups and optional MTA-STS HTTPS policy fetch only.",
        rate_limit_notes="Uses PROJECT_OVERWATCH_RATE_LIMIT_SECONDS between batch queue passive runs.",
        short_help="Passive SPF, DMARC, MX, CAA, MTA-STS, TLS-RPT and BIMI review from public DNS.",
        detailed_help=(
            "Reviews public DNS records for email security controls: SPF and DMARC TXT records, MX routing, "
            "CAA certificate authority restrictions, MTA-STS TXT and optional HTTPS policy file, TLS-RPT "
            "reporting, and BIMI branding metadata. This module does not send email, connect via SMTP, "
            "test inboxes, brute-force selectors, or validate credentials."
        ),
        example_inputs=("example.com", "https://www.example.com/path"),
        output_summary="SPF/DMARC/MX/CAA/MTA-STS/TLS-RPT/BIMI summaries with cautious advisory findings.",
        caution_notes=(
            "DNS and public policy review only — no email is sent and no inboxes are tested.",
            "Findings are advisory and do not prove messages cannot be spoofed.",
            "Absence of a record in this lookup does not prove it is not configured elsewhere.",
            "MTA-STS policy fetch failures are lookup limitations, not confirmed target misconfigurations.",
        ),
    ),
    ModuleEntry(
        module_id="infra_whois_rdap",
        display_name="WHOIS / RDAP Intelligence",
        category="Infrastructure",
        description="Passive registration and allocation metadata for domains and IP addresses.",
        status="active",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=True,
        accepted_target_types=("domain", "url", "ipv4"),
        config_notes="No API key required. Uses IANA bootstrap RDAP with rdap.org fallback and port-43 WHOIS when RDAP is unavailable.",
        rate_limit_notes="Public registry endpoints may rate limit — automatic retry/backoff on HTTP 429/503.",
        short_help="Passive registration and allocation metadata via public RDAP for domains, URLs, and IPv4 addresses.",
        detailed_help=(
            "Collects public registration and allocation metadata using RDAP for domains, URLs (host extracted), "
            "and public IPv4 addresses. Private/local IPs return an informational result without public lookup. "
            "Registry data may be incomplete, redacted, or outdated — treat results as contextual metadata only."
        ),
        example_inputs=("example.com", "https://example.com/path", "8.8.8.8"),
        output_summary="Registrar/registry, status, dates, nameservers, abuse contacts, and RDAP entity summaries.",
        caution_notes=(
            "Passive public metadata only — no active scanning.",
            "Registration data can be redacted, incomplete, or stale.",
            "Private/local IPv4 addresses skip public RDAP lookup by design.",
            "WHOIS port-43 fallback is used when RDAP is unavailable.",
            "Per-case RDAP/WHOIS responses are cached to reduce repeat registry queries.",
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
        status="disabled",
        mode="active",
        risk_level="high",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=False,
        caution_notes=("Disabled — high-risk active scanning; not available in this release.",),
    ),
    ModuleEntry(
        module_id="vuln_ffuf",
        display_name="FFUF",
        category="Vulnerability",
        description="Web fuzzing for hidden paths and parameters.",
        status="disabled",
        mode="active",
        risk_level="high",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=False,
        caution_notes=("Disabled — high-risk fuzzing; not available in this release.",),
    ),
    ModuleEntry(
        module_id="vuln_sqlmap",
        display_name="SQLMap",
        category="Vulnerability",
        description="SQL injection testing (planned; not enabled).",
        status="disabled",
        mode="active",
        risk_level="high",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=False,
        caution_notes=("Disabled — exploit-like capability; not available in this release.",),
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
        display_name="VirusTotal Reputation Intelligence",
        category="Threat Intel",
        description="Passive reputation enrichment for domains, URLs and public IPv4 addresses using VirusTotal.",
        status="active",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=True,
        accepted_target_types=("ipv4", "domain", "url"),
        api_key_names=("VIRUSTOTAL_API_KEY",),
        config_notes=(
            "Passive module — requires VIRUSTOTAL_API_KEY in local .env. "
            "Key is masked in Settings and must never be stored in observations, findings, evidence, reports or logs."
        ),
        rate_limit_notes="VirusTotal public API rate limits apply — batch queue courtesy delay applies between lookups.",
        short_help="Passive VirusTotal reputation lookup for a domain, URL, or public IPv4 address.",
        detailed_help=(
            "Queries the VirusTotal API v3 for third-party security vendor analysis counts and community metadata. "
            "Results are reported by VirusTotal — they are leads for analyst review, not confirmed threats or benign status. "
            "Private/local IPv4 addresses are not queried."
        ),
        example_inputs=("203.0.113.10", "example.com", "https://example.com/path"),
        output_summary="Security vendor analysis summary, reputation score, and cautious advisory findings.",
        caution_notes=(
            "Third-party vendor labels require manual verification.",
            "Clean VirusTotal results do not prove a target is safe or in scope.",
            "Respect VirusTotal API rate limits and terms of use.",
            "API key must remain in .env only — never commit or paste into case notes.",
        ),
    ),
    ModuleEntry(
        module_id="intel_abuseipdb",
        display_name="AbuseIPDB Reputation Intelligence",
        category="Threat Intel",
        description="Passive AbuseIPDB abuse-confidence lookup for public IPv4 addresses.",
        status="active",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=True,
        accepted_target_types=("ipv4",),
        api_key_names=("ABUSEIPDB_API_KEY",),
        config_notes=(
            "Passive module — requires ABUSEIPDB_API_KEY in local .env. "
            "Key is masked in Settings and must never be stored in observations, findings, evidence, reports or logs. "
            "Lookup-only — does not submit abuse reports."
        ),
        rate_limit_notes="AbuseIPDB daily query limits depend on your plan — batch queue courtesy delay applies.",
        short_help="Passive AbuseIPDB abuse-confidence lookup for a public IPv4 address.",
        detailed_help=(
            "Queries the AbuseIPDB check API for third-party abuse reports and confidence scores. "
            "Results are reported by AbuseIPDB — they are leads for analyst review, not confirmed malicious activity. "
            "Private/local IPv4 addresses are not queried. Domains and URLs are not supported in v2.3."
        ),
        example_inputs=("203.0.113.10", "8.8.8.8"),
        output_summary="Abuse confidence score, report counts, ISP/country context, and cautious advisory findings.",
        caution_notes=(
            "Third-party abuse reports require manual verification.",
            "Low or zero scores do not prove an IP is safe or in scope.",
            "Respect AbuseIPDB API rate limits and terms of use.",
            "Lookup-only — never submit reports through Project Overwatch.",
            "API key must remain in .env only — never commit or paste into case notes.",
        ),
    ),
    ModuleEntry(
        module_id="intel_greynoise",
        display_name="GreyNoise Internet Noise Intelligence",
        category="Threat Intel",
        description=(
            "Passive GreyNoise lookup for public IPv4 addresses to identify internet noise, "
            "scanner context and classification signals."
        ),
        status="active",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=True,
        accepted_target_types=("ipv4",),
        api_key_names=("GREYNOISE_API_KEY",),
        config_notes=(
            "Passive module — GREYNOISE_API_KEY in local .env is optional but recommended. "
            "Unauthenticated Community API lookups may be limited. Key is masked in Settings and must never "
            "be stored in observations, findings, evidence, reports or logs."
        ),
        rate_limit_notes="GreyNoise Community API daily rate limits apply — batch queue courtesy delay applies.",
        short_help="Passive GreyNoise internet-noise and RIOT lookup for a public IPv4 address.",
        detailed_help=(
            "Queries the GreyNoise v3 Community API for third-party internet noise, RIOT, and classification context. "
            "Results are reported by GreyNoise — they are leads for analyst review, not confirmed threats. "
            "Private/local IPv4 addresses are not queried. Domains and URLs are not supported in this version."
        ),
        example_inputs=("8.8.8.8", "1.1.1.1"),
        output_summary="Noise/RIOT flags, classification, provider name, last seen, and cautious advisory findings.",
        caution_notes=(
            "Internet-noise context requires manual verification.",
            "RIOT/benign labels do not prove an IP is safe or in scope.",
            "Respect GreyNoise API rate limits and terms of use.",
            "Uses v3 Community API only — no deprecated v2 endpoints.",
            "API key must remain in .env only — never commit or paste into case notes.",
        ),
    ),
    ModuleEntry(
        module_id="intel_shodan",
        display_name="Shodan Internet Exposure Intelligence",
        category="Threat Intel",
        description=(
            "Passive Shodan host lookup for public IPv4 addresses to identify internet-exposed "
            "services previously observed by Shodan."
        ),
        status="active",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=True,
        accepted_target_types=("ipv4",),
        api_key_names=("SHODAN_API_KEY",),
        config_notes=(
            "Passive module — requires SHODAN_API_KEY in local .env. "
            "Key is masked in Settings and must never be stored in observations, findings, evidence, "
            "reports or logs. Host lookup only — does not trigger Shodan scans."
        ),
        rate_limit_notes="Shodan query credits depend on your plan — batch queue courtesy delay applies.",
        short_help="Passive Shodan host exposure lookup for a public IPv4 address.",
        detailed_help=(
            "Queries the Shodan host API for third-party internet-exposure observations previously "
            "collected by Shodan. Results are reported by Shodan — they may be stale or incomplete and "
            "are not proof that services are currently open. Private/local IPv4 addresses are not queried. "
            "Domains and URLs are not supported in v2.5."
        ),
        example_inputs=("8.8.8.8", "1.1.1.1"),
        output_summary=(
            "Organisation/ISP/ASN, hostnames, ports, service summaries, last update, "
            "and cautious advisory findings."
        ),
        caution_notes=(
            "Shodan results are third-party observations and may be stale or incomplete.",
            "Reported services are not proof of current exposure — use authorised Nmap for local verification.",
            "This module does not trigger Shodan on-demand scans, search, alerts, or streaming.",
            "Respect Shodan API rate limits and terms of use.",
            "API key must remain in .env only — never commit or paste into case notes.",
        ),
    ),
    ModuleEntry(
        module_id="intel_urlhaus",
        display_name="URLhaus Malware URL Intelligence",
        category="Threat Intel",
        description="Passive abuse.ch URLhaus lookup for malware URL and host intelligence.",
        status="active",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=True,
        accepted_target_types=("url", "domain", "ipv4"),
        api_key_names=("ABUSECH_AUTH_KEY", "URLHAUS_AUTH_KEY"),
        config_notes=(
            "Passive module — requires ABUSECH_AUTH_KEY in local .env (URLHAUS_AUTH_KEY optional alias). "
            "Auth-Key is sent in the HTTP header only and must never be stored in observations, findings, "
            "evidence, reports or logs. Lookup-only — does not submit URLs or download malware samples."
        ),
        rate_limit_notes="URLhaus API rate limits depend on your abuse.ch account — batch queue courtesy delay applies.",
        short_help="Passive URLhaus malware URL/host lookup for URLs, domains, and public IPv4 addresses.",
        detailed_help=(
            "Queries URLhaus v1 URL or host endpoints for third-party malware URL intelligence. "
            "URL targets use the URL information endpoint; domain/host/public IPv4 targets use the host endpoint. "
            "Results are reported by URLhaus — not independently confirmed by Overwatch. "
            "Private/local IPv4 addresses are not queried."
        ),
        example_inputs=(
            "http://example.com/malware.exe",
            "example.com",
            "8.8.8.8",
        ),
        output_summary=(
            "Query status, URL/host status, threat/tags, blacklist summary, sampled URLs, "
            "payload hash summaries, and cautious advisory findings."
        ),
        caution_notes=(
            "URLhaus results are third-party malware URL intelligence.",
            "Host matches do not mean every URL/path on the host is malicious.",
            "Results are reported by URLhaus — not independently confirmed by Overwatch.",
            "No malware payloads are downloaded and no URLs are submitted.",
            "No active verification or fetching of malicious URLs is performed.",
            "Auth-Key must remain in .env only — never commit or paste into case notes.",
        ),
    ),
    ModuleEntry(
        module_id="net_pcap_review",
        display_name="PCAP Evidence Review",
        category="Network Analysis",
        description="Local-only review of uploaded packet capture files with bounded traffic summaries.",
        status="active",
        mode="analysis",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=False,
        implemented=True,
        accepted_target_types=("file", "pcap", "pcapng"),
        config_notes=(
            "Local file analysis only — upload a .pcap or .pcapng file. "
            "Optional pyshark plus Wireshark/tshark for deeper parsing. "
            "No live capture, wireless monitor mode, payload display, or decryption in this release."
        ),
        rate_limit_notes="Not applicable — analysis runs against uploaded files only.",
        short_help="Review an uploaded .pcap/.pcapng capture with bounded protocol and flow summaries.",
        detailed_help=(
            "Analyses a supplied packet capture locally to produce traffic summaries, DNS/HTTP/TLS metadata, "
            "cautious findings, and evidence items. Sensitive-looking values are redacted. "
            "Raw packet payloads are not displayed by default. "
            "Results reflect only the uploaded capture — not live network state."
        ),
        example_inputs=("lab-traffic.pcap", "incident-capture.pcapng"),
        output_summary=(
            "File hash, packet counts, duration, protocol summaries, top talkers/conversations, "
            "DNS/HTTP/TLS samples, cleartext indicators, and advisory findings."
        ),
        caution_notes=(
            "Supplied-capture-only analysis — not live network capture.",
            "Install pyshark and tshark for full parsing; metadata-only fallback otherwise.",
            "Passwords, tokens, cookies, and raw payloads are not shown by default.",
            "Findings are analyst aids based on the supplied capture only.",
        ),
    ),
    ModuleEntry(
        module_id="net_live_capture",
        display_name="Personal Lab Packet Capture",
        category="Network Analysis",
        description="Bounded live packet capture for Personal Lab with automatic PCAP Evidence Review handoff.",
        status="active",
        mode="local-capture",
        risk_level="medium",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=True,
        accepted_target_types=("unknown", "ipv4", "domain", "url"),
        config_notes=(
            "Personal Lab capture only — requires single confirmation checkbox. "
            "Uses tshark or tcpdump subprocess capture with duration and packet caps. "
            "No wireless monitor mode, packet sending, or continuous capture."
        ),
        rate_limit_notes="Sequential captures only — one bounded run at a time.",
        short_help="Capture packets on a selected interface for a short bounded window, then analyse automatically.",
        detailed_help=(
            "Lists local interfaces, runs a capped live capture to a controlled case folder, "
            "hashes the PCAP, and hands off to PCAP Evidence Review. "
            "Requires Personal Lab confirmation. macOS may require capture permissions."
        ),
        example_inputs=("live-capture:en0",),
        output_summary=(
            "Capture metadata, file hash, bounded PCAP analysis summary, and cautious findings."
        ),
        caution_notes=(
            "Capture only on systems and networks you own or are authorised to monitor.",
            "Short duration and packet caps are enforced.",
            "Permission issues are explained with a manual command suggestion.",
            "Raw payloads and sensitive values are not displayed by default.",
        ),
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
        description="DNS and domain history intelligence (planned — paid/API access likely required).",
        status="planned",
        mode="passive",
        risk_level="low",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=False,
        api_key_names=("SECURITYTRAILS_API_KEY",),
        config_notes=(
            "Requires SECURITYTRAILS_API_KEY in local .env. Planned only — SecurityTrails appears to require "
            "paid/API access and is not implemented in this release. Roadmap placeholder only."
        ),
        rate_limit_notes="Monthly API allowance depends on your SecurityTrails plan (when implemented).",
        caution_notes=(
            "Not available in Run Operation, Entity Workspace, or Batch Queue.",
            "SecurityTrails integration is deferred pending API access review.",
        ),
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
        status="disabled",
        mode="passive",
        risk_level="medium",
        requires_authorisation=False,
        requires_api_key=True,
        implemented=False,
        accepted_target_types=("email", "domain"),
        api_key_names=("HAVEIBEENPWNED_API_KEY",),
        config_notes="Disabled — credential/breach lookup module; not available in this release.",
        rate_limit_notes="HIBP API rate limits apply per key tier.",
        caution_notes=("Disabled — breach/credential intelligence requires explicit guardrails.",),
    ),
    # Dark Web
    ModuleEntry(
        module_id="dark_ahmia",
        display_name="Ahmia",
        category="Dark Web",
        description="Search public Tor hidden-service indexes.",
        status="disabled",
        mode="passive",
        risk_level="medium",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=False,
        caution_notes=("Disabled — Tor/dark-web collection not available in this release.",),
    ),
    ModuleEntry(
        module_id="dark_dehashed",
        display_name="Dehashed",
        category="Dark Web",
        description="Breach data lookup for compromised credentials.",
        status="disabled",
        mode="passive",
        risk_level="high",
        requires_authorisation=True,
        requires_api_key=True,
        implemented=False,
        caution_notes=("Disabled — credential breach lookup; not available in this release.",),
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
        status="disabled",
        mode="passive",
        risk_level="medium",
        requires_authorisation=True,
        requires_api_key=False,
        implemented=False,
        caution_notes=("Disabled — cloud enumeration requires explicit guardrails.",),
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
    if module.module_id in QUARANTINED_MODULE_IDS:
        return False
    return module.implemented and module.status == "active"


def module_ui_label(module: ModuleEntry) -> str:
    """Build a sidebar label with mode and status for clarity."""
    if module.status == "disabled":
        return f"{module.display_name} (disabled)"
    if is_executable(module):
        mode_label = {"active": "Active", "passive": "Passive", "analysis": "Analysis"}.get(
            module.mode, module.mode.title()
        )
        return f"{module.display_name} [{mode_label}]"
    return f"{module.display_name} (planned)"


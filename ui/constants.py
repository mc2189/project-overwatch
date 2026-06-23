"""Shared UI constants for Project Overwatch."""

from __future__ import annotations

NAV_PAGES: tuple[str, ...] = (
    "Run Operation",
    "Client Engagements",
    "Findings",
    "Entity Workspace",
    "Batch Queue",
    "Relationships",
    "Observations",
    "Evidence Locker",
    "Operations",
    "Graph",
    "Report",
    "Backup",
    "Settings",
    "Roadmap",
)

IMPLEMENTED_MODULE_IDS: tuple[str, ...] = (
    "infra_nmap",
    "infra_tls_review",
    "infra_http_security",
    "infra_domain_intel",
    "infra_cert_subdomain",
    "infra_website_metadata",
    "infra_email_security",
    "infra_whois_rdap",
    "intel_virustotal",
    "intel_abuseipdb",
    "intel_greynoise",
    "intel_shodan",
    "intel_urlhaus",
)

MODULE_CARD_TITLES: dict[str, str] = {
    "infra_nmap": "Network Service Check, powered by Nmap",
    "infra_tls_review": "SSL / TLS Configuration Review",
    "infra_http_security": "HTTP Security Header Review",
    "infra_domain_intel": "Domain Intelligence",
    "infra_cert_subdomain": "Certificate & Subdomain Intelligence",
    "infra_website_metadata": "Website Metadata Review",
    "infra_email_security": "Domain Email Security Posture",
    "infra_whois_rdap": "WHOIS / RDAP Intelligence",
    "intel_virustotal": "VirusTotal Reputation Intelligence",
    "intel_abuseipdb": "AbuseIPDB Reputation Intelligence",
    "intel_greynoise": "GreyNoise Internet Noise Intelligence",
    "intel_shodan": "Shodan Internet Exposure Intelligence",
    "intel_urlhaus": "URLhaus Malware URL Intelligence",
}

FINDING_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
FINDING_SEVERITY_OPTIONS = ("",) + FINDING_SEVERITY_ORDER
FINDING_STATUS_LABELS = {
    "open": "Open",
    "in_review": "In review",
    "action_required": "Action required",
    "accepted": "Accepted",
    "false_positive": "False positive",
    "closed": "Closed",
}

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

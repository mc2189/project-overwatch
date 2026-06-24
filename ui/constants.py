"""Shared UI constants for Project Overwatch."""

from __future__ import annotations

from modules.module_registry import MODULES, is_executable

NAV_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    (
        "Run",
        (
            "Assessment Workspace",
            "Packet Capture",
            "Batch Queue",
        ),
    ),
    (
        "Investigate",
        (
            "Findings",
            "Entity Workspace",
            "Evidence Locker",
            "Graph",
            "Relationships",
            "Observations",
            "Operations",
        ),
    ),
    (
        "Case",
        (
            "Report",
            "Client Engagements",
            "Backup",
        ),
    ),
    (
        "Admin",
        (
            "Settings",
            "Roadmap",
        ),
    ),
)

NAV_PAGES: tuple[str, ...] = tuple(page for _, pages in NAV_GROUPS for page in pages)

NAV_GROUP_BY_PAGE: dict[str, str] = {
    page: section for section, pages in NAV_GROUPS for page in pages
}

LEGACY_NAV_PAGE_ALIASES: dict[str, str] = {
    "Run Operation": "Assessment Workspace",
    "Entities": "Entity Workspace",
}


def normalize_nav_page(page: str | None) -> str:
    """Map legacy nav labels to current page names."""
    if not page:
        return "Assessment Workspace"
    return LEGACY_NAV_PAGE_ALIASES.get(page, page)


def implemented_module_ids() -> tuple[str, ...]:
    """Executable module IDs from the registry (single source of truth)."""
    return tuple(sorted(module.module_id for module in MODULES if is_executable(module)))


IMPLEMENTED_MODULE_IDS: tuple[str, ...] = implemented_module_ids()

MODULE_CARD_TITLES: dict[str, str] = {
    "infra_nmap": "Network Service Check (Nmap Profile Runner)",
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
    "net_pcap_review": "PCAP Evidence Review",
    "net_live_capture": "Personal Lab Packet Capture",
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

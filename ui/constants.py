"""Shared UI constants for Project Overwatch."""

from __future__ import annotations

from modules.module_registry import MODULES, is_executable

# Full capability map (non-solo sidebar still uses these groups).
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
            "Case Archive",
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

# Solo / Express Lab: short primary strip + demoted “More” pages.
SOLO_PRIMARY_NAV: tuple[tuple[str, str], ...] = (
    ("Assessment Workspace", "Lab"),
    ("Packet Capture", "Capture"),
    ("Findings", "Findings"),
    ("Entity Workspace", "Entities"),
    ("Evidence Locker", "Evidence"),
)

SOLO_MORE_NAV: tuple[str, ...] = (
    "Case Archive",
    "Batch Queue",
    "Report",
    "Client Engagements",
    "Backup",
    "Settings",
    "Roadmap",
)

SOLO_PRIMARY_PAGES: tuple[str, ...] = tuple(page for page, _ in SOLO_PRIMARY_NAV)
SOLO_PRIMARY_LABEL_BY_PAGE: dict[str, str] = {page: label for page, label in SOLO_PRIMARY_NAV}
SOLO_PRIMARY_PAGE_BY_LABEL: dict[str, str] = {label: page for page, label in SOLO_PRIMARY_NAV}

CASE_ARCHIVE_TABS: tuple[str, ...] = (
    "Graph",
    "Relationships",
    "Observations",
    "Operations",
)

LEGACY_NAV_PAGE_ALIASES: dict[str, str] = {
    "Run Operation": "Assessment Workspace",
    "Entities": "Entity Workspace",
    "Graph": "Case Archive",
    "Relationships": "Case Archive",
    "Observations": "Case Archive",
    "Operations": "Case Archive",
}

ARCHIVE_TAB_BY_LEGACY_PAGE: dict[str, str] = {
    "Graph": "Graph",
    "Relationships": "Relationships",
    "Observations": "Observations",
    "Operations": "Operations",
}


def normalize_nav_page(page: str | None) -> str:
    """Map legacy nav labels to current page names."""
    if not page:
        return "Assessment Workspace"
    if page in ARCHIVE_TAB_BY_LEGACY_PAGE and page not in NAV_PAGES:
        return "Case Archive"
    return LEGACY_NAV_PAGE_ALIASES.get(page, page)


def implemented_module_ids() -> tuple[str, ...]:
    """Executable module IDs from the registry (single source of truth)."""
    return tuple(sorted(module.module_id for module in MODULES if is_executable(module)))


IMPLEMENTED_MODULE_IDS: tuple[str, ...] = implemented_module_ids()

MODULE_CARD_TITLES: dict[str, str] = {
    "infra_nmap": "Network Service Check (Nmap Profile Runner)",
    "infra_tls_review": "SSL / TLS Configuration Review",
    "infra_http_security": "HTTP Security Header Review",
    "infra_remote_access_review": "Remote Access Exposure Review",
    "infra_ssh_review": "SSH Configuration Review",
    "infra_web_stack_identifier": "Web Stack Identifier",
    "infra_web_path_review": "Controlled Web Path Review",
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
    "evidence_file_metadata": "Document and Image Metadata Review",
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

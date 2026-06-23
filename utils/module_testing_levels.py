"""Module testing level classification for authorised assessment guardrails."""

from __future__ import annotations

from typing import Any, Literal

from utils.nmap_options import PROFILE_DETAILED, SCRIPT_VULN

TestingLevel = Literal[
    "passive_lookup",
    "safe_active_check",
    "intrusive_active_check",
    "high_risk_manual_only",
    "prohibited",
]

TESTING_LEVEL_LABELS: dict[str, str] = {
    "passive_lookup": "Passive lookup",
    "safe_active_check": "Safe active check",
    "intrusive_active_check": "Intrusive active check",
    "high_risk_manual_only": "High-risk manual only",
    "prohibited": "Prohibited",
}

MODULE_TESTING_LEVELS: dict[str, TestingLevel] = {
    # Passive OSINT / enrichment
    "infra_whois_rdap": "passive_lookup",
    "infra_domain_intel": "passive_lookup",
    "infra_cert_subdomain": "passive_lookup",
    "infra_website_metadata": "passive_lookup",
    "infra_email_security": "passive_lookup",
    "intel_virustotal": "passive_lookup",
    "intel_abuseipdb": "passive_lookup",
    "intel_greynoise": "passive_lookup",
    "intel_shodan": "passive_lookup",
    "intel_urlhaus": "passive_lookup",
    # Active
    "infra_nmap": "safe_active_check",
    # Planned authorised assessment modules
    "vuln_nuclei": "intrusive_active_check",
    "vuln_ffuf": "intrusive_active_check",
    "infra_ssl_tls": "safe_active_check",
    "infra_http_headers": "safe_active_check",
    "infra_web_fingerprint": "passive_lookup",
    "vuln_web_misconfig": "safe_active_check",
    "infra_amass": "passive_lookup",
    "intel_harvester": "passive_lookup",
    "infra_local_inventory": "safe_active_check",
    "resilience_auth_checks": "intrusive_active_check",
    # High-risk / manual-only placeholders
    "vuln_sqlmap": "high_risk_manual_only",
    "vuln_cred_test": "high_risk_manual_only",
    "vuln_password_spray": "high_risk_manual_only",
    "vuln_social_engineering": "high_risk_manual_only",
    "cloud_enum": "high_risk_manual_only",
    "vuln_exploit_validation": "high_risk_manual_only",
    "intel_malware_samples": "high_risk_manual_only",
    "dark_ahmia": "high_risk_manual_only",
    "dark_dehashed": "high_risk_manual_only",
}

PROHIBITED_MODULE_IDS: frozenset[str] = frozenset(
    {
        "prohibited_unauthorised",
        "prohibited_evasion",
        "prohibited_persistence",
        "prohibited_destructive",
        "prohibited_dos",
        "prohibited_malware_deploy",
        "prohibited_cred_theft",
        "prohibited_exfiltration",
    }
)

LEVEL_RANK: dict[str, int] = {
    "passive_lookup": 0,
    "safe_active_check": 1,
    "intrusive_active_check": 2,
    "high_risk_manual_only": 3,
    "prohibited": 4,
}


def get_module_testing_level(module_id: str, options: dict[str, Any] | None = None) -> TestingLevel:
    """Resolve the testing level for a module run, including Nmap profile nuances."""
    if module_id in PROHIBITED_MODULE_IDS:
        return "prohibited"
    if module_id == "infra_nmap":
        nmap_options = (options or {}).get("nmap_options") or options or {}
        script_category = nmap_options.get("script_category")
        profile = nmap_options.get("profile")
        if script_category == SCRIPT_VULN:
            return "intrusive_active_check"
        if profile == PROFILE_DETAILED:
            return "intrusive_active_check"
        return "safe_active_check"
    return MODULE_TESTING_LEVELS.get(module_id, "passive_lookup")


def testing_level_label(level: str) -> str:
    return TESTING_LEVEL_LABELS.get(level, level.replace("_", " ").title())


def is_active_testing_level(level: str) -> bool:
    return LEVEL_RANK.get(level, 0) >= LEVEL_RANK["safe_active_check"]


def is_intrusive_testing_level(level: str) -> bool:
    return LEVEL_RANK.get(level, 0) >= LEVEL_RANK["intrusive_active_check"]

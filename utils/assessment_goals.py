"""Assessment goal definitions for the guided workspace."""

from __future__ import annotations

from utils.run_modes import (
    CUSTOM,
    LOCAL_IP_CHECK,
    QUICK_CHECK,
    WEBSITE_FOOTPRINT,
    get_recommended_modules_for_mode,
    resolve_recommended_modules_for_mode,
)
from utils.security import is_private_or_local_ip
from utils.settings_manager import has_api_key

GOAL_QUICK_SAFETY = "quick_safety_check"
GOAL_WEBSITE_POSTURE = "website_domain_posture"
GOAL_EMAIL_SPOOFING = "email_domain_spoofing_review"
GOAL_EXTERNAL_EXPOSURE = "external_exposure_review"
GOAL_THREAT_REPUTATION = "threat_reputation_review"
GOAL_LOCAL_NETWORK = "local_network_check"
GOAL_EVIDENCE_REVIEW = "uploaded_evidence_review"
GOAL_LIVE_CAPTURE = "live_packet_capture"
GOAL_FULL_CLIENT = "full_client_assessment"
GOAL_CUSTOM = "custom_module_selection"

GOAL_ORDER: tuple[str, ...] = (
    GOAL_QUICK_SAFETY,
    GOAL_WEBSITE_POSTURE,
    GOAL_EMAIL_SPOOFING,
    GOAL_EXTERNAL_EXPOSURE,
    GOAL_THREAT_REPUTATION,
    GOAL_LOCAL_NETWORK,
    GOAL_EVIDENCE_REVIEW,
    GOAL_LIVE_CAPTURE,
    GOAL_FULL_CLIENT,
    GOAL_CUSTOM,
)

GOAL_LABELS: dict[str, str] = {
    GOAL_QUICK_SAFETY: "Quick safety check",
    GOAL_WEBSITE_POSTURE: "Website/domain posture review",
    GOAL_EMAIL_SPOOFING: "Email/domain spoofing review",
    GOAL_EXTERNAL_EXPOSURE: "External exposure review",
    GOAL_THREAT_REPUTATION: "Threat reputation review",
    GOAL_LOCAL_NETWORK: "Local network check",
    GOAL_EVIDENCE_REVIEW: "Uploaded evidence review",
    GOAL_LIVE_CAPTURE: "Live packet capture",
    GOAL_FULL_CLIENT: "Full client-style assessment",
    GOAL_CUSTOM: "Custom module selection",
}

GOAL_DESCRIPTIONS: dict[str, str] = {
    GOAL_QUICK_SAFETY: "Fastest useful checks for the detected target type with minimal configuration.",
    GOAL_WEBSITE_POSTURE: "Passive DNS, email security, certificate transparency, and website metadata.",
    GOAL_EMAIL_SPOOFING: "SPF, DMARC, MX and related DNS controls that affect spoofing and mail security.",
    GOAL_EXTERNAL_EXPOSURE: "Internet exposure context from Shodan, subdomains, and supporting passive checks.",
    GOAL_THREAT_REPUTATION: "Third-party reputation and malware URL intelligence where API keys allow.",
    GOAL_LOCAL_NETWORK: "Conservative network service check for a private or local IPv4 address.",
    GOAL_EVIDENCE_REVIEW: "Upload and review a .pcap or .pcapng packet capture locally — no live network capture.",
    GOAL_LIVE_CAPTURE: "Start a bounded Personal Lab packet capture from the Packet Capture page — no client engagement required.",
    GOAL_FULL_CLIENT: "Broader passive footprint plus optional active TLS/HTTP checks when authorised.",
    GOAL_CUSTOM: "Choose any compatible module manually (advanced).",
}

GOAL_TO_RUN_MODE: dict[str, str] = {
    GOAL_QUICK_SAFETY: QUICK_CHECK,
    GOAL_WEBSITE_POSTURE: WEBSITE_FOOTPRINT,
    GOAL_LOCAL_NETWORK: LOCAL_IP_CHECK,
    GOAL_CUSTOM: CUSTOM,
}

_GOAL_MODULE_SETS: dict[str, tuple[str, ...]] = {
    GOAL_EMAIL_SPOOFING: (
        "infra_email_security",
        "infra_whois_rdap",
        "infra_domain_intel",
    ),
    GOAL_EXTERNAL_EXPOSURE: (
        "intel_shodan",
        "infra_cert_subdomain",
        "infra_domain_intel",
        "infra_whois_rdap",
    ),
    GOAL_THREAT_REPUTATION: (
        "intel_virustotal",
        "intel_abuseipdb",
        "intel_greynoise",
        "intel_shodan",
        "intel_urlhaus",
    ),
    GOAL_FULL_CLIENT: (
        "infra_whois_rdap",
        "infra_domain_intel",
        "infra_email_security",
        "infra_cert_subdomain",
        "infra_website_metadata",
        "infra_tls_review",
        "infra_http_security",
    ),
}

SUGGESTED_GOALS_BY_TARGET: dict[str, tuple[str, ...]] = {
    "domain": (
        GOAL_WEBSITE_POSTURE,
        GOAL_EMAIL_SPOOFING,
        GOAL_THREAT_REPUTATION,
        GOAL_EXTERNAL_EXPOSURE,
        GOAL_QUICK_SAFETY,
    ),
    "url": (
        GOAL_WEBSITE_POSTURE,
        GOAL_THREAT_REPUTATION,
        GOAL_QUICK_SAFETY,
    ),
    "ipv4": (
        GOAL_THREAT_REPUTATION,
        GOAL_EXTERNAL_EXPOSURE,
        GOAL_QUICK_SAFETY,
    ),
    "email": (GOAL_EMAIL_SPOOFING, GOAL_QUICK_SAFETY),
    "pcap": (GOAL_EVIDENCE_REVIEW,),
    "pcapng": (GOAL_EVIDENCE_REVIEW,),
    "file": (GOAL_EVIDENCE_REVIEW,),
    "unknown": (GOAL_QUICK_SAFETY,),
}


def list_assessment_goals() -> list[tuple[str, str]]:
    return [(goal_id, GOAL_LABELS[goal_id]) for goal_id in GOAL_ORDER]


def goal_label(goal_id: str) -> str:
    return GOAL_LABELS.get(goal_id, goal_id.replace("_", " ").title())


def goal_description(goal_id: str) -> str:
    return GOAL_DESCRIPTIONS.get(goal_id, "")


def suggested_goals_for_target(target_type: str, target: str = "") -> list[str]:
    goals = list(SUGGESTED_GOALS_BY_TARGET.get(target_type, SUGGESTED_GOALS_BY_TARGET["unknown"]))
    if target_type == "ipv4" and target.strip() and is_private_or_local_ip(target.strip()):
        if GOAL_LOCAL_NETWORK not in goals:
            goals.insert(0, GOAL_LOCAL_NETWORK)
    if target_type in {"domain", "url"} and GOAL_FULL_CLIENT not in goals:
        goals.append(GOAL_FULL_CLIENT)
    seen: set[str] = set()
    ordered: list[str] = []
    for goal_id in goals:
        if goal_id not in seen:
            seen.add(goal_id)
            ordered.append(goal_id)
    return ordered


def _filter_configured_reputation(modules: list[str]) -> list[str]:
    filtered: list[str] = []
    for module_id in modules:
        if module_id == "intel_virustotal" and not has_api_key("VIRUSTOTAL_API_KEY"):
            continue
        if module_id == "intel_abuseipdb" and not has_api_key("ABUSEIPDB_API_KEY"):
            continue
        if module_id == "intel_shodan" and not has_api_key("SHODAN_API_KEY"):
            continue
        if module_id == "intel_urlhaus":
            from utils.settings_manager import get_urlhaus_auth_key

            if not get_urlhaus_auth_key():
                continue
        filtered.append(module_id)
    return filtered


def get_modules_for_goal(
    goal_id: str,
    target_type: str,
    *,
    target: str | None = None,
    quick_check_include_port_scan: bool = False,
) -> list[str]:
    """Return recommended module IDs for an assessment goal and target."""
    if goal_id == GOAL_EVIDENCE_REVIEW:
        return ["net_pcap_review"]
    if goal_id == GOAL_LIVE_CAPTURE:
        return ["net_live_capture"]
    if goal_id == GOAL_CUSTOM:
        return []
    run_mode = GOAL_TO_RUN_MODE.get(goal_id)
    if run_mode:
        return resolve_recommended_modules_for_mode(
            run_mode,
            target_type,
            quick_check_include_port_scan=quick_check_include_port_scan,
            target=target,
        )
    modules = list(_GOAL_MODULE_SETS.get(goal_id, ()))
    if goal_id == GOAL_THREAT_REPUTATION:
        modules = _filter_configured_reputation(modules)
    elif goal_id == GOAL_EXTERNAL_EXPOSURE:
        modules = _filter_configured_reputation(modules)
    elif goal_id == GOAL_FULL_CLIENT and target:
        base = list(_GOAL_MODULE_SETS[GOAL_FULL_CLIENT])
        if target_type == "ipv4":
            if is_private_or_local_ip(target):
                base = ["infra_nmap"]
            else:
                extra = get_recommended_modules_for_mode(QUICK_CHECK, "ipv4", target=target)
                for module_id in extra:
                    if module_id not in base:
                        base.append(module_id)
        modules = _filter_configured_reputation(base)
    return modules


def goal_to_run_mode_id(goal_id: str) -> str:
    return GOAL_TO_RUN_MODE.get(goal_id, CUSTOM)

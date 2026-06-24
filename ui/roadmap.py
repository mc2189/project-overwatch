"""Planned modules and authorised assessment roadmap for Project Overwatch."""

from __future__ import annotations

import streamlit as st

from modules.module_registry import CATEGORIES, MODULES, get_module, is_executable
from utils.module_compatibility import module_detailed_help, module_short_help
from utils.module_testing_levels import MODULE_TESTING_LEVELS, testing_level_label

ROADMAP_SECTIONS: tuple[dict[str, object], ...] = (
    {
        "title": "Active now",
        "description": (
            "Implemented modules available on Assessment Workspace when compatible with the target. "
            "Choose an operating context on Assessment Workspace: **Passive Research** for passive OSINT, "
            "**Personal Lab** for self-owned / authorised lab testing with confirmation, or "
            "**Client Engagement** for formal client work with full scope and ROE controls."
        ),
        "module_ids": (
            "infra_whois_rdap",
            "infra_domain_intel",
            "infra_email_security",
            "infra_cert_subdomain",
            "infra_website_metadata",
            "intel_virustotal",
            "intel_abuseipdb",
            "intel_greynoise",
            "intel_shodan",
            "intel_urlhaus",
            "infra_nmap",
            "infra_tls_review",
            "infra_http_security",
            "infra_web_stack_identifier",
            "net_pcap_review",
            "net_live_capture",
        ),
    },
    {
        "title": "Future network capture modules",
        "description": (
            "Planned live-capture and wireless review capabilities requiring Personal Lab or Client Engagement "
            "context, explicit authorisation, and additional safety design."
        ),
        "bullets": (
            "Bounded Personal Lab Packet Capture — active now (Packet Capture page)",
            "Wi-Fi Environment Survey — future, higher caution",
            "Wireless Security Review / monitor mode — future, not enabled",
            "Packet Decryption / Password Recovery — not enabled by default",
        ),
    },
    {
        "title": "Planned authorised assessment modules",
        "description": (
            "Future active modules designed for client engagements with documented scope, rules of engagement, "
            "and explicit authorisation. Not enabled yet — requires active engagement, in-scope targets, and ROE controls."
        ),
        "module_ids": (
            "vuln_nuclei",
            "vuln_ffuf",
            "infra_web_fingerprint",
            "vuln_web_misconfig",
            "infra_amass",
            "intel_harvester",
            "infra_local_inventory",
            "resilience_auth_checks",
            "intel_securitytrails",
        ),
        "labels": {
            "vuln_nuclei": "Requires active engagement · explicit scope · ROE controls · not enabled yet",
            "vuln_ffuf": "Requires active engagement · explicit scope · ROE controls · not enabled yet",
            "intel_securitytrails": "Planned only — likely requires paid/API access",
        },
    },
    {
        "title": "High-risk / manual-only",
        "description": (
            "Capabilities that may be considered only with separate design, legal review, and manual approval. "
            "Not enabled in Project Overwatch by default."
        ),
        "module_ids": (
            "vuln_sqlmap",
            "vuln_cred_test",
            "vuln_password_spray",
            "vuln_social_engineering",
            "cloud_enum",
            "vuln_exploit_validation",
            "intel_malware_samples",
            "dark_ahmia",
            "dark_dehashed",
            "intel_hibp",
        ),
    },
    {
        "title": "Prohibited by default",
        "description": (
            "Behaviours that must not be implemented as automated modules in Project Overwatch without "
            "fundamental policy change."
        ),
        "bullets": (
            "Unauthorised testing against out-of-scope or unknown targets",
            "Evasion, bypass, or stealth persistence techniques",
            "Destructive testing or denial-of-service",
            "Malware deployment or payload execution",
            "Credential theft, spraying, or stuffing automation",
            "Uncontrolled data exfiltration",
        ),
    },
)


def _render_module_card(module_id: str, extra_label: str | None = None) -> None:
    module = get_module(module_id)
    if module is None:
        st.markdown(f"**{module_id}** — registry entry missing")
        return
    testing_level = MODULE_TESTING_LEVELS.get(module_id, "passive_lookup")
    status_note = "implemented" if is_executable(module) else module.status
    st.markdown(
        f"**{module.display_name}** · {module.mode.title()} · "
        f"{module.risk_level.title()} risk · {testing_level_label(testing_level)} · Status: {status_note}"
    )
    if extra_label:
        st.caption(extra_label)
    st.write(module_short_help(module))
    st.caption(module_detailed_help(module))
    if module.accepted_target_types:
        st.caption("Target types: " + ", ".join(module.accepted_target_types))
    if module.requires_authorisation:
        st.caption("Requires explicit authorisation and the correct operating context (Personal Lab or Client Engagement).")


def render_roadmap_page() -> None:
    st.title("Roadmap")
    st.caption(
        "Project Overwatch supports passive OSINT today and is being extended for authorised client assessments. "
        "Intrusive tools are planned authorised assessment modules — not permanently excluded — but require "
        "engagement records, scope, rules of engagement, and explicit approval before they can run. "
        "Personal Lab Mode is for learning and owner-controlled testing without pretending to be a client engagement."
    )

    for section in ROADMAP_SECTIONS:
        st.markdown(f"### {section['title']}")
        st.write(section["description"])
        labels = section.get("labels") or {}
        module_ids = section.get("module_ids") or ()
        bullets = section.get("bullets") or ()
        if module_ids:
            with st.expander(f"View modules — {section['title']}", expanded=section["title"] == "Active now"):
                for module_id in module_ids:
                    _render_module_card(module_id, labels.get(module_id))
                    st.divider()
        if bullets:
            for bullet in bullets:
                st.markdown(f"- {bullet}")
        st.divider()

    st.markdown("### Registry categories (planned modules)")
    planned = [module for module in MODULES if not is_executable(module)]
    shown_ids = {
        module_id
        for section in ROADMAP_SECTIONS
        for module_id in (section.get("module_ids") or ())
    }
    remaining = [module for module in planned if module.module_id not in shown_ids]
    if not remaining:
        st.caption("All planned registry modules are listed above.")
        return
    for category in CATEGORIES:
        category_key = str(category["key"])
        category_label = str(category["label"])
        category_modules = [module for module in remaining if module.category == category_key]
        if not category_modules:
            continue
        with st.expander(category_label, expanded=False):
            for module in category_modules:
                _render_module_card(module.module_id)
                st.divider()

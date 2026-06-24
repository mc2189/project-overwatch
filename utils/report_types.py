"""Report type definitions for Report Builder v2."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

from utils.operating_context import CLIENT_ENGAGEMENT, PASSIVE_RESEARCH, PERSONAL_LAB
from utils.report_sections import (
    DEFAULT_CONCISE_SECTIONS,
    SECTION_APPENDIX,
    SECTION_ASSETS,
    SECTION_COVER,
    SECTION_EVIDENCE,
    SECTION_EXECUTIVE,
    SECTION_FILE_METADATA,
    SECTION_FINDINGS_TABLE,
    SECTION_KEY_FINDINGS,
    SECTION_NETWORK_SERVICES,
    SECTION_OPEN_ACTIONS,
    SECTION_OPERATING_CONTEXT,
    SECTION_PACKET_CAPTURE,
    SECTION_RECOMMENDED_ACTIONS,
    SECTION_REMOTE_ACCESS,
    SECTION_SCOPE,
    SECTION_SSH_CONFIGURATION,
    SECTION_TECHNICAL_OBSERVATIONS,
    SECTION_WEB_POSTURE,
)

FindingSelectionMode = Literal[
    "active",
    "all",
    "exclude_info",
    "selected",
    "by_module",
    "by_severity",
]


@dataclass(frozen=True)
class ReportType:
    type_id: str
    label: str
    description: str
    default_sections: frozenset[str]
    default_operating_context: str
    default_template: Literal["full", "executive"] = "executive"
    default_finding_mode: FindingSelectionMode = "active"
    include_engagement_by_default: bool = False
    include_raw_appendix_by_default: bool = False
    highlight_modules: frozenset[str] = field(default_factory=frozenset)


REPORT_TYPES: dict[str, ReportType] = {
    "personal_lab_summary": ReportType(
        type_id="personal_lab_summary",
        label="Personal Lab Summary",
        description="Learning-oriented summary for self-owned Personal Lab testing.",
        default_sections=frozenset(
            DEFAULT_CONCISE_SECTIONS
            | {SECTION_NETWORK_SERVICES, SECTION_PACKET_CAPTURE, SECTION_OPEN_ACTIONS}
        ),
        default_operating_context=PERSONAL_LAB,
        default_template="executive",
    ),
    "external_exposure_review": ReportType(
        type_id="external_exposure_review",
        label="External Exposure Review",
        description="Exposure-focused pack for remote access, services, and perimeter observations.",
        default_sections=frozenset(
            DEFAULT_CONCISE_SECTIONS
            | {SECTION_NETWORK_SERVICES, SECTION_REMOTE_ACCESS, SECTION_SSH_CONFIGURATION, SECTION_WEB_POSTURE}
        ),
        default_operating_context=CLIENT_ENGAGEMENT,
        include_engagement_by_default=True,
    ),
    "website_domain_posture": ReportType(
        type_id="website_domain_posture",
        label="Website / Domain Posture Review",
        description="Web, TLS, email, and domain posture observations with cautious wording.",
        default_sections=frozenset(
            DEFAULT_CONCISE_SECTIONS | {SECTION_WEB_POSTURE, SECTION_FINDINGS_TABLE}
        ),
        default_operating_context=PASSIVE_RESEARCH,
        highlight_modules=frozenset(
            {
                "infra_domain_intel",
                "infra_website_metadata",
                "infra_email_security",
                "infra_tls_review",
                "infra_http_security",
                "infra_web_stack_identifier",
                "infra_web_path_review",
            }
        ),
    ),
    "local_network_review": ReportType(
        type_id="local_network_review",
        label="Local Network Review",
        description="Local IP, Nmap, and LAN-oriented service observations.",
        default_sections=frozenset(
            DEFAULT_CONCISE_SECTIONS
            | {SECTION_NETWORK_SERVICES, SECTION_REMOTE_ACCESS, SECTION_SSH_CONFIGURATION, SECTION_ASSETS}
        ),
        default_operating_context=PERSONAL_LAB,
        highlight_modules=frozenset({"infra_nmap", "infra_remote_access_review", "infra_ssh_review"}),
    ),
    "packet_capture_lan_recon": ReportType(
        type_id="packet_capture_lan_recon",
        label="Packet Capture / LAN Recon Review",
        description="Supplied-capture and live-capture summaries with LAN recon context.",
        default_sections=frozenset(
            DEFAULT_CONCISE_SECTIONS | {SECTION_PACKET_CAPTURE, SECTION_NETWORK_SERVICES}
        ),
        default_operating_context=PERSONAL_LAB,
        highlight_modules=frozenset({"net_pcap_review", "net_live_capture"}),
    ),
    "evidence_metadata_review": ReportType(
        type_id="evidence_metadata_review",
        label="Evidence Metadata Review",
        description="File metadata and evidence locker summary for uploaded artefacts.",
        default_sections=frozenset(
            DEFAULT_CONCISE_SECTIONS | {SECTION_FILE_METADATA, SECTION_EVIDENCE}
        ),
        default_operating_context=PASSIVE_RESEARCH,
        highlight_modules=frozenset({"evidence_file_metadata"}),
    ),
    "full_technical_appendix": ReportType(
        type_id="full_technical_appendix",
        label="Full Technical Appendix",
        description="Full technical detail with optional raw appendix.",
        default_sections=frozenset(
            {
                SECTION_COVER,
                SECTION_OPERATING_CONTEXT,
                SECTION_SCOPE,
                SECTION_EXECUTIVE,
                SECTION_KEY_FINDINGS,
                SECTION_RECOMMENDED_ACTIONS,
                SECTION_TECHNICAL_OBSERVATIONS,
                SECTION_ASSETS,
                SECTION_NETWORK_SERVICES,
                SECTION_WEB_POSTURE,
                SECTION_REMOTE_ACCESS,
                SECTION_SSH_CONFIGURATION,
                SECTION_PACKET_CAPTURE,
                SECTION_FILE_METADATA,
                SECTION_EVIDENCE,
                SECTION_FINDINGS_TABLE,
                SECTION_OPEN_ACTIONS,
                SECTION_APPENDIX,
            }
        ),
        default_operating_context=CLIENT_ENGAGEMENT,
        default_template="full",
        include_raw_appendix_by_default=True,
    ),
    "client_executive_pack": ReportType(
        type_id="client_executive_pack",
        label="Client Executive Pack",
        description="Concise client-facing pack with executive summary, key findings, and recommendations.",
        default_sections=frozenset(DEFAULT_CONCISE_SECTIONS | {SECTION_KEY_FINDINGS, SECTION_OPEN_ACTIONS}),
        default_operating_context=CLIENT_ENGAGEMENT,
        default_template="executive",
        include_engagement_by_default=True,
    ),
}


def list_report_types() -> list[ReportType]:
    return list(REPORT_TYPES.values())


def get_report_type(type_id: str | None) -> ReportType | None:
    if not type_id:
        return None
    return REPORT_TYPES.get(type_id)


def report_type_select_options() -> list[str]:
    return list(REPORT_TYPES.keys())

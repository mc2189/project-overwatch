"""Report section identifiers for Report Builder v2."""

from __future__ import annotations

from typing import Final

SECTION_COVER: Final = "cover_case_summary"
SECTION_OPERATING_CONTEXT: Final = "operating_context"
SECTION_SCOPE: Final = "scope_limitations"
SECTION_EXECUTIVE: Final = "executive_summary"
SECTION_KEY_FINDINGS: Final = "key_findings"
SECTION_RECOMMENDED_ACTIONS: Final = "recommended_actions"
SECTION_TECHNICAL_OBSERVATIONS: Final = "technical_observations"
SECTION_ASSETS: Final = "assets_entities"
SECTION_NETWORK_SERVICES: Final = "network_service_summary"
SECTION_WEB_POSTURE: Final = "web_posture_summary"
SECTION_REMOTE_ACCESS: Final = "remote_access_summary"
SECTION_SSH_CONFIGURATION: Final = "ssh_configuration_summary"
SECTION_PLAYBOOK: Final = "playbook_summary"
SECTION_PACKET_CAPTURE: Final = "packet_capture_summary"
SECTION_FILE_METADATA: Final = "file_metadata_summary"
SECTION_EVIDENCE: Final = "evidence_summary"
SECTION_FINDINGS_TABLE: Final = "findings_table"
SECTION_OPEN_ACTIONS: Final = "open_actions"
SECTION_APPENDIX: Final = "appendix_raw"

ALL_SECTIONS: tuple[str, ...] = (
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
    SECTION_PLAYBOOK,
    SECTION_PACKET_CAPTURE,
    SECTION_FILE_METADATA,
    SECTION_EVIDENCE,
    SECTION_FINDINGS_TABLE,
    SECTION_OPEN_ACTIONS,
    SECTION_APPENDIX,
)

DEFAULT_CONCISE_SECTIONS: frozenset[str] = frozenset(
    {
        SECTION_COVER,
        SECTION_OPERATING_CONTEXT,
        SECTION_SCOPE,
        SECTION_EXECUTIVE,
        SECTION_KEY_FINDINGS,
        SECTION_RECOMMENDED_ACTIONS,
        SECTION_EVIDENCE,
    }
)

SECTION_LABELS: dict[str, str] = {
    SECTION_COVER: "Cover / case summary",
    SECTION_OPERATING_CONTEXT: "Operating context",
    SECTION_SCOPE: "Scope and limitations",
    SECTION_EXECUTIVE: "Executive summary",
    SECTION_KEY_FINDINGS: "Key findings",
    SECTION_RECOMMENDED_ACTIONS: "Recommended actions",
    SECTION_TECHNICAL_OBSERVATIONS: "Technical observations",
    SECTION_ASSETS: "Assets / entities reviewed",
    SECTION_NETWORK_SERVICES: "Network service summary",
    SECTION_WEB_POSTURE: "Web posture summary",
    SECTION_REMOTE_ACCESS: "Remote access summary",
    SECTION_SSH_CONFIGURATION: "SSH configuration summary",
    SECTION_PLAYBOOK: "Assessment playbook summary",
    SECTION_PACKET_CAPTURE: "Packet capture summary",
    SECTION_FILE_METADATA: "File metadata summary",
    SECTION_EVIDENCE: "Evidence summary",
    SECTION_FINDINGS_TABLE: "Findings table",
    SECTION_OPEN_ACTIONS: "Open actions",
    SECTION_APPENDIX: "Appendix / raw technical detail",
}


def section_label(section_id: str) -> str:
    return SECTION_LABELS.get(section_id, section_id.replace("_", " ").title())


def section_enabled(selected: frozenset[str] | None, section_id: str, *, legacy_template: str = "full") -> bool:
    """Return whether a section should be rendered."""
    if selected is None:
        if section_id == SECTION_APPENDIX:
            return legacy_template == "full"
        if section_id in {SECTION_ASSETS, SECTION_TECHNICAL_OBSERVATIONS}:
            return legacy_template == "full"
        return True
    return section_id in selected

"""Built-in report export presets for Project Overwatch."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

from utils.report_builder import ReportOptions
from utils.report_redaction import parse_custom_terms
from utils.report_settings import ReportBranding

ReportTemplate = Literal["full", "executive"]


@dataclass(frozen=True)
class ReportPreset:
    preset_id: str
    label: str
    description: str
    template: ReportTemplate
    include_closed_findings: bool
    include_raw_appendix: bool
    include_graph_appendix: bool
    redact_ips: bool
    redact_emails: bool
    redact_domains: bool
    suggested_run_mode_id: str | None = None


REPORT_PRESETS: dict[str, ReportPreset] = {
    "executive_brief": ReportPreset(
        preset_id="executive_brief",
        label="Executive brief",
        description="Short executive summary with active findings only.",
        template="executive",
        include_closed_findings=False,
        include_raw_appendix=False,
        include_graph_appendix=False,
        redact_ips=False,
        redact_emails=False,
        redact_domains=False,
        suggested_run_mode_id="quick_check",
    ),
    "quick_check_overview": ReportPreset(
        preset_id="quick_check_overview",
        label="Quick Check overview",
        description="Executive summary suited to Quick Check investigations.",
        template="executive",
        include_closed_findings=False,
        include_raw_appendix=False,
        include_graph_appendix=False,
        redact_ips=False,
        redact_emails=False,
        redact_domains=False,
        suggested_run_mode_id="quick_check",
    ),
    "domain_footprint_summary": ReportPreset(
        preset_id="domain_footprint_summary",
        label="Domain footprint summary",
        description="Executive summary focused on passive domain and certificate findings.",
        template="executive",
        include_closed_findings=False,
        include_raw_appendix=False,
        include_graph_appendix=True,
        redact_ips=False,
        redact_emails=False,
        redact_domains=False,
        suggested_run_mode_id="website_footprint",
    ),
    "local_ip_technical": ReportPreset(
        preset_id="local_ip_technical",
        label="Local IP technical",
        description="Full technical report for IPv4 service-check investigations.",
        template="full",
        include_closed_findings=False,
        include_raw_appendix=False,
        include_graph_appendix=True,
        redact_ips=False,
        redact_emails=False,
        redact_domains=False,
        suggested_run_mode_id="local_ip_check",
    ),
    "full_technical": ReportPreset(
        preset_id="full_technical",
        label="Full technical",
        description="Complete technical report including observations and relationships.",
        template="full",
        include_closed_findings=False,
        include_raw_appendix=False,
        include_graph_appendix=True,
        redact_ips=False,
        redact_emails=False,
        redact_domains=False,
    ),
    "shareable_redacted": ReportPreset(
        preset_id="shareable_redacted",
        label="Shareable (redacted)",
        description="Executive summary with IP, email, and domain redaction for external sharing.",
        template="executive",
        include_closed_findings=False,
        include_raw_appendix=False,
        include_graph_appendix=False,
        redact_ips=True,
        redact_emails=True,
        redact_domains=True,
    ),
    "archive_complete": ReportPreset(
        preset_id="archive_complete",
        label="Archive complete",
        description="Full report including closed findings and raw output appendix.",
        template="full",
        include_closed_findings=True,
        include_raw_appendix=True,
        include_graph_appendix=True,
        redact_ips=False,
        redact_emails=False,
        redact_domains=False,
    ),
}


def presets_for_run_mode(run_mode_id: str | None) -> list[str]:
    """Return preset IDs suggested for a run mode."""
    if not run_mode_id:
        return []
    return [
        preset_id
        for preset_id, preset in REPORT_PRESETS.items()
        if preset.suggested_run_mode_id == run_mode_id
    ]


def suggest_preset_for_run_mode(run_mode_id: str | None) -> str | None:
    """Return the primary preset ID for a run mode, if any."""
    matches = presets_for_run_mode(run_mode_id)
    return matches[0] if matches else None


def preset_select_options(run_mode_id: str | None = None) -> list[str]:
    """Order preset keys with run-mode matches first."""
    suggested = presets_for_run_mode(run_mode_id)
    general = [preset_id for preset_id in REPORT_PRESETS if preset_id not in suggested]
    return ["custom", *suggested, *general]


def apply_preset_to_session(preset_id: str) -> None:
    """Write preset widget defaults into Streamlit session state."""
    import streamlit as st

    preset = REPORT_PRESETS[preset_id]
    st.session_state["report_template"] = preset.template
    st.session_state["include_closed_findings"] = preset.include_closed_findings
    st.session_state["include_raw_appendix"] = preset.include_raw_appendix
    st.session_state["include_graph_appendix"] = preset.include_graph_appendix
    st.session_state["redact_ips"] = preset.redact_ips
    st.session_state["redact_emails"] = preset.redact_emails
    st.session_state["redact_domains"] = preset.redact_domains
    st.session_state["report_preset_choice"] = preset_id


def build_report_options_from_state(
    branding: ReportBranding,
    *,
    custom_terms_text: str = "",
    custom_regex_text: str = "",
) -> ReportOptions:
    """Build ReportOptions from report page session state keys."""
    import streamlit as st

    redactions = {
        option
        for option, key in (
            ("ipv4", "redact_ips"),
            ("email", "redact_emails"),
            ("domain", "redact_domains"),
        )
        if st.session_state.get(key, False)
    }
    return ReportOptions(
        include_closed_findings=st.session_state.get("include_closed_findings", False),
        include_raw_appendix=st.session_state.get("include_raw_appendix", False),
        include_graph_appendix=st.session_state.get("include_graph_appendix", False),
        include_engagement_context=st.session_state.get("include_engagement_context", False),
        template=st.session_state.get("report_template", "full"),
        redactions=redactions,
        branding=branding,
        custom_redaction_terms=parse_custom_terms(custom_terms_text),
        custom_redaction_regex=custom_regex_text,
    )

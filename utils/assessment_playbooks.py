"""Assessment playbook definitions for guided autopilot follow-ups."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal

from utils.operating_context import CLIENT_ENGAGEMENT, PASSIVE_RESEARCH, PERSONAL_LAB

SafetyLevel = Literal["passive_only", "safe_active", "mixed"]
AssessmentMode = Literal[
    "manual",
    "assisted",
    "passive_autopilot",
    "personal_lab_autopilot",
]

MODE_MANUAL = "manual"
MODE_ASSISTED = "assisted"
MODE_PASSIVE_AUTOPILOT = "passive_autopilot"
MODE_PERSONAL_LAB_AUTOPILOT = "personal_lab_autopilot"

DEFAULT_MAX_STEPS = 10
DEFAULT_MAX_ACTIVE = 3
DEFAULT_MAX_PASSIVE = 8
DEFAULT_MAX_FAILURES = 3


@dataclass(frozen=True)
class AssessmentPlaybook:
    playbook_id: str
    display_name: str
    description: str
    suitable_target_types: tuple[str, ...]
    default_operating_context: str
    starting_modules: tuple[str, ...]
    follow_up_rule_ids: tuple[str, ...]
    stop_conditions: tuple[str, ...] = (
        "max_steps",
        "max_active",
        "max_passive",
        "max_failures",
        "duplicate_target_module",
        "emergency_stop",
        "user_stop",
        "blocked_only",
    )
    safety_level: SafetyLevel = "mixed"
    max_steps: int = DEFAULT_MAX_STEPS
    max_active_checks: int = DEFAULT_MAX_ACTIVE
    max_passive_checks: int = DEFAULT_MAX_PASSIVE
    max_failures: int = DEFAULT_MAX_FAILURES


PLAYBOOKS: dict[str, AssessmentPlaybook] = {
    "quick_safety_check": AssessmentPlaybook(
        playbook_id="quick_safety_check",
        display_name="Quick Safety Check",
        description="Conservative passive and safe-active triage for a single target.",
        suitable_target_types=("domain", "url", "ipv4"),
        default_operating_context=PASSIVE_RESEARCH,
        starting_modules=("infra_domain_intel", "infra_website_metadata", "infra_email_security"),
        follow_up_rule_ids=("nmap_followups", "http_followups", "reputation_followups"),
        safety_level="mixed",
        max_active_checks=2,
    ),
    "website_domain_posture": AssessmentPlaybook(
        playbook_id="website_domain_posture",
        display_name="Website / Domain Posture",
        description="Web, TLS, email, and domain posture with cautious follow-ups.",
        suitable_target_types=("domain", "url"),
        default_operating_context=PASSIVE_RESEARCH,
        starting_modules=(
            "infra_domain_intel",
            "infra_website_metadata",
            "infra_email_security",
            "infra_http_security",
            "infra_tls_review",
        ),
        follow_up_rule_ids=("http_followups", "web_stack_followups", "web_path_followups"),
        safety_level="mixed",
    ),
    "external_exposure_review": AssessmentPlaybook(
        playbook_id="external_exposure_review",
        display_name="External Exposure Review",
        description="Service discovery and exposure follow-ups for public targets.",
        suitable_target_types=("ipv4", "domain"),
        default_operating_context=CLIENT_ENGAGEMENT,
        starting_modules=("infra_nmap", "intel_abuseipdb", "intel_shodan"),
        follow_up_rule_ids=("nmap_followups", "remote_access_followups", "reputation_followups"),
        safety_level="mixed",
    ),
    "local_network_triage": AssessmentPlaybook(
        playbook_id="local_network_triage",
        display_name="Local Network Triage",
        description="Conservative service discovery and LAN-oriented follow-ups.",
        suitable_target_types=("ipv4",),
        default_operating_context=PERSONAL_LAB,
        starting_modules=("infra_nmap",),
        follow_up_rule_ids=("nmap_followups", "remote_access_followups", "pcap_followups"),
        safety_level="safe_active",
        max_active_checks=4,
    ),
    "packet_capture_lan_recon": AssessmentPlaybook(
        playbook_id="packet_capture_lan_recon",
        display_name="Packet Capture LAN Recon",
        description="Capture review with ranked LAN device follow-ups.",
        suitable_target_types=("ipv4", "domain", "url"),
        default_operating_context=PERSONAL_LAB,
        starting_modules=("net_pcap_review", "net_live_capture"),
        follow_up_rule_ids=("pcap_followups", "nmap_followups", "reputation_followups"),
        safety_level="mixed",
    ),
    "remote_access_review": AssessmentPlaybook(
        playbook_id="remote_access_review",
        display_name="Remote Access Review",
        description="Remote administration exposure with SSH and access follow-ups.",
        suitable_target_types=("ipv4", "domain"),
        default_operating_context=PERSONAL_LAB,
        starting_modules=("infra_nmap", "infra_remote_access_review"),
        follow_up_rule_ids=("nmap_followups", "remote_access_followups"),
        safety_level="safe_active",
    ),
    "evidence_file_review": AssessmentPlaybook(
        playbook_id="evidence_file_review",
        display_name="Evidence File Review",
        description="Uploaded document and image metadata with privacy follow-ups.",
        suitable_target_types=("domain", "url", "ipv4"),
        default_operating_context=PASSIVE_RESEARCH,
        starting_modules=("evidence_file_metadata", "net_pcap_review"),
        follow_up_rule_ids=("file_metadata_followups",),
        safety_level="passive_only",
        max_active_checks=0,
    ),
    "full_personal_lab_assessment": AssessmentPlaybook(
        playbook_id="full_personal_lab_assessment",
        display_name="Full Personal Lab Assessment",
        description="Broad lab assessment with capped safe-active follow-ups.",
        suitable_target_types=("ipv4", "domain", "url"),
        default_operating_context=PERSONAL_LAB,
        starting_modules=("infra_nmap", "infra_http_security", "infra_tls_review"),
        follow_up_rule_ids=(
            "nmap_followups",
            "http_followups",
            "web_stack_followups",
            "web_path_followups",
            "remote_access_followups",
            "pcap_followups",
            "reputation_followups",
        ),
        safety_level="mixed",
        max_steps=12,
        max_active_checks=5,
    ),
    "client_executive_review": AssessmentPlaybook(
        playbook_id="client_executive_review",
        display_name="Client Executive Review",
        description="Client engagement posture with scope-aware follow-ups and reporting.",
        suitable_target_types=("domain", "url", "ipv4"),
        default_operating_context=CLIENT_ENGAGEMENT,
        starting_modules=(
            "infra_domain_intel",
            "infra_email_security",
            "infra_nmap",
            "infra_http_security",
            "infra_tls_review",
        ),
        follow_up_rule_ids=("nmap_followups", "http_followups", "remote_access_followups", "reputation_followups"),
        safety_level="mixed",
        max_active_checks=3,
    ),
}


def list_playbooks() -> list[AssessmentPlaybook]:
    return list(PLAYBOOKS.values())


def get_playbook(playbook_id: str | None) -> AssessmentPlaybook | None:
    if not playbook_id:
        return None
    return PLAYBOOKS.get(playbook_id)


def playbook_for_goal(goal_id: str | None) -> AssessmentPlaybook | None:
    """Map assessment goals to a default playbook where sensible."""
    from utils.assessment_goals import (
        GOAL_EVIDENCE_REVIEW,
        GOAL_EXTERNAL_EXPOSURE,
        GOAL_FULL_CLIENT,
        GOAL_LOCAL_NETWORK,
        GOAL_LIVE_CAPTURE,
        GOAL_WEBSITE_POSTURE,
    )

    mapping = {
        GOAL_WEBSITE_POSTURE: "website_domain_posture",
        GOAL_EXTERNAL_EXPOSURE: "external_exposure_review",
        GOAL_LOCAL_NETWORK: "local_network_triage",
        GOAL_EVIDENCE_REVIEW: "evidence_file_review",
        GOAL_LIVE_CAPTURE: "packet_capture_lan_recon",
        GOAL_FULL_CLIENT: "client_executive_review",
    }
    return get_playbook(mapping.get(goal_id or ""))


def playbook_suitable_for_target(playbook: AssessmentPlaybook, target_type: str) -> bool:
    return target_type in playbook.suitable_target_types


def default_assessment_mode() -> str:
    from utils.settings_manager import default_assessment_mode as _default_mode

    return _default_mode()


def assessment_mode_labels() -> dict[str, str]:
    return {
        MODE_MANUAL: "Manual — suggestions only",
        MODE_ASSISTED: "Assisted — build queue, you confirm runs",
        MODE_PASSIVE_AUTOPILOT: "Passive Autopilot — passive follow-ups may run automatically",
        MODE_PERSONAL_LAB_AUTOPILOT: "Personal Lab Autopilot — safe active follow-ups after confirmation",
    }


def mode_allows_auto_passive(mode: str) -> bool:
    return mode == MODE_PASSIVE_AUTOPILOT


def mode_allows_auto_active(mode: str, *, personal_lab_confirmed: bool, autopilot_confirmed: bool) -> bool:
    if mode != MODE_PERSONAL_LAB_AUTOPILOT:
        return False
    return personal_lab_confirmed and autopilot_confirmed


def playbook_limits(playbook: AssessmentPlaybook | None, *, settings: dict[str, Any] | None = None) -> dict[str, int]:
    settings = settings or {}
    base = playbook or PLAYBOOKS["quick_safety_check"]
    return {
        "max_steps": int(settings.get("max_playbook_steps") or base.max_steps),
        "max_active": int(settings.get("max_active_checks") or base.max_active_checks),
        "max_passive": int(settings.get("max_passive_checks") or base.max_passive_checks),
        "max_failures": int(settings.get("max_failures") or base.max_failures),
    }

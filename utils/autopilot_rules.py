"""Follow-up rule engine for assessment playbooks and autopilot queue."""

from __future__ import annotations

from typing import Any

from modules.module_registry import get_module
from utils.assessment_playbooks import AssessmentPlaybook
from utils.batch_queue import ACTIVE_BATCH_MODULE_IDS, PASSIVE_BATCH_MODULE_IDS
from utils.next_actions import make_action
from utils.nmap_followup_actions import suggest_nmap_followup_actions
from utils.web_port_planner import is_private_ipv4_target

AUTOPILOT_ACTION_TYPES = frozenset(
    {
        "run_module",
        "add_to_queue",
        "wait_for_confirmation",
        "open_finding",
        "open_entity",
        "create_report",
        "stop_playbook",
        "note_only",
        "no_action",
        "try_common_web_ports",
        "navigate_page",
    }
)


def _module_is_passive(module_id: str | None) -> bool:
    if not module_id:
        return False
    module = get_module(module_id)
    if module is None:
        return False
    return module.mode == "passive" or module_id in PASSIVE_BATCH_MODULE_IDS


def _module_is_active(module_id: str | None) -> bool:
    if not module_id:
        return False
    module = get_module(module_id)
    if module is None:
        return False
    return module.mode == "active" or module_id in ACTIVE_BATCH_MODULE_IDS


def make_autopilot_action(
    *,
    title: str,
    reason: str,
    action_type: str = "add_to_queue",
    priority: str = "medium",
    target: str | None = None,
    module_id: str | None = None,
    finding_id: int | None = None,
    playbook_id: str | None = None,
    parent_action_id: str | None = None,
    source_module_id: str | None = None,
    source_result_id: str | None = None,
    why_detail: str | None = None,
    requires_confirmation: bool | None = None,
    blocked_reason: str | None = None,
    button_label: str | None = None,
) -> dict[str, Any]:
    """Build an autopilot action using the shared next-actions schema plus metadata."""
    if action_type not in AUTOPILOT_ACTION_TYPES:
        action_type = "note_only" if action_type == "note_only" else "no_action"

    is_passive = _module_is_passive(module_id)
    is_active = _module_is_active(module_id)
    if requires_confirmation is None:
        requires_confirmation = is_active or action_type == "run_module"

    if action_type == "run_module" and is_passive:
        action_type = "add_to_queue"
        requires_confirmation = False

    base = make_action(
        title=title,
        reason=reason,
        action_type=action_type if action_type in {
            "run_module",
            "add_to_queue",
            "open_finding",
            "open_entity",
            "create_report",
            "no_action",
            "try_common_web_ports",
            "open_graph",
            "add_note",
        } else "no_action",
        priority=priority,
        target=target,
        module_id=module_id,
        finding_id=finding_id,
        blocked_reason=blocked_reason,
        button_label=button_label,
        why_detail=why_detail or reason,
    )
    base.update(
        {
            "autopilot": True,
            "playbook_id": playbook_id,
            "parent_action_id": parent_action_id,
            "source_module_id": source_module_id,
            "source_result_id": source_result_id,
            "is_passive": is_passive,
            "is_active": is_active,
            "requires_confirmation": requires_confirmation,
            "autopilot_status": "proposed",
            "autopilot_action_type": action_type,
        }
    )
    if action_type in {"wait_for_confirmation", "stop_playbook", "note_only"}:
        base["action_type"] = "no_action"
        base["autopilot_action_type"] = action_type
        base["button_label"] = button_label or "Info"
    if action_type == "navigate_page":
        base["action_type"] = "no_action"
        base["autopilot_action_type"] = "navigate_page"
        base["navigate_page"] = "Packet Capture"
        base["button_label"] = button_label or "Open page"
    return base


def _explain(source: str, detail: str) -> str:
    return f"{detail} (triggered by {source})."


def _rules_from_nmap(
    result: dict[str, Any],
    *,
    target: str,
    playbook_id: str | None,
) -> list[dict[str, Any]]:
    actions: list[dict[str, Any]] = []
    parsed = result.get("parsed_data") or {}
    ports = parsed.get("parsed_ports") or []
    source = "Network Service Check"

    for action in suggest_nmap_followup_actions(result, target=target):
        module_id = action.get("module_id")
        port_hint = ""
        for row in ports:
            service = str(row.get("service") or "").lower()
            try:
                port_num = int(row.get("port"))
            except (TypeError, ValueError):
                continue
            if module_id == "infra_ssh_review" and (service == "ssh" or port_num == 22):
                port_hint = f" on port {port_num}"
                break
            if module_id in {"infra_http_security", "infra_tls_review"} and port_num in {80, 443, 8080, 8443}:
                port_hint = f" (port {port_num} responded)"
                break

        detail = action.get("reason") or "Follow-up suggested from open port observations."
        if module_id == "infra_ssh_review":
            detail = _explain(
                source,
                f"Nmap found SSH{port_hint or ''}, so SSH Configuration Review is suggested "
                "to record the visible SSH banner and exposure context",
            )
        elif module_id == "infra_remote_access_review":
            detail = _explain(
                source,
                "Remote administration or file-sharing services were observed — "
                "Remote Access Exposure Review is suggested to classify exposure",
            )
        elif module_id == "infra_http_security":
            detail = _explain(source, "Web-like ports responded — HTTP Security Header Review is suggested")
        elif module_id == "infra_tls_review":
            detail = _explain(source, "TLS-like ports responded — TLS Configuration Review is suggested")

        actions.append(
            make_autopilot_action(
                title=action.get("title") or "Follow-up check",
                reason=action.get("reason") or detail,
                action_type="add_to_queue" if _module_is_passive(module_id) else "run_module",
                priority=action.get("priority") or "medium",
                target=target,
                module_id=module_id,
                playbook_id=playbook_id,
                source_module_id="infra_nmap",
                why_detail=detail,
            )
        )

    if not ports:
        actions.append(
            make_autopilot_action(
                title="Verify host reachability",
                reason="No open ports were parsed — confirm the host is online or try Packet Capture on LAN targets.",
                action_type="note_only",
                priority="medium",
                target=target,
                playbook_id=playbook_id,
                source_module_id="infra_nmap",
                why_detail=_explain(source, "No open ports parsed — host may be offline, filtered, or profile too narrow"),
            )
        )
        if is_private_ipv4_target(target):
            actions.append(
                make_autopilot_action(
                    title="Capture traffic to this host",
                    reason="Local target with no parsed ports — bounded PCAP may add DHCP/ARP context.",
                    action_type="navigate_page",
                    priority="low",
                    target=target,
                    module_id="net_live_capture",
                    playbook_id=playbook_id,
                    source_module_id="infra_nmap",
                    requires_confirmation=True,
                    why_detail=_explain(source, "LAN target with no open ports — packet capture may help triage"),
                )
            )
    return actions


def _rules_from_http_security(
    result: dict[str, Any],
    *,
    target: str,
    playbook_id: str | None,
) -> list[dict[str, Any]]:
    if result.get("module_id") != "infra_http_security":
        return []
    parsed = result.get("parsed_data") or {}
    response = parsed.get("response") or {}
    actions: list[dict[str, Any]] = []
    source = "HTTP Security Header Review"

    if response.get("success"):
        actions.append(
            make_autopilot_action(
                title="Web Stack Identifier",
                reason="HTTP response received — identify visible web stack indicators.",
                action_type="run_module",
                priority="medium",
                target=target,
                module_id="infra_web_stack_identifier",
                playbook_id=playbook_id,
                source_module_id="infra_http_security",
                why_detail=_explain(source, "HTTP response received — web stack identification may add context"),
            )
        )
        missing = parsed.get("missing_headers") or []
        if missing:
            actions.append(
                make_autopilot_action(
                    title="Add HTTP header findings to report",
                    reason=f"Missing security headers observed ({', '.join(str(item) for item in missing[:4])}).",
                    action_type="create_report",
                    priority="medium",
                    target=target,
                    playbook_id=playbook_id,
                    source_module_id="infra_http_security",
                    requires_confirmation=True,
                    why_detail=_explain(source, "Missing security headers should be documented cautiously"),
                )
            )
    else:
        actions.append(
            make_autopilot_action(
                title="Run Network Service Check",
                reason="HTTP review did not receive a response — discover open ports first.",
                action_type="run_module",
                priority="high",
                target=target,
                module_id="infra_nmap",
                playbook_id=playbook_id,
                source_module_id="infra_http_security",
                why_detail=_explain(source, "No HTTP response — service discovery is suggested"),
            )
        )
        if is_private_ipv4_target(target):
            actions.append(
                make_autopilot_action(
                    title="Try common web ports",
                    reason="Probe common web ports sequentially on this local target.",
                    action_type="try_common_web_ports",
                    priority="medium",
                    target=target,
                    playbook_id=playbook_id,
                    source_module_id="infra_http_security",
                    requires_confirmation=True,
                    why_detail=_explain(source, "Local target may use non-standard web ports"),
                )
            )
    return actions


def _rules_from_web_stack(
    result: dict[str, Any],
    *,
    target: str,
    playbook_id: str | None,
) -> list[dict[str, Any]]:
    if result.get("module_id") != "infra_web_stack_identifier" or not result.get("success"):
        return []
    parsed = result.get("parsed_data") or {}
    indicators = parsed.get("indicators") or []
    headers = parsed.get("headers") or {}
    actions: list[dict[str, Any]] = []
    source = "Web Stack Identifier"

    from utils.web_stack_indicators import CATEGORY_CMS

    if any(row.get("category") == CATEGORY_CMS for row in indicators):
        actions.append(
            make_autopilot_action(
                title="Controlled Web Path Review",
                reason="CMS indicators observed — review common public paths cautiously.",
                action_type="run_module",
                priority="medium",
                target=target,
                module_id="infra_web_path_review",
                playbook_id=playbook_id,
                source_module_id="infra_web_stack_identifier",
                why_detail=_explain(source, "CMS indicators suggest a controlled web path review"),
            )
        )
    if headers.get("server") or headers.get("x-powered-by"):
        actions.append(
            make_autopilot_action(
                title="Review server disclosure",
                reason="Server or platform headers disclose software — note for report if unexpected.",
                action_type="note_only",
                priority="low",
                target=target,
                playbook_id=playbook_id,
                source_module_id="infra_web_stack_identifier",
                why_detail=_explain(source, "Server disclosure headers were observed"),
            )
        )
    if indicators:
        categories = sorted({str(row.get("category_label") or row.get("category")) for row in indicators})
        actions.append(
            make_autopilot_action(
                title="Review stack indicators",
                reason=f"Observed categories: {', '.join(categories[:5])}.",
                action_type="note_only",
                priority="low",
                target=target,
                playbook_id=playbook_id,
                source_module_id="infra_web_stack_identifier",
                why_detail=_explain(source, "Visible stack indicators should be validated before external reporting"),
            )
        )
    return actions


def _rules_from_remote_access(
    result: dict[str, Any],
    *,
    target: str,
    playbook_id: str | None,
) -> list[dict[str, Any]]:
    if result.get("module_id") != "infra_remote_access_review" or not result.get("success"):
        return []
    parsed = result.get("parsed_data") or {}
    services = parsed.get("remote_services") or []
    actions: list[dict[str, Any]] = []
    source = "Remote Access Exposure Review"

    for service in services:
        label = str(service.get("service_label") or "").upper()
        port = service.get("port")
        if label == "SSH" or port == 22:
            actions.append(
                make_autopilot_action(
                    title=f"SSH Configuration Review (port {port or 22})",
                    reason="SSH was classified in remote access review — review visible SSH banner.",
                    action_type="run_module",
                    priority="medium",
                    target=target,
                    module_id="infra_ssh_review",
                    playbook_id=playbook_id,
                    source_module_id="infra_remote_access_review",
                    why_detail=_explain(
                        source,
                        f"SSH service observed on {target}:{port or 22} — banner review is suggested",
                    ),
                )
            )
        elif label in {"SMB", "MICROSOFT-DS"}:
            actions.append(
                make_autopilot_action(
                    title="Review SMB exposure",
                    reason="SMB/file-sharing service observed — document exposure context (SMB module planned).",
                    action_type="note_only",
                    priority="medium",
                    target=target,
                    playbook_id=playbook_id,
                    source_module_id="infra_remote_access_review",
                    why_detail=_explain(source, "SMB exposure should be validated — dedicated SMB review is not enabled yet"),
                )
            )
        elif label in {"RDP", "VNC", "MS-WBT-SERVER"}:
            actions.append(
                make_autopilot_action(
                    title="Add remote desktop exposure to report",
                    reason=f"{label} remote access observed — validate scope and document exposure.",
                    action_type="create_report",
                    priority="high",
                    target=target,
                    playbook_id=playbook_id,
                    source_module_id="infra_remote_access_review",
                    requires_confirmation=True,
                    why_detail=_explain(source, f"{label} remote access should be documented for client review"),
                )
            )
    return actions


def _rules_from_pcap(
    result: dict[str, Any],
    *,
    target: str,
    playbook_id: str | None,
) -> list[dict[str, Any]]:
    module_id = result.get("module_id")
    if module_id not in {"net_pcap_review", "net_live_capture"} or not result.get("success"):
        return []
    parsed = result.get("parsed_data") or {}
    if module_id == "net_live_capture":
        parsed = (parsed.get("pcap_review") or {}).get("parsed_data") or parsed
    actions: list[dict[str, Any]] = []
    source = "Packet Capture review"

    devices = parsed.get("lan_devices") or parsed.get("devices") or []
    for device in devices[:3]:
        ip_value = device.get("ip") or device.get("ipv4")
        if not ip_value:
            continue
        if is_private_ipv4_target(str(ip_value)):
            actions.append(
                make_autopilot_action(
                    title=f"Network Service Check — {ip_value}",
                    reason="LAN device inferred from capture — conservative service discovery suggested.",
                    action_type="run_module",
                    priority="medium",
                    target=str(ip_value),
                    module_id="infra_nmap",
                    playbook_id=playbook_id,
                    source_module_id=module_id,
                    requires_confirmation=True,
                    why_detail=_explain(source, f"LAN device {ip_value} observed — Nmap may identify services"),
                )
            )

    preview = parsed.get("entities_preview") or {}
    for domain in (preview.get("domains") or [])[:4]:
        actions.append(
            make_autopilot_action(
                title=f"Domain intelligence — {domain}",
                reason="Domain observed in capture — passive domain review suggested.",
                action_type="add_to_queue",
                priority="low",
                target=str(domain),
                module_id="infra_domain_intel",
                playbook_id=playbook_id,
                source_module_id=module_id,
                why_detail=_explain(source, f"Domain {domain} appeared in capture metadata"),
            )
        )
    for ip_value in (preview.get("ips") or [])[:4]:
        ip_text = str(ip_value)
        if is_private_ipv4_target(ip_text):
            continue
        actions.append(
            make_autopilot_action(
                title=f"Passive reputation — {ip_text}",
                reason="Public IP observed in capture — passive reputation lookup suggested.",
                action_type="add_to_queue",
                priority="medium",
                target=ip_text,
                module_id="intel_abuseipdb",
                playbook_id=playbook_id,
                source_module_id=module_id,
                why_detail=_explain(source, f"Public IP {ip_text} observed in capture"),
            )
        )

    if parsed.get("cleartext_protocols"):
        actions.append(
            make_autopilot_action(
                title="Review cleartext protocol indicators",
                reason=f"Cleartext indicators: {', '.join(parsed['cleartext_protocols'][:6])}.",
                action_type="note_only",
                priority="medium",
                target=target,
                playbook_id=playbook_id,
                source_module_id=module_id,
                why_detail=_explain(source, "Cleartext protocol indicators should be reviewed before reporting"),
            )
        )
    return actions


def _rules_from_file_metadata(
    result: dict[str, Any],
    *,
    target: str,
    playbook_id: str | None,
) -> list[dict[str, Any]]:
    if result.get("module_id") != "evidence_file_metadata" or not result.get("success"):
        return []
    parsed = result.get("parsed_data") or {}
    actions: list[dict[str, Any]] = []
    source = "Document and Image Metadata Review"

    for row in parsed.get("files") or []:
        flags = row.get("privacy_flags") or {}
        filename = row.get("filename") or "file"
        if flags.get("gps_present"):
            actions.append(
                make_autopilot_action(
                    title="Review GPS metadata",
                    reason=f"GPS metadata in {filename} — review before external sharing.",
                    action_type="open_finding",
                    priority="high",
                    target=target,
                    playbook_id=playbook_id,
                    source_module_id="evidence_file_metadata",
                    requires_confirmation=True,
                    why_detail=_explain(source, f"GPS metadata in {filename} requires privacy review"),
                )
            )
        if flags.get("author_present") or flags.get("company_present"):
            actions.append(
                make_autopilot_action(
                    title="Review author/company metadata",
                    reason=f"Author or company metadata in {filename} — confirm before reporting.",
                    action_type="note_only",
                    priority="medium",
                    target=target,
                    playbook_id=playbook_id,
                    source_module_id="evidence_file_metadata",
                    why_detail=_explain(source, f"Author/company metadata in {filename} may affect privacy"),
                )
            )
    if parsed.get("notable_count"):
        actions.append(
            make_autopilot_action(
                title="Add metadata review to report",
                reason="Notable file metadata observed — include in evidence report pack.",
                action_type="create_report",
                priority="medium",
                target=target,
                playbook_id=playbook_id,
                source_module_id="evidence_file_metadata",
                requires_confirmation=True,
                why_detail=_explain(source, "Notable metadata should be summarised in a report"),
            )
        )
    return actions


def _rules_from_reputation(
    result: dict[str, Any],
    *,
    target: str,
    playbook_id: str | None,
) -> list[dict[str, Any]]:
    if not result.get("success") or is_private_ipv4_target(target):
        return []
    module_id = result.get("module_id")
    if module_id not in {"infra_nmap", "intel_abuseipdb", "intel_greynoise"}:
        return []
    actions: list[dict[str, Any]] = []
    if module_id == "infra_nmap":
        for passive_id, label in (("intel_abuseipdb", "AbuseIPDB"), ("intel_greynoise", "GreyNoise"), ("intel_shodan", "Shodan")):
            actions.append(
                make_autopilot_action(
                    title=f"{label} reputation",
                    reason=f"Public target {target} — passive {label} lookup suggested.",
                    action_type="add_to_queue",
                    priority="medium",
                    target=target,
                    module_id=passive_id,
                    playbook_id=playbook_id,
                    source_module_id="infra_nmap",
                    why_detail=f"Public IP/service map complete — {label} may add passive context.",
                )
            )
            break
    return actions


RULE_DISPATCH: dict[str, Any] = {
    "nmap_followups": _rules_from_nmap,
    "http_followups": _rules_from_http_security,
    "web_stack_followups": _rules_from_web_stack,
    "web_path_followups": lambda result, **kwargs: [],
    "remote_access_followups": _rules_from_remote_access,
    "pcap_followups": _rules_from_pcap,
    "file_metadata_followups": _rules_from_file_metadata,
    "reputation_followups": _rules_from_reputation,
}


def propose_followup_actions(
    *,
    latest_results: list[dict[str, Any]],
    target: str,
    playbook: AssessmentPlaybook | None = None,
    rule_ids: tuple[str, ...] | None = None,
    case_id: int | None = None,
    conn: Any | None = None,
) -> list[dict[str, Any]]:
    """Inspect latest results and return proposed autopilot actions."""
    playbook_id = playbook.playbook_id if playbook else None
    allowed_rules = rule_ids or (playbook.follow_up_rule_ids if playbook else tuple(RULE_DISPATCH))
    actions: list[dict[str, Any]] = []
    seen: set[tuple[str, str | None, str | None]] = set()

    for result in latest_results:
        if not result.get("success"):
            continue
        module_id = result.get("module_id")
        result_target = (result.get("parsed_data") or {}).get("target") or target
        for rule_id in allowed_rules:
            handler = RULE_DISPATCH.get(rule_id)
            if handler is None:
                continue
            if rule_id == "nmap_followups" and module_id != "infra_nmap":
                continue
            if rule_id == "http_followups" and module_id != "infra_http_security":
                continue
            if rule_id == "web_stack_followups" and module_id != "infra_web_stack_identifier":
                continue
            if rule_id == "remote_access_followups" and module_id != "infra_remote_access_review":
                continue
            if rule_id == "pcap_followups" and module_id not in {"net_pcap_review", "net_live_capture"}:
                continue
            if rule_id == "file_metadata_followups" and module_id != "evidence_file_metadata":
                continue
            if rule_id == "reputation_followups" and module_id not in {"infra_nmap", "intel_abuseipdb", "intel_greynoise"}:
                continue
            for action in handler(result, target=result_target or target, playbook_id=playbook_id):
                key = (
                    (action.get("target") or target or "").lower(),
                    action.get("module_id"),
                    action.get("autopilot_action_type") or action.get("action_type"),
                )
                if key in seen:
                    continue
                seen.add(key)
                action["source_result_id"] = module_id
                actions.append(action)

    if case_id is not None and conn is not None:
        from utils.expected_suppression import filter_autopilot_actions

        actions = filter_autopilot_actions(
            actions,
            case_id=case_id,
            target=target,
            latest_results=latest_results,
            conn=conn,
        )

    if case_id is not None and conn is not None:
        from utils.case_memory_actions import propose_case_memory_autopilot_actions

        for action in propose_case_memory_autopilot_actions(
            case_id,
            target=target,
            conn=conn,
            playbook_id=playbook_id,
        ):
            key = (
                (action.get("target") or target or "").lower(),
                action.get("module_id"),
                action.get("autopilot_action_type") or action.get("action_type"),
                action.get("title"),
            )
            if key in seen:
                continue
            seen.add(key)
            actions.append(action)

    return actions

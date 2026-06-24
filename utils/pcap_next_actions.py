"""Investigation playbooks and aggressive next-actions from PCAP / live capture."""

from __future__ import annotations

from typing import Any

from modules.module_registry import get_module, is_executable
from utils.next_actions import make_action, make_action_id
from utils.pcap_triage import actionable_cleartext, build_triage_report, rank_investigation_entities
from utils.settings_manager import has_api_key
from utils.web_port_planner import is_private_ipv4_target

_API_KEY_HINTS: dict[str, str] = {
    "intel_virustotal": "VIRUSTOTAL_API_KEY",
    "intel_abuseipdb": "ABUSEIPDB_API_KEY",
    "intel_shodan": "SHODAN_API_KEY",
    "intel_urlhaus": "ABUSECH_AUTH_KEY",
    "intel_greynoise": "GREYNOISE_API_KEY",
}


def _pcap_parsed_from_result(result: dict[str, Any]) -> dict[str, Any]:
    module_id = result.get("module_id") or ""
    parsed = result.get("parsed_data") or {}
    if module_id == "net_live_capture":
        return (parsed.get("pcap_review") or {}).get("parsed_data") or {}
    return parsed


def _api_block_reason(module_id: str) -> str | None:
    env_key = _API_KEY_HINTS.get(module_id)
    if not env_key:
        return None
    if has_api_key(env_key):
        return None
    return f"Add {env_key} to .env"


def finalize_capture_actions(
    actions: list[dict[str, Any]],
    *,
    case_id: int,
) -> list[dict[str, Any]]:
    """Enable capture follow-ups with minimal blocking (API keys + module availability only)."""
    enriched: list[dict[str, Any]] = []
    for action in actions:
        item = dict(action)
        blocked = None
        module_id = item.get("module_id")
        action_type = item.get("action_type")
        if action_type in {"run_module", "add_to_queue"} and module_id:
            module = get_module(module_id)
            if module is None or not is_executable(module):
                blocked = f"{module_id} is not available."
            else:
                blocked = _api_block_reason(module_id)
        item["enabled"] = blocked is None
        item["blocked_reason"] = blocked
        enriched.append(item)
    return enriched


def suggest_pcap_investigation_actions(
    result: dict[str, Any],
    *,
    case_id: int,
    workspace_target: str = "",
    entity_id: int | None = None,
    triage: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Return ordered investigation actions from a PCAP or live-capture result."""
    module_id = result.get("module_id") or ""
    parsed = result.get("parsed_data") or {}
    pcap_parsed = _pcap_parsed_from_result(result)
    if not pcap_parsed and not parsed.get("capture"):
        return []

    if triage is None:
        triage = build_triage_report(
            pcap_parsed,
            workspace_target=workspace_target,
            capture_meta=parsed.get("capture"),
        )

    actions: list[dict[str, Any]] = []
    ranked = triage.get("ranked_entities") or rank_investigation_entities(pcap_parsed)

    risky = actionable_cleartext(pcap_parsed.get("cleartext_protocols"))
    if pcap_parsed.get("http_entries") or risky:
        proto_text = ", ".join(risky) if risky else "HTTP"
        actions.append(
            make_action(
                title="Review cleartext exposure",
                reason=f"Cleartext indicators in capture: {proto_text}.",
                action_type="open_finding",
                priority="high",
                target=workspace_target or pcap_parsed.get("filename") or "",
                module_id=module_id or "net_pcap_review",
                button_label="Review findings",
            )
        )

    investigate_ips = [
        item for item in ranked if item["entity_type"] == "ip" and item["tier"] == "investigate"
    ][:3]
    for item in investigate_ips:
        ip = item["value"]
        modules = item.get("suggested_modules") or []
        primary = modules[0] if modules else "intel_abuseipdb"
        label = "Nmap" if primary == "infra_nmap" else primary.replace("intel_", "").replace("infra_", "")
        actions.append(
            make_action(
                title=f"Probe {ip}",
                reason=f"External/local IP with {item.get('packets', 0)} packets in capture.",
                action_type="run_module",
                priority="high",
                target=ip,
                module_id=primary,
                button_label=f"Run {label}",
            )
        )
        if not is_private_ipv4_target(ip):
            actions.append(
                make_action(
                    title=f"Queue reputation for {ip}",
                    reason="Add public IP to batch queue for reputation checks.",
                    action_type="add_to_queue",
                    priority="medium",
                    target=ip,
                    module_id="intel_abuseipdb",
                    button_label="Queue AbuseIPDB",
                )
            )

    investigate_domains = [
        item for item in ranked if item["entity_type"] == "domain" and item["tier"] == "investigate"
    ][:3]
    for item in investigate_domains:
        domain = item["value"]
        actions.append(
            make_action(
                title=f"Domain intel: {domain}",
                reason="Domain appeared in DNS/TLS metadata — run domain intelligence.",
                action_type="run_module",
                priority="high",
                target=domain,
                module_id="infra_domain_intel",
                button_label="Domain intel",
            )
        )
        actions.append(
            make_action(
                title=f"Queue URLhaus for {domain}",
                reason="Check reported URLs associated with this domain.",
                action_type="add_to_queue",
                priority="medium",
                target=domain,
                module_id="intel_urlhaus",
                button_label="Queue URLhaus",
            )
        )

    diff = triage.get("fingerprint_diff") or {}
    if diff.get("new_public_ips"):
        ip = diff["new_public_ips"][0]
        actions.append(
            make_action(
                title=f"New IP since last capture: {ip}",
                reason="This public IP was not in the previous capture fingerprint.",
                action_type="run_module",
                priority="high",
                target=ip,
                module_id="intel_shodan",
                button_label="Shodan lookup",
            )
        )

    if entity_id:
        actions.append(
            make_action(
                title="View capture in graph",
                reason="Open relationship graph focused on this capture artefact.",
                action_type="open_graph",
                priority="medium",
                entity_id=entity_id,
                button_label="Open graph",
                action_id=make_action_id("open_graph", "View capture graph", target=str(entity_id)),
            )
        )

    actions.append(
        make_action(
            title="Generate resilience report",
            reason="Include capture triage and entity observations in case report.",
            action_type="create_report",
            priority="medium",
            target=workspace_target or "",
            button_label="Generate report",
        )
    )

    actions.append(
        make_action(
            title="Review evidence locker",
            reason="Inspect stored PCAP artefacts and analysis summaries.",
            action_type="review_evidence",
            priority="medium",
            button_label="Evidence locker",
        )
    )

    if parsed.get("capture", {}).get("interface"):
        iface = parsed["capture"]["interface"]
        actions.append(
            make_action(
                title="Re-capture with host filter",
                reason="Run a narrower capture focused on a specific host.",
                action_type="no_action",
                priority="low",
                target=workspace_target or iface,
                button_label="Use target-host filter above",
            )
        )

    # De-dupe by id
    seen: set[str] = set()
    unique: list[dict[str, Any]] = []
    for action in actions:
        action_id = action.get("id") or ""
        if action_id in seen:
            continue
        seen.add(action_id)
        unique.append(action)
    finalized = finalize_capture_actions(unique, case_id=case_id)
    if case_id <= 0:
        return finalized
    from database.db_setup import get_db_conn
    from utils.expected_suppression import filter_pcap_followup_actions

    conn = get_db_conn()
    try:
        return filter_pcap_followup_actions(finalized, case_id=case_id, conn=conn)
    finally:
        conn.close()


def suggest_pcap_primary_action(
    result: dict[str, Any],
    *,
    case_id: int,
    workspace_target: str = "",
    triage: dict[str, Any] | None = None,
) -> dict[str, Any]:
    actions = suggest_pcap_investigation_actions(
        result,
        case_id=case_id,
        workspace_target=workspace_target,
        triage=triage,
    )
    if actions:
        return actions[0]
    return make_action(
        title="Review capture evidence",
        reason="Capture completed — inspect triage and evidence locker.",
        action_type="review_evidence",
        priority="medium",
        button_label="Review evidence",
    )


def suggest_post_followup_actions(
    followup_results: list[dict[str, Any]],
    *,
    case_id: int,
) -> list[dict[str, Any]]:
    """Suggest deeper checks after capture follow-up modules have run."""
    actions: list[dict[str, Any]] = []
    seen: set[str] = set()

    for result in followup_results:
        if not result.get("success"):
            continue
        module_id = result.get("module_id")
        target = (result.get("target") or "").strip()
        if not target:
            continue

        if module_id == "infra_nmap" and is_private_ipv4_target(target):
            parsed = result.get("parsed_data") or {}
            from utils.remote_access_classifier import filter_remote_access_services, nmap_ports_to_service_rows

            remote_services = filter_remote_access_services(
                nmap_ports_to_service_rows(parsed.get("parsed_ports") or [])
            )
            if remote_services:
                key = f"{target}:remote_access"
                if key not in seen:
                    seen.add(key)
                    actions.append(
                        make_action(
                            title=f"Remote Access Exposure Review on {target}",
                            reason="Nmap found remote-access or file-sharing services.",
                            action_type="run_module",
                            priority="high",
                            target=target,
                            module_id="infra_remote_access_review",
                            button_label="Remote access review",
                        )
                    )
            ports = [
                int(row.get("port"))
                for row in parsed.get("parsed_ports") or []
                if row.get("port") is not None
            ]
            web_ports = [port for port in ports if port in {80, 443, 8080, 8443}]
            if web_ports or ports:
                for check_module, label in (
                    ("infra_tls_review", "TLS review"),
                    ("infra_http_security", "HTTP headers"),
                ):
                    key = f"{target}:{check_module}"
                    if key in seen:
                        continue
                    seen.add(key)
                    actions.append(
                        make_action(
                            title=f"{label} on {target}",
                            reason="Nmap found responsive services — review web/TLS posture.",
                            action_type="run_module",
                            priority="high",
                            target=target,
                            module_id=check_module,
                            button_label=label,
                        )
                    )

        if module_id in {"intel_abuseipdb", "intel_greynoise", "intel_shodan"} and not is_private_ipv4_target(target):
            key = f"{target}:vt"
            if key not in seen:
                seen.add(key)
                actions.append(
                    make_action(
                        title=f"VirusTotal: {target}",
                        reason="Cross-check reputation with a second intel source.",
                        action_type="run_module",
                        priority="medium",
                        target=target,
                        module_id="intel_virustotal",
                        button_label="VirusTotal",
                    )
                )

    return finalize_capture_actions(actions, case_id=case_id)

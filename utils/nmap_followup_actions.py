"""Follow-up actions from Nmap profile results."""

from __future__ import annotations

from typing import Any

from utils.next_actions import make_action
from utils.remote_access_classifier import filter_remote_access_services, nmap_ports_to_service_rows
from utils.web_port_planner import is_private_ipv4_target

_WEB_PORTS = {80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 7000, 9443}
_TLS_PORTS = {443, 8443, 9443}
_ADMIN_SERVICES = {"ssh", "ms-wbt-server", "vnc", "rdp"}


def _open_ports(parsed: dict[str, Any]) -> list[dict[str, Any]]:
    ports: list[dict[str, Any]] = []
    for row in parsed.get("parsed_ports") or []:
        try:
            port_num = int(row.get("port"))
        except (TypeError, ValueError):
            continue
        ports.append({**row, "port_num": port_num})
    return ports


def suggest_nmap_followup_actions(result: dict[str, Any], *, target: str) -> list[dict[str, Any]]:
    """Suggest HTTP/TLS, intel, capture, and admin review actions from Nmap output."""
    if result.get("module_id") != "infra_nmap" or not result.get("success"):
        return []

    parsed = result.get("parsed_data") or {}
    actions: list[dict[str, Any]] = []
    seen: set[str] = set()
    ports = _open_ports(parsed)

    web_ports = [row for row in ports if row["port_num"] in _WEB_PORTS]
    if web_ports:
        key = f"{target}:http"
        if key not in seen:
            seen.add(key)
            actions.append(
                make_action(
                    title="HTTP Security Header Review",
                    reason="Web-like ports were observed — review HTTP headers on the assessed target.",
                    action_type="run_module",
                    priority="high",
                    target=target,
                    module_id="infra_http_security",
                    button_label="HTTP headers",
                )
            )
        tls_ports = [row for row in web_ports if row["port_num"] in _TLS_PORTS or row["port_num"] in {443, 8443}]
        if tls_ports or any(row["port_num"] in _TLS_PORTS for row in web_ports):
            key = f"{target}:tls"
            if key not in seen:
                seen.add(key)
                actions.append(
                    make_action(
                        title="TLS Configuration Review",
                        reason="TLS-like ports responded — review certificate and protocol posture.",
                        action_type="run_module",
                        priority="high",
                        target=target,
                        module_id="infra_tls_review",
                        button_label="TLS review",
                    )
                )

    if not is_private_ipv4_target(target):
        for module_id, label in (
            ("intel_abuseipdb", "AbuseIPDB"),
            ("intel_greynoise", "GreyNoise"),
        ):
            key = f"{target}:{module_id}"
            if key in seen:
                continue
            seen.add(key)
            actions.append(
                make_action(
                    title=f"{label} reputation",
                    reason="Public IP service map complete — cross-check passive reputation.",
                    action_type="run_module",
                    priority="medium",
                    target=target,
                    module_id=module_id,
                    button_label=label,
                )
            )
            break

    if is_private_ipv4_target(target):
        key = f"{target}:capture"
        if key not in seen:
            seen.add(key)
            actions.append(
                make_action(
                    title="Capture traffic to this host",
                    reason="Local device services observed — PCAP capture may add DHCP/ARP context.",
                    action_type="navigate_page",
                    priority="medium",
                    target=target,
                    module_id="net_live_capture",
                    button_label="Packet Capture",
                )
            )

    for row in ports:
        service = str(row.get("service") or "").lower()
        if service in _ADMIN_SERVICES or any(token in service for token in _ADMIN_SERVICES):
            key = f"{target}:admin"
            if key not in seen:
                seen.add(key)
                actions.append(
                    make_action(
                        title="Remote Access Exposure Review",
                        reason=f"Remote administration service observed on port {row['port_num']}.",
                        action_type="run_module",
                        priority="medium",
                        target=target,
                        module_id="infra_remote_access_review",
                        button_label="Remote access review",
                    )
                )
            if service == "ssh" or row["port_num"] == 22:
                key = f"{target}:ssh"
                if key not in seen:
                    seen.add(key)
                    actions.append(
                        make_action(
                            title=f"SSH Configuration Review (port {row['port_num']})",
                            reason=f"SSH service observed on port {row['port_num']} — review banner and exposure.",
                            action_type="run_module",
                            priority="medium",
                            target=target,
                            module_id="infra_ssh_review",
                            button_label="SSH review",
                        )
                    )
            break

    remote_candidates = filter_remote_access_services(nmap_ports_to_service_rows(parsed.get("parsed_ports") or []))
    if remote_candidates and f"{target}:remote_access" not in seen:
        seen.add(f"{target}:remote_access")
        if not any(action.get("module_id") == "infra_remote_access_review" for action in actions):
            actions.append(
                make_action(
                    title="Remote Access Exposure Review",
                    reason="Remote-access or file-sharing services were observed — review exposure context.",
                    action_type="run_module",
                    priority="medium",
                    target=target,
                    module_id="infra_remote_access_review",
                    button_label="Remote access review",
                )
            )

    if not ports:
        actions.append(
            make_action(
                title="Verify host is online",
                reason="No open ports parsed — host may be offline, filtered, or profile may be too narrow.",
                action_type="run_module",
                priority="medium",
                target=target,
                module_id="infra_nmap",
                button_label="Try Standard Detection",
            )
        )

    return actions


def suggest_primary_nmap_action(result: dict[str, Any], *, target: str) -> dict[str, Any]:
    actions = suggest_nmap_followup_actions(result, target=target)
    return actions[0] if actions else make_action(
        title="Review Nmap details",
        reason="Scan completed — review structured port and service output.",
        action_type="no_action",
        priority="low",
        target=target,
        module_id="infra_nmap",
        button_label="Info",
    )

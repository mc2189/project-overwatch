"""Advisory findings from local PCAP evidence review."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding


def interpret_pcap_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return cautious analyst findings from a supplied PCAP review."""
    findings: list[dict[str, Any]] = []
    filename = parsed_data.get("filename") or "capture"

    if not parsed_data.get("parser_available"):
        if parsed_data.get("unsupported_file_type"):
            findings.append(
                make_finding(
                    "Unsupported file type",
                    "info",
                    90,
                    "The supplied file is not a supported .pcap or .pcapng capture.",
                    ["Upload a standard packet capture export from Wireshark or tcpdump."],
                    finding_kind=FINDING_KIND_SOURCE_NOTICE,
                )
            )
            return findings
        findings.append(
            make_finding(
                "Parser dependency unavailable",
                "info",
                88,
                "PCAP uploaded and hashed, but deep parsing is unavailable because "
                "pyshark/tshark is not installed. Metadata only — requires validation.",
                [
                    "Install Wireshark/tshark and pyshark for deeper packet review.",
                    "Analysis is based only on the supplied capture file.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if parsed_data.get("packets_analysed", 0) > 0 or parsed_data.get("packet_count", 0) > 0:
        findings.append(
            make_finding(
                "PCAP analysed successfully",
                "info",
                90,
                f"Supplied capture {filename!r} was reviewed locally. "
                f"{parsed_data.get('packets_analysed', 0)} packet(s) analysed in this pass.",
                ["Point-in-time review of supplied evidence only — not live capture."],
            )
        )

    if parsed_data.get("analysis_capped"):
        findings.append(
            make_finding(
                "Packet analysis capped",
                "info",
                85,
                "Packet analysis was capped to protect performance. "
                "Results reflect the first portion of the capture only.",
                ["Re-run on a smaller excerpt if full coverage is required."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    if parsed_data.get("dns_queries"):
        findings.append(
            make_finding(
                "DNS queries observed",
                "info",
                82,
                f"DNS queries were observed in the supplied capture ({len(parsed_data['dns_queries'])} sampled).",
                ["Validate queried names against expected infrastructure."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    from utils.pcap_triage import actionable_cleartext

    risky_cleartext = actionable_cleartext(parsed_data.get("cleartext_protocols"))
    if parsed_data.get("http_entries"):
        findings.append(
            make_finding(
                "HTTP traffic observed",
                "medium",
                82,
                "HTTP traffic was observed in the supplied capture. "
                "Cleartext web traffic may expose credentials or session data — investigate.",
                ["Run HTTP security review on observed hosts.", "Review hosts and methods during triage."],
            )
        )

    if risky_cleartext:
        severity = "high" if any(p in {"ftp", "telnet"} for p in risky_cleartext) else "medium"
        findings.append(
            make_finding(
                "Risky cleartext protocol observed",
                severity,
                84 if severity == "high" else 78,
                f"Non-DNS cleartext protocols in capture: {', '.join(risky_cleartext)}.",
                ["Confirm whether legacy cleartext services are expected.", "Prioritise remediation in resilience planning."],
            )
        )

    cleartext = parsed_data.get("cleartext_protocols") or []
    dns_only = cleartext and not risky_cleartext
    if dns_only and not parsed_data.get("http_entries"):
        findings.append(
            make_finding(
                "DNS in cleartext (routine)",
                "info",
                60,
                "DNS was the only cleartext protocol indicator — this is normal on most networks.",
                ["No action required unless unexpected resolvers or queries appear."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    if parsed_data.get("tls_sni"):
        findings.append(
            make_finding(
                "TLS traffic observed",
                "info",
                80,
                f"TLS handshakes/SNI values were observed ({len(parsed_data['tls_sni'])} sampled).",
                ["Correlate server names with known assets.", "Run domain intel on unfamiliar SNIs."],
            )
        )

    triage = parsed_data.get("triage") or {}
    for item in (triage.get("ranked_entities") or [])[:6]:
        if item.get("tier") != "investigate":
            continue
        value = item.get("value")
        entity_type = item.get("entity_type", "entity")
        modules = ", ".join(item.get("suggested_modules") or [])
        findings.append(
            make_finding(
                f"Investigate {entity_type}: {value}",
                "medium",
                75,
                f"{entity_type.upper()} `{value}` ranked for follow-up ({item.get('packets', 0)} packets).",
                [f"Suggested modules: {modules}" if modules else "Run reputation or service checks."],
            )
        )

    if parsed_data.get("sensitive_values_redacted"):
        findings.append(
            make_finding(
                "Sensitive-looking value detected and redacted",
                "medium",
                84,
                "Sensitive-looking material (for example authorisation or cookie hints) was detected "
                "during HTTP review and redacted from stored output.",
                ["Inspect the original capture offline under controlled conditions if required."],
            )
        )

    if parsed_data.get("high_volume_flows"):
        findings.append(
            make_finding(
                "High-volume flow observed",
                "low",
                70,
                "One or more high-volume flows were observed in the supplied capture.",
                ["May indicate bulk transfer or chatty services — requires validation."],
            )
        )

    if parsed_data.get("repeated_patterns"):
        findings.append(
            make_finding(
                "Repeated connection pattern observed",
                "low",
                68,
                "Repeated connection patterns were observed between endpoints in the supplied capture.",
                ["Correlate with expected application behaviour."],
            )
        )

    if parsed_data.get("broadcast_indicators"):
        findings.append(
            make_finding(
                "Broadcast traffic observed",
                "info",
                65,
                "Broadcast or multicast indicators were observed in the supplied capture.",
                ["May be normal LAN noise — validate in context."],
            )
        )

    return findings

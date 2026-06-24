"""Advisory findings from Personal Lab live packet capture."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding


def interpret_live_capture_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return cautious findings for a live capture run."""
    findings: list[dict[str, Any]] = []
    capture = parsed_data.get("capture") or {}

    if parsed_data.get("backend_unavailable"):
        findings.append(
            make_finding(
                "Capture backend unavailable",
                "info",
                90,
                "Live capture could not run because tshark and tcpdump are not available.",
                ["Install Wireshark/tshark or tcpdump for interface capture."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if capture.get("permission_denied"):
        findings.append(
            make_finding(
                "Capture permission issue",
                "info",
                88,
                "Live capture failed due to local permission restrictions.",
                [
                    "Grant capture permissions or run the suggested manual command in a privileged shell.",
                    "Based only on the attempted capture — requires validation.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if parsed_data.get("capture_success"):
        findings.append(
            make_finding(
                "Packet capture completed",
                "info",
                85,
                "A bounded Personal Lab packet capture completed and was saved locally.",
                ["Capture reflects only the selected interface and filter window."],
            )
        )

    if parsed_data.get("analysis_success"):
        findings.append(
            make_finding(
                "Capture analysed",
                "info",
                82,
                "The captured file was passed to PCAP Evidence Review for bounded analysis.",
                ["Analysis is based only on the captured file — not live network state."],
            )
        )

    if capture.get("capped_by_duration") or capture.get("capped_by_packet_count"):
        findings.append(
            make_finding(
                "Capture capped by duration or packet count",
                "info",
                80,
                "Capture limits were applied to protect performance and privacy.",
                ["Adjust duration or packet cap if a narrower or longer window is required."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    pcap_review = parsed_data.get("pcap_review") or {}
    if pcap_review.get("sensitive_detected") or (pcap_review.get("parsed_data") or {}).get(
        "sensitive_values_redacted"
    ):
        findings.append(
            make_finding(
                "Sensitive-looking value detected and redacted",
                "medium",
                84,
                "Sensitive-looking material was detected during PCAP review and redacted from stored output.",
                ["Inspect the original capture offline under controlled conditions if required."],
            )
        )

    pcap_parsed = (pcap_review.get("parsed_data") or {}) if pcap_review else {}
    if not pcap_parsed.get("parser_available") and parsed_data.get("capture_success"):
        if pcap_parsed.get("basic_metadata_available"):
            findings.append(
                make_finding(
                    "Basic PCAP metadata only",
                    "info",
                    80,
                    "Capture saved with packet counts from capinfos/tshark. "
                    "Install pyshark for DNS, HTTP, TLS, and entity extraction.",
                    ["Run `pip install pyshark` in your Project Overwatch virtual environment."],
                    finding_kind=FINDING_KIND_SOURCE_NOTICE,
                )
            )
        else:
            findings.append(
                make_finding(
                    "Parser dependency unavailable",
                    "info",
                    78,
                    "Capture saved successfully but PCAP parsing is unavailable without tshark/pyshark.",
                    ["Install Wireshark/tshark and pyshark for packet metadata review."],
                    finding_kind=FINDING_KIND_SOURCE_NOTICE,
                )
            )

    return findings

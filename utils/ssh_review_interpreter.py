"""Advisory interpretation of SSH configuration review results."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding


def interpret_ssh_review_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    host = parsed_data.get("host") or parsed_data.get("target") or "target"
    port = parsed_data.get("port") or 22
    endpoint = f"{host}:{port}"
    is_private = bool(parsed_data.get("is_private_target"))
    connection = parsed_data.get("connection") or {}
    banner = parsed_data.get("banner") or {}
    nmap_ssh = parsed_data.get("nmap_ssh_service")
    metadata = parsed_data.get("optional_metadata")

    findings.append(
        make_finding(
            "SSH configuration review completed",
            "info",
            88,
            f"Visible SSH service review completed for {endpoint} based on available service information. "
            "This is not an authenticated configuration review.",
            [
                "Review whether SSH exposure is expected for this target.",
                "Restrict access to trusted networks and strong access controls where SSH is required.",
            ],
            finding_kind=FINDING_KIND_SOURCE_NOTICE,
        )
    )

    if parsed_data.get("no_service_data") and not parsed_data.get("manual_review"):
        findings.append(
            make_finding(
                "SSH service not identified from available data",
                "info",
                86,
                "No SSH service was identified from Nmap or stored service observations before review.",
                [
                    "Run Network Service Check first to corroborate SSH exposure.",
                    "Use manual port selection if you need to review a specific port.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    if nmap_ssh or parsed_data.get("data_sources"):
        findings.append(
            make_finding(
                "SSH service observed",
                "low" if is_private else "medium",
                84 if is_private else 80,
                f"SSH service indicators were observed for {endpoint} based on visible service data. "
                "Review whether remote access is expected and restricted to trusted devices.",
                [
                    "Confirm the service and port match expected administration paths.",
                    "Correlate with Remote Access Exposure Review where available.",
                ],
            )
        )

    if port != 22 and (nmap_ssh or connection.get("attempted")):
        findings.append(
            make_finding(
                "SSH service observed on non-standard port",
                "info",
                82,
                f"SSH review targeted port {port} on {host}. Non-standard ports are not inherently safer — "
                "review whether this exposure is expected.",
                ["Document expected administrative ports in scope notes."],
            )
        )

    if banner.get("raw_banner"):
        findings.append(
            make_finding(
                "SSH banner observed",
                "info",
                86,
                f"An SSH banner was observed during visible service review for {endpoint}. "
                "Banner text may disclose software family or version strings.",
                [
                    "Review whether banner disclosure is acceptable for this asset.",
                    "Do not treat banner text as proof of patch level without authenticated validation.",
                ],
            )
        )
        if banner.get("software") or banner.get("version"):
            findings.append(
                make_finding(
                    "SSH version disclosed",
                    "info",
                    80,
                    f"SSH software/version information appears visible for {endpoint} "
                    f"({banner.get('software_family') or banner.get('software') or 'unknown'}). "
                    "Review whether version disclosure is expected.",
                    ["Correlate with vendor advisories only after authenticated validation."],
                )
            )
    elif connection.get("attempted") and not connection.get("success"):
        findings.append(
            make_finding(
                "SSH review could not connect",
                "info",
                85,
                f"SSH review could not retrieve a banner from {endpoint} "
                f"({connection.get('error') or 'connection failed'}). "
                "This does not prove SSH is absent — the service may be filtered or offline.",
                [
                    "Run Network Service Check to confirm whether SSH is open.",
                    "Verify host reachability and the selected port.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    if is_private:
        findings.append(
            make_finding(
                "SSH service observed on local/private target",
                "info",
                84,
                f"SSH indicators were reviewed on a local/private target ({endpoint}). "
                "Confirm whether administration services are expected on this lab or LAN device.",
                ["Use Personal Lab context notes before sharing results externally."],
            )
        )
    elif nmap_ssh or connection.get("success"):
        findings.append(
            make_finding(
                "SSH service observed on public target",
                "medium",
                78,
                f"SSH service indicators were reviewed on a public or non-local target ({endpoint}). "
                "Review whether remote access should be exposed and restricted to trusted networks.",
                [
                    "Confirm scope and ROE before reporting externally.",
                    "Consider Remote Access Exposure Review for broader admin service context.",
                ],
            )
        )

    if metadata and not metadata.get("error"):
        findings.append(
            make_finding(
                "SSH metadata partially available",
                "info",
                80,
                "Optional SSH handshake metadata was collected without authentication. "
                "Algorithm lists are visible-service indicators only.",
                ["Review algorithm exposure in context — not a confirmed misconfiguration."],
            )
        )
    elif parsed_data.get("optional_metadata_unavailable"):
        findings.append(
            make_finding(
                "SSH metadata partially unavailable",
                "info",
                88,
                "Optional SSH metadata backend was unavailable — banner-only review was performed.",
                ["Install optional Paramiko only if deeper metadata is required locally."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    return findings

"""Advisory interpretation of remote access exposure review results."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding
from utils.remote_access_classifier import (
    CLASS_FILE_SHARING,
    CLASS_LEGACY_CLEARTEXT,
    CLASS_MANAGEMENT_CONSOLE,
    CLASS_MEDIA_DEVICE,
    CLASS_REMOTE_ADMIN,
    classification_label,
    severity_for_service,
)


def _device_context_note(parsed_data: dict[str, Any]) -> str:
    hint = parsed_data.get("lan_device_hint") or {}
    role = hint.get("role_label") or hint.get("role")
    hostname = hint.get("hostname")
    if role and hostname:
        return f" Device context from capture: {hostname} ({role})."
    if role:
        return f" Device role hint from capture: {role}."
    return ""


def interpret_remote_access_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return cautious findings from remote access exposure review."""
    findings: list[dict[str, Any]] = []
    target = parsed_data.get("target") or "assessed target"
    is_private = bool(parsed_data.get("is_private_target"))
    exposure = "local/private network" if is_private else "public or non-local target"
    services = list(parsed_data.get("remote_services") or [])
    device_note = _device_context_note(parsed_data)
    version_observed = False

    if parsed_data.get("no_service_data"):
        findings.append(
            make_finding(
                "No service data available for remote access review",
                "info",
                90,
                "No Nmap or service observations were available. Run Network Service Check first.",
                [
                    "Run Network Service Check on the target.",
                    "Re-run this review after service discovery completes.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if not services:
        findings.append(
            make_finding(
                "No remote-access service identified from available data",
                "info",
                85,
                f"No remote administration, file-sharing, or legacy management services were identified "
                f"for {target} from observed service data.",
                [
                    "If services are expected, run a broader Network Service Check profile.",
                    "Confirm the target address and that the host was online during discovery.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if not is_private:
        findings.append(
            make_finding(
                "Remote access services observed on public target",
                "high",
                82,
                f"Remote-access or administrative services were observed on {target} ({exposure}). "
                "Review whether exposure is intentional and restricted.",
                [
                    "Validate exposure with asset owner and change records.",
                    "Restrict access to trusted networks where possible.",
                    "Add this exposure to the case report for follow-up.",
                ],
            )
        )

    for service in services:
        label = service.get("service_label") or f"port {service.get('port')}"
        port_label = f"{service.get('port')}/{service.get('protocol', 'tcp')}"
        classification = service.get("classification") or ""
        class_label = service.get("classification_label") or classification_label(classification)
        severity = severity_for_service(
            classification=classification,
            is_private=is_private,
            service_label=label,
        )
        product = service.get("product") or ""
        version = service.get("version") or ""
        version_note = f" ({product} {version})".strip() if product or version else ""

        title = _title_for_service(label, classification)
        explanation = (
            f"{title} observed on {port_label} for {target} ({exposure}). "
            f"Classification: {class_label}. Based on observed service data — review whether this is expected "
            f"and restricted to trusted devices.{version_note}{device_note}"
        )
        actions = _actions_for_service(label, classification, is_private)
        findings.append(
            make_finding(
                title,
                severity,
                80 if severity != "high" else 78,
                explanation,
                actions,
            )
        )
        if (product or version) and not version_observed:
            version_observed = True

    if version_observed:
        findings.append(
            make_finding(
                "Service version observed",
                "info",
                75,
                "Service version details were observed during remote access review. "
                "Validate patch level separately — version alone does not confirm vulnerability.",
                [
                    "Record versions in asset inventory.",
                    "Review vendor advisories through your normal patch process.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    if device_note and services:
        role_hint = (parsed_data.get("lan_device_hint") or {}).get("role_label") or "device"
        service_names = ", ".join(service.get("service_label") or "service" for service in services[:3])
        findings.append(
            make_finding(
                "Device management exposure context",
                "info",
                70,
                f"Likely {role_hint} management exposure observed ({service_names}). "
                "Review whether management interfaces should be reachable on this network.",
                [
                    "Confirm the device role matches expected inventory.",
                    "Restrict management services to trusted admin networks.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    return findings


def _title_for_service(label: str, classification: str) -> str:
    mapping = {
        CLASS_REMOTE_ADMIN: {
            "SSH": "Remote administration service observed (SSH)",
            "RDP": "Remote desktop service observed",
            "VNC": "VNC service observed",
            "WinRM": "WinRM service observed",
        },
        CLASS_FILE_SHARING: {"SMB": "SMB/file-sharing service observed"},
        CLASS_LEGACY_CLEARTEXT: {
            "Telnet": "Telnet service observed",
            "FTP": "FTP service observed",
        },
        CLASS_MEDIA_DEVICE: {"RTSP": "Media/RTSP service observed"},
    }
    if classification == CLASS_REMOTE_ADMIN and label in {"SSH", "RDP", "VNC", "WinRM"}:
        return mapping[CLASS_REMOTE_ADMIN][label]
    if classification == CLASS_FILE_SHARING and label == "SMB":
        return mapping[CLASS_FILE_SHARING]["SMB"]
    if classification == CLASS_LEGACY_CLEARTEXT and label in {"Telnet", "FTP"}:
        return mapping[CLASS_LEGACY_CLEARTEXT][label]
    if classification == CLASS_MEDIA_DEVICE and label == "RTSP":
        return mapping[CLASS_MEDIA_DEVICE]["RTSP"]
    if classification == CLASS_MANAGEMENT_CONSOLE:
        return "Management console service observed"
    return f"Remote access service observed ({label})"


def _actions_for_service(label: str, classification: str, is_private: bool) -> list[str]:
    actions = [
        "Review whether this service is expected on the assessed target.",
        "Restrict access to trusted networks and strong access controls.",
        "Disable the service if it is not required.",
    ]
    if not is_private:
        actions.insert(0, "Treat public exposure as priority validation with asset owner.")
    if classification == CLASS_LEGACY_CLEARTEXT:
        actions.append("Prefer encrypted alternatives and disable cleartext management where possible.")
    if label in {"RDP", "VNC", "SSH"}:
        actions.append("Review remote access policy, MFA, and logging for this service.")
    if classification == CLASS_FILE_SHARING:
        actions.append("Confirm SMB/file sharing is limited to intended internal use.")
    return actions

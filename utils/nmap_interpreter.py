"""Advisory defensive interpretation of parsed Nmap results."""

from __future__ import annotations

from typing import Any


def _finding(
    title: str,
    severity: str,
    confidence: int,
    explanation: str,
    suggested_actions: list[str],
) -> dict[str, Any]:
    return {
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "explanation": explanation,
        "suggested_actions": suggested_actions,
    }


def interpret_nmap_results(parsed_data: dict[str, Any], options: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    """Return cautious defensive findings from parsed Nmap data."""
    options = options or {}
    findings: list[dict[str, Any]] = []
    parsed_ports = parsed_data.get("parsed_ports", [])
    script_results = parsed_data.get("script_results", [])
    os_matches = parsed_data.get("os_matches", [])
    script_category = options.get("script_category", "none")

    if options.get("os_detection_runtime_failed"):
        findings.append(
            _finding(
                "OS detection failed at runtime",
                "info",
                90,
                "Nmap reported that OS detection requires elevated privileges during the scan. The scan continued without OS detection.",
                [
                    "Review the raw output for the exact Nmap message.",
                    "Use service/version detection instead, or run OS detection only in an authorised elevated terminal session.",
                ],
            )
        )
    elif options.get("os_detection_skipped"):
        findings.append(
            _finding(
                "OS detection skipped",
                "info",
                95,
                "Nmap OS detection requires elevated privileges and was not run.",
                [
                    "Run a standard service scan instead, or use OS detection only in an authorised elevated terminal session.",
                ],
            )
        )

    if options.get("traceroute_runtime_failed"):
        findings.append(
            _finding(
                "Traceroute failed at runtime",
                "info",
                88,
                "Nmap reported that traceroute requires elevated privileges during the scan. The scan continued without traceroute.",
                [
                    "Review the raw output for the exact Nmap message.",
                    "Use an authorised elevated terminal session if traceroute is required.",
                ],
            )
        )
    elif options.get("traceroute_skipped"):
        findings.append(
            _finding(
                "Traceroute skipped",
                "info",
                92,
                "Nmap traceroute may require elevated privileges and was not run.",
                [
                    "Continue with the service scan results, or run traceroute separately in an authorised elevated session.",
                ],
            )
        )

    if options.get("host_discovery_only"):
        findings.append(
            _finding(
                "Host discovery completed",
                "info",
                85,
                "This run used host discovery only. Open ports and services were not scanned.",
                [
                    "If appropriate and authorised, run a service scan profile on responsive hosts.",
                    "Record discovery results in the case notes.",
                ],
            )
        )
        return findings

    if not parsed_ports:
        findings.append(
            _finding(
                "No open ports identified",
                "info",
                70,
                "No open ports were parsed from this scan. This does not prove the host has no exposed services.",
                [
                    "Review the raw Nmap output for filtered or unusual results.",
                    "Confirm the target address and scan profile were appropriate.",
                ],
            )
        )

    for port in parsed_ports:
        service = (port.get("service") or "").lower()
        version = (port.get("version") or "").lower()
        combined = f"{service} {version}".strip()
        port_label = f"{port.get('port')}/{port.get('protocol')}"

        if any(token in combined for token in ("vnc", "rdp", "ms-wbt-server", "apple remote desktop")):
            findings.append(
                _finding(
                    f"Remote desktop service exposed on {port_label}",
                    "medium",
                    80,
                    "Remote desktop services can allow interactive access if not restricted.",
                    [
                        "Confirm this service is expected on the target.",
                        "Restrict access with firewall rules and strong authentication.",
                        "Review logs for unexpected login attempts.",
                    ],
                )
            )
        elif service in {"http", "https", "http-alt", "ssl/http"} or "http" in service:
            findings.append(
                _finding(
                    f"Web service exposed on {port_label}",
                    "low",
                    75,
                    "An open web service may expose applications or admin interfaces.",
                    [
                        "Review TLS configuration and certificate validity.",
                        "Check security headers and exposed admin pages using passive review.",
                        "Confirm only intended content is publicly reachable.",
                    ],
                )
            )
        elif service in {"microsoft-ds", "netbios-ssn", "smb"} or "smb" in combined:
            findings.append(
                _finding(
                    f"SMB/file sharing exposed on {port_label}",
                    "medium",
                    78,
                    "Windows file sharing should be limited to trusted networks.",
                    [
                        "Confirm SMB exposure is expected and required.",
                        "Restrict access to authorised subnets and accounts.",
                        "Review share permissions and disable legacy protocols where possible.",
                    ],
                )
            )
        elif service == "ssh":
            findings.append(
                _finding(
                    f"SSH service exposed on {port_label}",
                    "low",
                    72,
                    "SSH is expected on many servers but should be hardened.",
                    [
                        "Prefer key-based authentication and disable password login where appropriate.",
                        "Limit source IPs where possible.",
                        "Review SSH banners and patch levels.",
                    ],
                )
            )
        elif service in {"ftp", "telnet"}:
            findings.append(
                _finding(
                    f"Legacy cleartext service exposed on {port_label}",
                    "high",
                    85,
                    f"{service.upper()} transmits credentials or data without modern encryption.",
                    [
                        "Confirm whether this legacy service is still required.",
                        "Replace with encrypted alternatives where possible.",
                        "Restrict access and monitor authentication attempts.",
                    ],
                )
            )
        elif "kerberos" in combined:
            findings.append(
                _finding(
                    f"Kerberos service observed on {port_label}",
                    "info",
                    65,
                    "Kerberos is common in managed environments and is not automatically a vulnerability.",
                    [
                        "Confirm the service is expected for this asset.",
                        "Review realm configuration and monitoring if this host is unexpected.",
                    ],
                )
            )
        elif service:
            findings.append(
                _finding(
                    f"Open service requires review: {port_label}",
                    "info",
                    60,
                    f"Service '{service}' is exposed. Open ports alone do not prove a vulnerability.",
                    [
                        "Identify whether the service is business-required.",
                        "Review vendor documentation and patch status manually.",
                    ],
                )
            )
        else:
            findings.append(
                _finding(
                    f"Unknown open port requires review: {port_label}",
                    "info",
                    55,
                    "An open port was found without a confident service fingerprint.",
                    [
                        "Inspect the raw Nmap output and service/version details.",
                        "Validate whether the port should be reachable.",
                    ],
                )
            )

    for os_match in os_matches[:3]:
        if os_match.get("name"):
            findings.append(
                _finding(
                    f"Possible OS match: {os_match['name']}",
                    "info",
                    int(os_match.get("accuracy") or 50),
                    "OS fingerprinting is indicative, not definitive.",
                    [
                        "Corroborate OS details with asset inventory records.",
                        "Use the result to prioritise patch review, not as proof of compromise.",
                    ],
                )
            )

    if script_category == "none" and not script_results:
        findings.append(
            _finding(
                "No NSE script results collected",
                "info",
                80,
                "Absence of script output does not mean the target is safe.",
                [
                    "Use script categories only when authorised and necessary.",
                    "Do not treat missing script results as a clean bill of health.",
                ],
            )
        )

    for script in script_results:
        output = (script.get("output") or "").lower()
        script_id = script.get("script_id", "script")
        if not output:
            continue
        if script_category == "vuln" or "vuln" in script_id:
            findings.append(
                _finding(
                    f"Potential NSE finding from {script_id}",
                    "medium",
                    70,
                    "NSE vuln script output indicates a potential issue requiring validation, not confirmed compromise.",
                    [
                        "Validate the finding manually in a controlled environment.",
                        "Correlate with patch level, configuration review, and change records.",
                        "Do not treat script output as proof of exploitation.",
                    ],
                )
            )
        elif any(token in output for token in ("vulnerable", "weak", "expired", "anonymous")):
            findings.append(
                _finding(
                    f"Script output requires review: {script_id}",
                    "medium",
                    68,
                    "Script output contains language that may indicate a configuration concern.",
                    [
                        "Review the raw script output in context.",
                        "Confirm whether the condition is expected for this asset.",
                    ],
                )
            )

    return findings

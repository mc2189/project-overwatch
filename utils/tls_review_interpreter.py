"""Advisory interpretation of controlled TLS configuration review results."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding


def interpret_tls_review_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return cautious analyst findings from an authorised TLS review."""
    findings: list[dict[str, Any]] = []
    host = parsed_data.get("host") or parsed_data.get("target") or "target"
    port = parsed_data.get("port") or 443
    conn = parsed_data.get("connection") or {}
    tls = parsed_data.get("tls") or {}
    cert = parsed_data.get("certificate") or {}
    endpoint = f"{host}:{port}"

    if parsed_data.get("scope_blocked"):
        findings.append(
            make_finding(
                "Scope blocked TLS review",
                "info",
                90,
                parsed_data.get("scope_blocked_reason")
                or "TLS review was blocked by engagement/scope controls before connecting.",
                [
                    "Confirm the target is in scope with safe active testing permitted.",
                    "Review engagement ROE and emergency stop status.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if conn.get("success"):
        version = tls.get("version") or "unknown"
        findings.append(
            make_finding(
                "TLS service observed",
                "info",
                90,
                f"A TLS service was observed on {endpoint} during authorised TLS review "
                f"(negotiated {version}). Point-in-time result — requires client validation before remediation.",
                [
                    "Confirm the service and port are expected for this asset.",
                    "Correlate with passive domain intelligence if collected.",
                ],
            )
        )
        if cert.get("subject"):
            findings.append(
                make_finding(
                    "Certificate observed",
                    "info",
                    88,
                    f"A server certificate was observed during authorised TLS review for {endpoint}. "
                    f"Subject: {cert['subject']!r}. Point-in-time result.",
                    [
                        "Review certificate subject and SAN names against expected hostnames.",
                        "Correlate with certificate transparency data if available.",
                    ],
                )
            )
    elif conn.get("error"):
        findings.append(
            make_finding(
                "TLS service not reachable",
                "info",
                88,
                f"No TLS response from {endpoint}. The selected service was not reachable "
                f"({conn['error']}). This does not prove weak TLS — no usable handshake was received.",
                [
                    "Run Network Service Check to identify TLS services and ports.",
                    "Confirm the host is online and the expected port is correct.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if not conn.get("success"):
        return findings

    days = cert.get("days_until_expiry")
    if days is not None:
        if days < 0:
            findings.append(
                make_finding(
                    "Certificate expired",
                    "medium",
                    85,
                    f"The observed certificate for {endpoint} appears expired "
                    f"(not valid after {cert.get('not_after')}). Observed during authorised TLS review.",
                    [
                        "Confirm expiry with the certificate owner.",
                        "Plan renewal or replacement — requires client validation before remediation.",
                    ],
                )
            )
        elif days <= 7:
            findings.append(
                make_finding(
                    "Certificate expires soon",
                    "medium",
                    82,
                    f"The observed certificate for {endpoint} expires in {days} day(s). "
                    "Point-in-time result during authorised TLS review.",
                    [
                        "Confirm renewal timeline with the client.",
                        "Monitor for successful replacement after renewal.",
                    ],
                )
            )
        elif days <= 30:
            findings.append(
                make_finding(
                    "Certificate expires within 30 days",
                    "low",
                    80,
                    f"The observed certificate for {endpoint} expires in {days} day(s). "
                    "Observed during authorised TLS review.",
                    [
                        "Review renewal planning with the client.",
                        "Re-check after renewal window if relevant to the engagement.",
                    ],
                )
            )

    hostname_valid = cert.get("hostname_valid")
    if hostname_valid is False:
        findings.append(
            make_finding(
                "Certificate hostname mismatch",
                "medium",
                85,
                f"Hostname validation did not succeed for {endpoint} during authorised TLS review. "
                "This may indicate a certificate/name mismatch — point-in-time result.",
                [
                    "Compare certificate SAN/CN with the tested hostname.",
                    "Confirm whether a different hostname or SNI is expected.",
                ],
            )
        )

    chain_valid = cert.get("chain_valid")
    if chain_valid is False:
        findings.append(
            make_finding(
                "Certificate chain validation failed",
                "medium",
                82,
                f"Certificate chain validation did not succeed for {endpoint} during authorised TLS review. "
                "May indicate incomplete chain, untrusted issuer, or local trust store differences.",
                [
                    "Review the presented chain with the client.",
                    "Distinguish target configuration issues from local trust limitations.",
                ],
            )
        )

    probes = tls.get("protocol_probe") or {}
    legacy_accepted: list[str] = []
    modern_only: list[str] = []
    for label, probe in probes.items():
        if probe.get("note") == "not_supported_by_local_runtime":
            findings.append(
                make_finding(
                    f"Protocol probe not supported by local runtime ({label})",
                    "info",
                    70,
                    f"TLS {label} probe was not performed because the local Python/OpenSSL runtime "
                    "does not support testing that version. This is not a target risk finding.",
                    [
                        "Use an environment with broader TLS support if legacy protocol verification is required.",
                    ],
                    finding_kind=FINDING_KIND_SOURCE_NOTICE,
                )
            )
            continue
        if probe.get("tested") and probe.get("accepted"):
            if label in {"TLS 1.0", "TLS 1.1"}:
                legacy_accepted.append(label)
            elif label in {"TLS 1.2", "TLS 1.3"}:
                modern_only.append(label)

    if legacy_accepted:
        findings.append(
            make_finding(
                "Weak or legacy TLS protocol accepted",
                "medium",
                78,
                f"During authorised TLS review, {endpoint} accepted legacy protocol(s): "
                f"{', '.join(legacy_accepted)}. One handshake per version — point-in-time result.",
                [
                    "Confirm whether legacy TLS is required for compatibility.",
                    "Plan deprecation where policy allows — requires client validation.",
                ],
            )
        )

    negotiated = (tls.get("version") or "").upper()
    if modern_only and not legacy_accepted and negotiated.startswith("TLS 1."):
        if negotiated in {"TLS 1.2", "TLS 1.3"} or any(v in modern_only for v in ("TLS 1.2", "TLS 1.3")):
            findings.append(
                make_finding(
                    "Strong TLS protocol negotiated",
                    "info",
                    85,
                    f"TLS review for {endpoint} negotiated {tls.get('version') or 'a modern protocol'}. "
                    "Legacy TLS 1.0/1.1 were not observed as accepted in controlled probes (where tested).",
                    [
                        "Document as positive posture signal — still a point-in-time observation.",
                    ],
                )
            )

    return findings

"""Advisory interpretation of passive domain intelligence results."""

from __future__ import annotations

from datetime import datetime, timezone
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


def _parse_cert_expiry(not_after: str | None) -> datetime | None:
    if not not_after:
        return None
    try:
        parsed = datetime.fromisoformat(not_after.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed
    except ValueError:
        return None


def interpret_domain_intel_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return cautious analyst findings from domain intelligence data."""
    findings: list[dict[str, Any]] = []
    domain = parsed_data.get("domain") or "target"
    dns_records = parsed_data.get("dns", {})
    http_results = parsed_data.get("http", {})
    security_headers = parsed_data.get("security_headers", {}).get("https", {})
    tls = parsed_data.get("tls", {})
    wayback = parsed_data.get("wayback", {})

    a_records = dns_records.get("A", [])
    aaaa_records = dns_records.get("AAAA", [])
    if not a_records and not aaaa_records:
        findings.append(
            _finding(
                "No A or AAAA records observed",
                "medium",
                85,
                f"No IPv4 (A) or IPv6 (AAAA) DNS records were observed for {domain}. "
                "The domain may be unused, misconfigured, or resolving through another mechanism.",
                [
                    "Confirm whether the domain is expected to resolve publicly.",
                    "Review NS and CNAME records for alternate resolution paths.",
                    "Document whether this is expected or needs follow-up.",
                ],
            )
        )

    mx_records = dns_records.get("MX", [])
    if mx_records:
        findings.append(
            _finding(
                "MX records found",
                "info",
                90,
                f"Mail exchange (MX) records were observed for {domain}: {', '.join(mx_records)}.",
                [
                    "Confirm mail server configuration matches organisational expectations.",
                    "Review whether exposed mail hosts are expected in this case.",
                    "Document whether the finding is expected or needs follow-up.",
                ],
            )
        )

    ns_records = dns_records.get("NS", [])
    if ns_records:
        findings.append(
            _finding(
                "Nameserver records found",
                "info",
                88,
                f"Nameserver (NS) records were observed for {domain}: {', '.join(ns_records)}.",
                [
                    "Confirm nameserver delegation matches expected DNS hosting.",
                    "Review whether third-party DNS providers are authorised for this domain.",
                    "Document whether the finding is expected or needs follow-up.",
                ],
            )
        )

    https_info = http_results.get("https", {})
    if not https_info.get("reachable"):
        error_detail = https_info.get("error") or "connection failed"
        findings.append(
            _finding(
                "HTTPS unavailable or failed",
                "medium",
                80,
                f"HTTPS was not successfully reached for {domain}. Observed result: {error_detail}. "
                "This may indicate no web service, a firewall block, or a TLS configuration issue.",
                [
                    "Check website TLS and security headers when HTTPS becomes reachable.",
                    "Review whether a web service is expected on this domain.",
                    "Document whether the finding is expected or needs follow-up.",
                ],
            )
        )

    missing_headers = [name for name, meta in security_headers.items() if not meta.get("present")]
    if missing_headers and https_info.get("reachable"):
        header_list = ", ".join(missing_headers)
        findings.append(
            _finding(
                "Common security headers not observed",
                "low",
                75,
                f"The following common HTTPS security headers were not observed for {domain}: {header_list}. "
                "Absence does not confirm a vulnerability; headers may be set elsewhere or not applicable.",
                [
                    "Check website TLS and security headers in a browser or header inspection tool.",
                    "Review whether missing headers are expected for this application.",
                    "Document whether the finding is expected or needs follow-up.",
                ],
            )
        )

    if tls.get("available"):
        expiry = _parse_cert_expiry(tls.get("not_after"))
        if expiry:
            days_remaining = (expiry - datetime.now(timezone.utc)).days
            if days_remaining <= 30:
                findings.append(
                    _finding(
                        "TLS certificate expiry approaching",
                        "medium" if days_remaining <= 14 else "low",
                        92,
                        f"TLS certificate for {domain} expires on {tls.get('not_after')} "
                        f"(approximately {days_remaining} day(s) remaining).",
                        [
                            "Confirm certificate renewal plans with the domain owner or service team.",
                            "Check website TLS and security headers after renewal.",
                            "Document whether the finding is expected or needs follow-up.",
                        ],
                    )
                )
    elif https_info.get("reachable"):
        tls_error = tls.get("error") or "certificate details unavailable"
        findings.append(
            _finding(
                "TLS certificate details unavailable",
                "low",
                70,
                f"HTTPS responded for {domain}, but full TLS certificate details could not be collected: {tls_error}.",
                [
                    "Check website TLS and security headers with an external TLS inspection tool.",
                    "Review whether certificate chain issues are expected in this environment.",
                    "Document whether the finding is expected or needs follow-up.",
                ],
            )
        )

    if wayback.get("available"):
        findings.append(
            _finding(
                "Wayback snapshots available",
                "info",
                85,
                f"Internet Archive Wayback Machine snapshots are available for {domain}. "
                f"First snapshot: {wayback.get('first_snapshot') or 'unknown'}; "
                f"last snapshot: {wayback.get('last_snapshot') or 'unknown'}.",
                [
                    "Review historical snapshots for exposed old content or retired subpaths.",
                    "Compare archived content with current public-facing pages.",
                    "Document whether the finding is expected or needs follow-up.",
                ],
            )
        )

    return findings

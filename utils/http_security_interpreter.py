"""Advisory interpretation of controlled HTTP security header review results."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding


def interpret_http_security_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return cautious analyst findings from an authorised HTTP header review."""
    findings: list[dict[str, Any]] = []
    url = parsed_data.get("requested_url") or parsed_data.get("target") or "target"
    scheme = (parsed_data.get("scheme") or "https").lower()
    response = parsed_data.get("response") or {}
    security = parsed_data.get("security_headers") or {}
    headers = parsed_data.get("headers") or {}
    cookies = parsed_data.get("cookies") or []
    well_known = parsed_data.get("well_known") or {}

    if parsed_data.get("scope_blocked"):
        findings.append(
            make_finding(
                "Scope blocked HTTP review",
                "info",
                90,
                parsed_data.get("scope_blocked_reason")
                or "HTTP security review was blocked by engagement/scope controls before connecting.",
                [
                    "Confirm the target is in scope with safe active testing permitted.",
                    "Review engagement ROE and emergency stop status.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if response.get("success"):
        findings.append(
            make_finding(
                "HTTP response observed",
                "info",
                90,
                f"An HTTP response was observed for {url} during authorised HTTP header review "
                f"(status {response.get('status_code')}). Point-in-time result.",
                [
                    "Confirm the URL and status are expected for this asset.",
                    "Correlate with passive website metadata if collected.",
                ],
            )
        )
        if scheme == "https" or str(response.get("final_url", "")).lower().startswith("https://"):
            findings.append(
                make_finding(
                    "HTTPS used",
                    "info",
                    85,
                    f"The reviewed response used HTTPS for {response.get('final_url') or url}. "
                    "Observed during authorised HTTP header review.",
                    [
                        "Confirm TLS configuration separately if required.",
                        "Review HSTS and redirect behaviour for completeness.",
                    ],
                )
            )
    elif response.get("error"):
        findings.append(
            make_finding(
                "HTTP response error observed",
                "low",
                75,
                f"HTTP security review could not retrieve a response from {url}: {response['error']}. "
                "Point-in-time result — may indicate filtering, downtime, or network limits.",
                [
                    "Retry later if the site is expected to be reachable.",
                    "Confirm URL, DNS, and path with the client.",
                ],
            )
        )

    def _header_finding(
        field: str,
        title_present: str,
        title_missing: str,
        *,
        missing_severity: str = "low",
        present_severity: str = "info",
        missing_text: str,
        present_text: str,
    ) -> None:
        item = security.get(field) or {}
        if item.get("present"):
            findings.append(
                make_finding(
                    title_present,
                    present_severity,
                    82,
                    present_text,
                    ["Review header value during human validation — point-in-time observation only."],
                )
            )
        elif response.get("success"):
            findings.append(
                make_finding(
                    title_missing,
                    missing_severity,
                    80,
                    missing_text,
                    [
                        "Absence in this review does not prove the header is never sent on other paths.",
                        "Requires client validation before remediation.",
                    ],
                )
            )

    _header_finding(
        "hsts",
        "HSTS header observed",
        "HSTS header not observed on HTTPS",
        missing_severity="low" if scheme == "https" else "info",
        missing_text=(
            f"Strict-Transport-Security was not observed for {url} during authorised HTTP header review. "
            "On HTTPS sites this is a common hardening header — point-in-time advisory only."
        ),
        present_text=(
            f"Strict-Transport-Security was observed for {url} during authorised HTTP header review."
        ),
    )
    _header_finding(
        "csp",
        "Content-Security-Policy observed",
        "Content-Security-Policy not observed",
        missing_text=(
            f"Content-Security-Policy was not observed for {url}. "
            "CSP can reduce XSS impact but absence is advisory only in this review."
        ),
        present_text=f"Content-Security-Policy was observed for {url}.",
    )
    _header_finding(
        "x_frame_options",
        "X-Frame-Options observed",
        "X-Frame-Options not observed",
        missing_text=(
            f"X-Frame-Options was not observed for {url}. "
            "May increase clickjacking review priority — point-in-time result."
        ),
        present_text=f"X-Frame-Options was observed for {url}.",
    )
    _header_finding(
        "x_content_type_options",
        "X-Content-Type-Options observed",
        "X-Content-Type-Options not observed",
        missing_text=f"X-Content-Type-Options was not observed for {url}.",
        present_text=f"X-Content-Type-Options was observed for {url}.",
    )
    _header_finding(
        "referrer_policy",
        "Referrer-Policy observed",
        "Referrer-Policy not observed",
        missing_severity="info",
        missing_text=f"Referrer-Policy was not observed for {url}.",
        present_text=f"Referrer-Policy was observed for {url}.",
    )
    _header_finding(
        "permissions_policy",
        "Permissions-Policy observed",
        "Permissions-Policy not observed",
        missing_severity="info",
        missing_text=f"Permissions-Policy was not observed for {url}.",
        present_text=f"Permissions-Policy was observed for {url}.",
    )

    legacy = security.get("x_xss_protection") or {}
    if legacy.get("present"):
        findings.append(
            make_finding(
                "Legacy X-XSS-Protection header observed",
                "info",
                70,
                f"X-XSS-Protection was observed for {url}. This legacy header is informational only "
                "and is not a substitute for modern XSS mitigations such as CSP.",
                ["Document for completeness; do not treat as a primary control."],
            )
        )

    if headers.get("server"):
        findings.append(
            make_finding(
                "Server header exposed",
                "info",
                75,
                f"A Server response header was observed for {url}: {headers['server']!r}. "
                "Banner disclosure is informational — point-in-time result.",
                [
                    "Review whether version disclosure is expected.",
                    "Correlate with patch management processes during client review.",
                ],
            )
        )
    if headers.get("x_powered_by"):
        findings.append(
            make_finding(
                "X-Powered-By header exposed",
                "info",
                75,
                f"An X-Powered-By response header was observed for {url}: {headers['x_powered_by']!r}. "
                "Technology disclosure is informational — point-in-time result.",
                [
                    "Review whether framework disclosure is expected.",
                    "Use alongside other footprint data during human review.",
                ],
            )
        )

    for cookie in cookies:
        name = cookie.get("name") or "unknown"
        issues: list[str] = []
        if not cookie.get("secure") and scheme == "https":
            issues.append("Secure")
        if not cookie.get("httponly"):
            issues.append("HttpOnly")
        if not cookie.get("samesite"):
            issues.append("SameSite")
        if not issues:
            continue
        severity = "medium" if cookie.get("session_like") else "low"
        findings.append(
            make_finding(
                f"Cookie missing recommended flags ({name})",
                severity,
                78 if cookie.get("session_like") else 72,
                f"Cookie {name!r} observed during authorised HTTP review without "
                f"{', '.join(issues)} flag(s). Cookie values were not stored. "
                "Point-in-time result — requires client validation.",
                [
                    "Review cookie purpose and exposure during authenticated flows separately.",
                    "Do not treat flag absence as proof of exploitability.",
                ],
            )
        )

    security_txt = well_known.get("security_txt") or {}
    if security_txt.get("observed"):
        findings.append(
            make_finding(
                "security.txt observed",
                "info",
                80,
                f"A security.txt resource was observed at {security_txt.get('url') or 'a standard path'} "
                "during authorised HTTP review.",
                ["Review contact/policy details with the client if relevant to the engagement."],
            )
        )
    elif response.get("success"):
        findings.append(
            make_finding(
                "security.txt not observed",
                "info",
                70,
                f"security.txt was not observed at standard paths for {url} during this review. "
                "Optional metadata only — not a security control by itself.",
                ["Document absence if security contact discovery is in scope."],
            )
        )

    robots = well_known.get("robots_txt") or {}
    if robots.get("observed"):
        findings.append(
            make_finding(
                "robots.txt observed",
                "info",
                75,
                f"robots.txt was observed for {robots.get('url') or url} during authorised HTTP review.",
                ["Use as public crawl policy context only — not proof of hidden content."],
            )
        )

    return findings

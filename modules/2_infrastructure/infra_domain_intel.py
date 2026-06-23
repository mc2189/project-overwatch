"""Passive domain intelligence collection for Project Overwatch."""

from __future__ import annotations

import re
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import requests

from utils.display_format import (
    display_or_unavailable,
    format_wayback_timestamp,
    format_wayback_user_error,
)
from utils.result_status import resolve_collection_status

COMMON_SECURITY_HEADERS = [
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
]

DOMAIN_PATTERN = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

REQUEST_TIMEOUT = 12


def normalize_domain(value: str) -> str:
    """Normalise a domain name or URL to a lowercase hostname."""
    cleaned = value.strip().lower()
    if not cleaned:
        return ""

    if "://" not in cleaned:
        cleaned = f"http://{cleaned}"

    parsed = urlparse(cleaned)
    host = parsed.netloc or parsed.path.split("/")[0]
    host = host.split("@")[-1]
    host = host.split(":")[0]
    return host.rstrip(".")


def is_valid_domain(domain: str) -> bool:
    return bool(domain) and bool(DOMAIN_PATTERN.match(domain))


def _query_dns(domain: str, record_type: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(domain, record_type, lifetime=REQUEST_TIMEOUT)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []

    values: list[str] = []
    for answer in answers:
        if record_type == "MX":
            values.append(str(answer.exchange).rstrip(".").lower())
        elif record_type == "CNAME":
            values.append(str(answer.target).rstrip(".").lower())
        elif record_type in {"NS", "PTR"}:
            values.append(str(answer.target).rstrip(".").lower())
        elif record_type == "TXT":
            values.append(str(answer).strip('"'))
        else:
            values.append(str(answer))
    return sorted(set(values))


def _collect_dns_records(domain: str) -> dict[str, list[str]]:
    return {
        "A": _query_dns(domain, "A"),
        "AAAA": _query_dns(domain, "AAAA"),
        "MX": _query_dns(domain, "MX"),
        "NS": _query_dns(domain, "NS"),
        "TXT": _query_dns(domain, "TXT"),
        "CNAME": _query_dns(domain, "CNAME"),
    }


def _fetch_http_response(url: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "url": url,
        "reachable": False,
        "status_code": None,
        "final_url": url,
        "server": None,
        "content_type": None,
        "error": None,
    }
    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            headers={"User-Agent": "ProjectOverwatch/0.7 (passive domain intelligence)"},
        )
        result["reachable"] = True
        result["status_code"] = response.status_code
        result["final_url"] = response.url
        result["server"] = response.headers.get("Server")
        result["content_type"] = response.headers.get("Content-Type")
        result["headers"] = {key.lower(): value for key, value in response.headers.items()}
    except requests.RequestException as exc:
        result["error"] = str(exc)
    return result


def _assess_security_headers(headers: dict[str, str]) -> dict[str, dict[str, Any]]:
    assessment: dict[str, dict[str, Any]] = {}
    for header in COMMON_SECURITY_HEADERS:
        if header in headers:
            assessment[header] = {"present": True, "value": headers[header]}
        else:
            assessment[header] = {"present": False, "value": None}
    return assessment


def _collect_tls_details(domain: str) -> dict[str, Any]:
    details: dict[str, Any] = {
        "available": False,
        "issuer": None,
        "subject": None,
        "not_before": None,
        "not_after": None,
        "error": None,
    }
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                cert = secure_sock.getpeercert()
                details["available"] = True
                issuer_parts = dict(x[0] for x in cert.get("issuer", []))
                subject_parts = dict(x[0] for x in cert.get("subject", []))
                details["issuer"] = issuer_parts.get("organizationName") or issuer_parts.get("commonName")
                details["subject"] = subject_parts.get("commonName")
                not_before = cert.get("notBefore")
                not_after = cert.get("notAfter")
                if not_before:
                    details["not_before"] = _format_cert_date(not_before)
                if not_after:
                    details["not_after"] = _format_cert_date(not_after)
    except OSError as exc:
        details["error"] = str(exc)
    return details


def _format_cert_date(value: str) -> str:
    try:
        parsed = datetime.strptime(value, "%b %d %H:%M:%S %Y %Z")
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return value


def _check_wayback_availability(domain: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "available": False,
        "first_snapshot": None,
        "last_snapshot": None,
        "snapshot_count": 0,
        "error": None,
    }
    url = f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=1&fl=timestamp"
    try:
        response = requests.get(url, timeout=REQUEST_TIMEOUT)
        response.raise_for_status()
        payload = response.json()
        if len(payload) > 1:
            result["available"] = True
            result["snapshot_count"] = max(len(payload) - 1, 1)
            raw_first = payload[1][0]
            result["first_snapshot"] = raw_first
            result["first_snapshot_display"] = format_wayback_timestamp(raw_first)
        summary_url = f"https://web.archive.org/cdx/search/cdx?url={domain}&output=json&limit=1&fl=timestamp&sort=reverse"
        summary_response = requests.get(summary_url, timeout=REQUEST_TIMEOUT)
        summary_response.raise_for_status()
        summary_payload = summary_response.json()
        if len(summary_payload) > 1:
            raw_last = summary_payload[1][0]
            result["last_snapshot"] = raw_last
            result["last_snapshot_display"] = format_wayback_timestamp(raw_last)
    except (requests.RequestException, ValueError, IndexError) as exc:
        raw_error = str(exc)
        result["error"] = format_wayback_user_error(raw_error)
        result["error_detail"] = raw_error
    return result


def _build_findings(parsed_data: dict[str, Any]) -> list[str]:
    findings: list[str] = []
    https_headers = parsed_data.get("security_headers", {}).get("https", {})
    missing = [name for name, meta in https_headers.items() if not meta.get("present")]
    if missing:
        findings.append(f"Missing HTTPS security headers: {', '.join(missing)}")
    if parsed_data.get("tls", {}).get("available") and parsed_data["tls"].get("not_after"):
        findings.append(f"TLS certificate expires: {parsed_data['tls']['not_after']}")
    if parsed_data.get("wayback", {}).get("available"):
        findings.append("Wayback Machine snapshots are available for this domain.")
    return findings


def _build_raw_output(parsed_data: dict[str, Any]) -> str:
    lines = [f"Domain intelligence report for {parsed_data['domain']}", ""]
    lines.append("DNS records:")
    for record_type, values in parsed_data.get("dns", {}).items():
        if values:
            lines.append(f"  {record_type}: {', '.join(values)}")
        else:
            lines.append(f"  {record_type}: (none)")

    lines.append("")
    lines.append("HTTP/HTTPS:")
    for scheme in ("http", "https"):
        info = parsed_data.get("http", {}).get(scheme, {})
        if info.get("reachable"):
            lines.append(
                f"  {scheme.upper()} {info.get('status_code')} -> {info.get('final_url')} "
                f"server={info.get('server') or 'unknown'}"
            )
        else:
            lines.append(f"  {scheme.upper()} unreachable: {info.get('error') or 'unknown error'}")

    tls = parsed_data.get("tls", {})
    lines.append("")
    lines.append("TLS:")
    if tls.get("available"):
        lines.append(
            f"  issuer={tls.get('issuer')} subject={tls.get('subject')} "
            f"valid={tls.get('not_before')} -> {tls.get('not_after')}"
        )
    else:
        lines.append(f"  unavailable: {tls.get('error') or 'unknown error'}")

    wayback = parsed_data.get("wayback", {})
    lines.append("")
    lines.append("Wayback:")
    if wayback.get("available"):
        first = display_or_unavailable(
            wayback.get("first_snapshot_display")
            or format_wayback_timestamp(wayback.get("first_snapshot"))
        )
        last = display_or_unavailable(
            wayback.get("last_snapshot_display")
            or format_wayback_timestamp(wayback.get("last_snapshot"))
        )
        lines.append(f"  snapshots available; first={first}; last={last}")
    else:
        detail = wayback.get("error_detail") or wayback.get("error") or "none"
        lines.append(f"  no snapshots found ({detail})")

    return "\n".join(lines)


def run_domain_intel(target: str) -> dict[str, Any]:
    """Collect passive domain intelligence and return structured data."""
    original_input = target.strip()
    domain = normalize_domain(original_input)

    if not is_valid_domain(domain):
        return {
            "success": False,
            "errors": [f"Invalid domain or URL: {original_input}"],
            "parsed_data": {"domain": domain, "input": original_input},
            "raw_output": f"Error: invalid domain or URL: {original_input}",
            "findings": [],
        }

    dns_records = _collect_dns_records(domain)
    http_results = {
        "http": _fetch_http_response(f"http://{domain}"),
        "https": _fetch_http_response(f"https://{domain}"),
    }
    security_headers = {
        "https": _assess_security_headers(http_results["https"].get("headers", {}))
        if http_results["https"].get("headers")
        else {header: {"present": False, "value": None} for header in COMMON_SECURITY_HEADERS},
    }
    tls_details = _collect_tls_details(domain)
    wayback = _check_wayback_availability(domain)

    parsed_data: dict[str, Any] = {
        "domain": domain,
        "input": original_input,
        "dns": dns_records,
        "http": http_results,
        "security_headers": security_headers,
        "tls": tls_details,
        "wayback": wayback,
    }
    findings = _build_findings(parsed_data)
    raw_output = _build_raw_output(parsed_data)
    warnings: list[str] = []
    wayback = parsed_data.get("wayback", {})
    if wayback.get("error"):
        warnings.append(f"Wayback lookup unavailable: {wayback['error']}")
    has_core_data = any(
        parsed_data.get("dns", {}).get(record_type)
        for record_type in ("A", "AAAA", "MX", "NS", "TXT", "CNAME")
    ) or parsed_data.get("http", {}).get("https", {}).get("reachable")
    status = resolve_collection_status(warnings=warnings, has_core_data=bool(has_core_data))

    return {
        "success": True,
        "status": status,
        "parsed_data": parsed_data,
        "raw_output": raw_output,
        "findings": findings,
        "warnings": warnings,
        "errors": [],
    }

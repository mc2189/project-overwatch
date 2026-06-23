"""Discover pivot entities from module run results."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from utils.target_detection import get_target_type

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _unique(values: list[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        cleaned = value.strip()
        key = cleaned.lower()
        if not cleaned or key in seen:
            continue
        seen.add(key)
        ordered.append(cleaned)
    return ordered


def discover_pivots_from_results(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return pivot suggestions discovered in the latest run results."""
    pivots: list[dict[str, Any]] = []

    for result in results:
        if not result.get("success"):
            continue
        parsed = result.get("parsed_data") or {}
        module_id = result.get("module_id") or ""

        if module_id == "infra_cert_subdomain":
            for subdomain in parsed.get("subdomains") or []:
                pivots.append(
                    {
                        "pivot_type": "subdomain",
                        "value": str(subdomain),
                        "source_module": module_id,
                        "suggested_checks": ["infra_domain_intel", "infra_website_metadata"],
                    }
                )

        if module_id == "infra_domain_intel":
            dns = parsed.get("dns") or {}
            for record_type in ("A", "AAAA", "MX", "NS"):
                for value in dns.get(record_type) or []:
                    text = str(value).strip()
                    if record_type in {"A", "AAAA"} and _IPV4_RE.search(text):
                        pivots.append(
                            {
                                "pivot_type": "ip",
                                "value": text,
                                "source_module": module_id,
                                "suggested_checks": ["intel_abuseipdb", "intel_greynoise", "infra_whois_rdap"],
                            }
                        )
                    elif record_type == "NS":
                        pivots.append(
                            {
                                "pivot_type": "nameserver",
                                "value": text,
                                "source_module": module_id,
                                "suggested_checks": ["infra_whois_rdap"],
                            }
                        )
                    elif record_type == "MX":
                        pivots.append(
                            {
                                "pivot_type": "mail_server",
                                "value": text,
                                "source_module": module_id,
                                "suggested_checks": ["infra_email_security"],
                            }
                        )

        if module_id == "infra_email_security":
            for mx in parsed.get("mx") or []:
                host = mx.get("exchange") or mx.get("host") or mx.get("value")
                if host:
                    pivots.append(
                        {
                            "pivot_type": "mail_server",
                            "value": str(host),
                            "source_module": module_id,
                            "suggested_checks": ["infra_whois_rdap"],
                        }
                    )

        if module_id == "intel_shodan":
            for hostname in parsed.get("hostnames") or []:
                pivots.append(
                    {
                        "pivot_type": "hostname",
                        "value": str(hostname),
                        "source_module": module_id,
                        "suggested_checks": ["infra_domain_intel", "intel_virustotal"],
                    }
                )
            for port in (parsed.get("ports") or [])[:8]:
                pivots.append(
                    {
                        "pivot_type": "service",
                        "value": f"tcp/{port}",
                        "source_module": module_id,
                        "suggested_checks": ["infra_tls_review", "infra_http_security"],
                    }
                )

        if module_id == "infra_http_security":
            final_url = (parsed.get("response") or {}).get("final_url")
            if final_url:
                pivots.append(
                    {
                        "pivot_type": "url",
                        "value": str(final_url),
                        "source_module": module_id,
                        "suggested_checks": ["infra_website_metadata", "intel_urlhaus"],
                    }
                )

        if module_id == "infra_tls_review":
            cert = parsed.get("certificate") or {}
            for san in cert.get("san_dns_names") or []:
                pivots.append(
                    {
                        "pivot_type": "subdomain",
                        "value": str(san),
                        "source_module": module_id,
                        "suggested_checks": ["infra_domain_intel"],
                    }
                )

    deduped: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for pivot in pivots:
        value = pivot.get("value", "")
        pivot_type = pivot.get("pivot_type", "unknown")
        if get_target_type(value) == "unknown" and pivot_type != "service":
            continue
        key = (pivot_type, value.lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(pivot)
    return deduped[:25]

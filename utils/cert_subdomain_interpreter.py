"""Advisory interpretation of passive certificate and subdomain intelligence results."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding

LARGE_SUBDOMAIN_THRESHOLD = 25


def interpret_cert_subdomain_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return cautious analyst findings from certificate transparency data."""
    findings: list[dict[str, Any]] = []
    domain = parsed_data.get("domain") or "target"
    subdomains = parsed_data.get("subdomains") or []
    warning = parsed_data.get("warning")
    wildcard_observed = parsed_data.get("wildcard_observed")
    source = parsed_data.get("source") or "certificate transparency"

    if warning and not subdomains:
        timeout = "timeout" in warning.lower() or "timed out" in warning.lower()
        title = "Certificate transparency source unavailable"
        explanation = (
            f"The public certificate transparency source ({source}) did not return names for {domain} in this run. "
            f"{warning} No certificate names were returned in this run — this does not prove the domain has no related names."
        )
        if timeout:
            explanation = (
                f"The public certificate transparency source ({source}) timed out for {domain}. "
                "No certificate names were returned in this run — this does not prove the domain has no related names."
            )
        findings.append(
            make_finding(
                title,
                "info",
                75,
                explanation,
                [
                    "Retry later if crt.sh or the public source was slow or temporarily unavailable.",
                    "Consider passive Domain Intelligence or manual review if certificate data is still needed.",
                    "Document that certificate-derived leads were not available for this run.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if subdomains:
        sample = ", ".join(subdomains[:8])
        if len(subdomains) > 8:
            sample += ", ..."
        findings.append(
            make_finding(
                "Subdomains discovered from public certificates",
                "info",
                85,
                f"{len(subdomains)} related public name(s) were observed for {domain} via {source}. "
                f"Examples include: {sample}. "
                "Certificate-derived names are leads for review; they do not confirm that a host is live or reachable.",
                [
                    "Review whether the discovered names are expected for this organisation.",
                    "Consider running Domain Intelligence on selected subdomains of interest.",
                    "Treat certificate-derived names as leads requiring verification.",
                ],
            )
        )

    if len(subdomains) >= LARGE_SUBDOMAIN_THRESHOLD:
        findings.append(
            make_finding(
                "Large number of public names observed",
                "low",
                80,
                f"{len(subdomains)} related names were observed in public certificate data for {domain}. "
                "A broad public footprint may warrant prioritised review.",
                [
                    "Prioritise review of unexpected or high-risk subdomain names.",
                    "Retire or remove DNS/certificate records for old systems if they are no longer required.",
                    "Document which names are in scope for follow-up investigation.",
                ],
            )
        )

    if wildcard_observed and subdomains:
        findings.append(
            make_finding(
                "Wildcard certificate names observed",
                "info",
                75,
                f"Wildcard certificate entries were observed while reviewing public certificate data for {domain}. "
                "Wildcard names can indicate shared infrastructure but do not prove additional live hosts.",
                [
                    "Review whether wildcard certificates match expected infrastructure patterns.",
                    "Correlate wildcard-related names with other observations before treating them as active assets.",
                    "Document whether wildcard coverage is expected for this domain.",
                ],
            )
        )

    return findings

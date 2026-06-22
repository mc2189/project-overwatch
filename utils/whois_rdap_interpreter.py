"""Advisory interpretation of WHOIS/RDAP lookup results."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding
from utils.whois_rdap_parser import days_until_expiry


def interpret_whois_rdap_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return cautious analyst findings from WHOIS/RDAP metadata."""
    findings: list[dict[str, Any]] = []
    target = parsed_data.get("domain_or_ip") or parsed_data.get("query_value") or "target"
    target_type = parsed_data.get("target_type") or "unknown"

    if parsed_data.get("private_local_ip"):
        findings.append(
            make_finding(
                "Private/local IP not applicable for public RDAP",
                "info",
                95,
                f"{target} is a private or local IPv4 address. Public RDAP allocation lookup is not applicable.",
                [
                    "Use Local Device / IP Check or active modules for on-network assessment.",
                    "Document that public registration metadata does not apply to this address.",
                ],
            )
        )
        return findings

    source = parsed_data.get("source") or "rdap"
    warning = parsed_data.get("warning")
    if warning or parsed_data.get("lookup_status") == "unavailable":
        findings.append(
            make_finding(
                "RDAP source unavailable",
                "info",
                70,
                f"Public RDAP lookup for {target} was unavailable or incomplete. "
                f"Observed detail: {warning or 'no response'}.",
                [
                    "Retry the lookup later if the registry endpoint timed out.",
                    "Registration data may be incomplete, redacted, or withheld by the registry.",
                    "Document the limitation in case notes.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        if not parsed_data.get("rdap_summary"):
            return findings

    rdap = parsed_data.get("rdap_summary") or {}
    if rdap or parsed_data.get("lookup_status") == "completed":
        findings.append(
            make_finding(
                "Registration metadata observed",
                "info",
                85,
                f"Public {source.upper()} metadata was observed for {target}. "
                "Registration and allocation fields are contextual metadata — they may be incomplete or redacted.",
                [
                    "Review registrar/registry, dates, status, and nameserver fields manually.",
                    "Do not treat registry metadata as proof of ownership or operational control.",
                    "Document whether the metadata matches case expectations.",
                ],
            )
        )

    registrar = rdap.get("registrar") or parsed_data.get("registrar")
    if registrar and (registrar.get("name") or registrar.get("handle")):
        label = registrar.get("name") or registrar.get("handle")
        findings.append(
            make_finding(
                "Registrar/registry observed",
                "info",
                82,
                f"A registrar or registry reference was observed for {target}: {label}.",
                [
                    "Confirm whether the registrar matches organisational expectations.",
                    "Registry data can lag behind transfers or privacy redaction.",
                    "Document whether the registrar is expected for this case.",
                ],
            )
        )

    expiration = (rdap.get("events") or {}).get("expiration")
    days_left = days_until_expiry(expiration)
    if expiration and days_left is not None:
        if days_left < 0:
            findings.append(
                make_finding(
                    "Domain expiry date in the past",
                    "medium",
                    80,
                    f"An expiration date of {expiration} was observed for {target}. "
                    "The date may reflect stale registry data or a lapsed registration.",
                    [
                        "Verify current registration status through additional sources if important to the case.",
                        "Do not assume the domain is unavailable without corroboration.",
                        "Document follow-up if expiry status matters to the investigation.",
                    ],
                )
            )
        elif days_left <= 30:
            findings.append(
                make_finding(
                    "Domain expiry approaching",
                    "low",
                    78,
                    f"An expiration date within approximately {days_left} days was observed for {target} "
                    f"({expiration}). This is a calendar observation, not confirmed operational impact.",
                    [
                        "Confirm whether renewal is expected for this domain.",
                        "Correlate with business context before treating this as a risk.",
                        "Document whether follow-up is required.",
                    ],
                )
            )
        else:
            findings.append(
                make_finding(
                    "Domain expiry date observed",
                    "info",
                    75,
                    f"An expiration date of {expiration} was observed for {target}.",
                    [
                        "Use expiry metadata as context only.",
                        "Registry dates may be approximate or redacted.",
                        "Document whether the date is relevant to the case.",
                    ],
                )
            )
    elif target_type in {"domain", "url"} and parsed_data.get("lookup_status") == "completed":
        findings.append(
            make_finding(
                "No expiry date observed",
                "info",
                70,
                f"No expiration date was present in the RDAP response for {target}. "
                "Some registries omit or redact expiry metadata.",
                [
                    "Do not assume the domain has no expiry date.",
                    "Use additional sources if expiry timing is critical.",
                    "Document the absence of expiry metadata in case notes.",
                ],
            )
        )

    abuse = rdap.get("abuse_contact") or parsed_data.get("abuse_contact")
    if abuse and (abuse.get("email") or abuse.get("name") or abuse.get("handle")):
        contact_label = abuse.get("email") or abuse.get("name") or abuse.get("handle")
        findings.append(
            make_finding(
                "Abuse contact observed",
                "info",
                80,
                f"A public abuse contact reference was observed for {target}: {contact_label}.",
                [
                    "Use abuse contacts only for authorised reporting workflows.",
                    "Verify contact details before external communication.",
                    "Document whether the contact is relevant to this case.",
                ],
            )
        )
    elif parsed_data.get("lookup_status") == "completed" and target_type in {"domain", "url", "ipv4"}:
        findings.append(
            make_finding(
                "No abuse contact observed",
                "info",
                68,
                f"No dedicated abuse contact was present in the {source.upper()} response for {target}.",
                [
                    "Absence of an abuse contact does not indicate malicious activity.",
                    "Some registries redact or omit contact metadata.",
                    "Document whether follow-up through other channels is required.",
                ],
            )
        )

    return findings

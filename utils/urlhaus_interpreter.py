"""Advisory interpretation of URLhaus Malware URL Intelligence results."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding

MISSING_KEY_MESSAGE = "URLhaus / abuse.ch Auth-Key is not configured."


def interpret_urlhaus_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return cautious analyst findings from URLhaus data."""
    findings: list[dict[str, Any]] = []
    target = parsed_data.get("lookup_value") or parsed_data.get("target") or "target"
    api = parsed_data.get("api") or {}
    query_status = str(parsed_data.get("query_status") or "").lower()

    if parsed_data.get("private_local_ip"):
        findings.append(
            make_finding(
                "Private/local IP not applicable for URLhaus",
                "info",
                90,
                "Private/local IP address — public URLhaus malware URL lookup is not applicable.",
                [
                    "Use other local or case context for private address review.",
                    "Run passive modules against related public hosts if needed.",
                ],
            )
        )
        return findings

    if api.get("error") == MISSING_KEY_MESSAGE or api.get("status_code") in {401, 403}:
        findings.append(
            make_finding(
                "URLhaus Auth-Key missing or rejected",
                "info",
                95,
                "URLhaus / abuse.ch Auth-Key is not configured or was rejected. "
                "Add ABUSECH_AUTH_KEY to your local .env file.",
                [
                    "Configure the key locally — it is never stored in the database.",
                    "Retry after updating .env and reloading the app.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if api.get("status_code") == 429:
        findings.append(
            make_finding(
                "URLhaus rate limit reached",
                "info",
                80,
                "URLhaus reported a rate limit for this lookup. "
                "This is an operational limitation, not a target risk indicator.",
                [
                    "Wait before retrying or reduce batch queue frequency.",
                    "Document the delay in case notes if follow-up is required.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if api.get("error") and query_status not in {"ok", "no_results"}:
        findings.append(
            make_finding(
                "URLhaus lookup unavailable",
                "info",
                75,
                f"URLhaus could not return a complete result for {target}. "
                f"Observed detail: {api.get('error')}.",
                [
                    "Confirm ABUSECH_AUTH_KEY is valid and within rate limits.",
                    "Retry the lookup later if the source timed out.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if parsed_data.get("output_capped"):
        findings.append(
            make_finding(
                "URLhaus returned large result set capped",
                "info",
                78,
                "URLhaus returned a large result set; displayed/stored entity output was capped for usability.",
                [
                    "Review collapsed raw data if a fuller URL list is required.",
                    "Treat capped samples as representative, not exhaustive.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    if query_status == "no_results":
        findings.append(
            make_finding(
                "No URLhaus results observed",
                "info",
                72,
                f"URLhaus returned no malware URL intelligence for {target}. "
                "Absence of URLhaus data is inconclusive — not confirmed safe status.",
                [
                    "Treat non-matches as one data point only.",
                    "Correlate with VirusTotal or other modules where useful.",
                ],
            )
        )
        return findings

    if query_status in {"invalid_url", "invalid_host"}:
        findings.append(
            make_finding(
                "URLhaus rejected lookup parameters",
                "info",
                70,
                f"URLhaus reported {query_status.replace('_', ' ')} for {target}.",
                [
                    "Verify the target format matches URLhaus expectations.",
                    "Try normalising the URL or host before retrying.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    lookup_type = parsed_data.get("lookup_type")
    if lookup_type == "url":
        url_status = str(parsed_data.get("url_status") or "unknown").lower()
        threat = parsed_data.get("threat")
        if url_status == "online":
            findings.append(
                make_finding(
                    "URLhaus reported active malware URL",
                    "medium",
                    80,
                    f"URLhaus reported {target} with status online"
                    + (f" and threat {threat}." if threat else ".")
                    + " Reported by URLhaus — not independently verified by Overwatch.",
                    [
                        "Do not visit or download content from the URL.",
                        "Correlate with VirusTotal and case context before escalation.",
                    ],
                )
            )
        elif url_status == "offline":
            findings.append(
                make_finding(
                    "URLhaus reported historical/offline malware URL",
                    "low",
                    76,
                    f"URLhaus reported {target} as an offline/historical malware URL entry. "
                    "Reported by URLhaus — offline status does not guarantee the host is safe.",
                    [
                        "Review date added and last online timestamps.",
                        "Treat as third-party historical intelligence only.",
                    ],
                )
            )
        else:
            findings.append(
                make_finding(
                    "URL reported by URLhaus",
                    "low",
                    74,
                    f"URLhaus returned malware URL intelligence for {target} "
                    f"(status: {url_status or 'unknown'}). "
                    "Reported by URLhaus — not independently verified by Overwatch.",
                    [
                        "Review threat, tags, and blacklist context in the module output.",
                        "Do not fetch payloads or visit the URL directly.",
                    ],
                )
            )
    else:
        active_count = int(parsed_data.get("active_url_count") or 0)
        offline_count = int(parsed_data.get("offline_url_count") or 0)
        url_count = int(parsed_data.get("url_count") or 0)
        if active_count > 0:
            findings.append(
                make_finding(
                    "Host reported by URLhaus with active malware URLs",
                    "medium",
                    79,
                    f"URLhaus reported host {target} with {active_count} active URL(s) "
                    f"of {url_count} total observed in URLhaus data. "
                    "Host-level matches do not mean every path on the host is malicious.",
                    [
                        "Review sampled URLs and threat tags in module output.",
                        "Correlate with domain intelligence and case context.",
                    ],
                )
            )
        elif url_count > 0:
            findings.append(
                make_finding(
                    "Host reported by URLhaus",
                    "low",
                    75,
                    f"URLhaus reported host {target} with {url_count} malware URL(s) "
                    f"({offline_count} offline/historical). "
                    "Reported by URLhaus — not independently verified by Overwatch.",
                    [
                        "Review sampled URLs and blacklist status.",
                        "Treat host matches as third-party intelligence only.",
                    ],
                )
            )
        else:
            findings.append(
                make_finding(
                    "URLhaus host data observed",
                    "info",
                    73,
                    f"URLhaus returned host intelligence for {target}. "
                    "Results are reported by URLhaus and require analyst review.",
                    [
                        "Review URL counts, tags, and blacklist metadata.",
                        "Correlate with other passive modules where useful.",
                    ],
                )
            )

    blacklist = parsed_data.get("blacklist_summary") or {}
    if any(str(value).lower() == "listed" for value in blacklist.values()):
        findings.append(
            make_finding(
                "URLhaus blacklist status observed",
                "low",
                72,
                "URLhaus metadata includes a listed blacklist status. "
                "Reported by URLhaus — blacklist context requires analyst review.",
                [
                    "Confirm which blacklist provider flagged the entry.",
                    "Do not treat blacklist status as confirmed malicious activity alone.",
                ],
            )
        )

    if not findings:
        findings.append(
            make_finding(
                "URLhaus data observed",
                "info",
                70,
                f"URLhaus returned malware URL intelligence for {target}. "
                "Results are reported by URLhaus and require analyst review.",
                [
                    "Review query status, threat, and tags in module output.",
                    "Correlate with other case evidence before escalation.",
                ],
            )
        )

    return findings

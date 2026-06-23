"""Advisory interpretation of AbuseIPDB Reputation Intelligence results."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding

MISSING_KEY_MESSAGE = "AbuseIPDB API key is not configured."


def _score_severity(score: int | None) -> tuple[str, int]:
    if score is None:
        return "info", 70
    if score >= 75:
        return "medium", 82
    if score >= 25:
        return "low", 78
    if score >= 1:
        return "info", 75
    return "info", 72


def interpret_abuseipdb_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return cautious analyst findings from AbuseIPDB data."""
    findings: list[dict[str, Any]] = []
    target = parsed_data.get("ip_address") or parsed_data.get("target") or "target"
    api = parsed_data.get("api") or {}

    if parsed_data.get("private_local_ip"):
        findings.append(
            make_finding(
                "Private/local IP not applicable for AbuseIPDB",
                "info",
                90,
                "Private/local IP address — public AbuseIPDB reputation lookup is not applicable.",
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
                "AbuseIPDB API key missing or rejected",
                "info",
                95,
                "AbuseIPDB API key is not configured or was rejected. "
                "Add ABUSEIPDB_API_KEY to your local .env file.",
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
                "AbuseIPDB rate limit reached",
                "info",
                80,
                "AbuseIPDB reported a rate limit for this lookup. "
                "This is an operational limitation, not a target risk indicator.",
                [
                    "Wait before retrying or reduce batch queue frequency.",
                    "Document the delay in case notes if follow-up is required.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if api.get("error") and parsed_data.get("abuse_confidence_score") is None:
        findings.append(
            make_finding(
                "AbuseIPDB lookup unavailable",
                "info",
                70,
                f"AbuseIPDB could not return a complete report for {target}. "
                f"Observed detail: {api.get('error')}.",
                [
                    "Confirm ABUSEIPDB_API_KEY is valid and within rate limits.",
                    "Retry the lookup later if the source timed out.",
                    "Document the limitation in case notes.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    score = parsed_data.get("abuse_confidence_score")
    reports = int(parsed_data.get("total_reports") or 0)
    users = parsed_data.get("num_distinct_users")

    if score is None and reports == 0:
        findings.append(
            make_finding(
                "AbuseIPDB returned no reputation data",
                "info",
                65,
                f"AbuseIPDB returned no abuse-confidence data for {target}. "
                "Absence of data is inconclusive, not benign.",
                [
                    "Retry later if the IP was recently reported elsewhere.",
                    "Correlate with other case evidence before drawing conclusions.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    severity, confidence = _score_severity(int(score) if score is not None else None)

    if reports == 0 and (score is None or int(score) == 0):
        findings.append(
            make_finding(
                "No AbuseIPDB reports observed",
                "info",
                75,
                f"AbuseIPDB reported no abuse reports for {target} in the queried window. "
                "This is reported third-party data only — not confirmed safe status.",
                [
                    "Treat clean AbuseIPDB results as one data point only.",
                    "Continue review using other modules and analyst context.",
                ],
            )
        )
    elif score is not None and int(score) >= 75:
        findings.append(
            make_finding(
                "High abuse confidence reported by AbuseIPDB",
                severity,
                confidence,
                f"AbuseIPDB reported a high abuse confidence score of {score} for {target} "
                f"({reports} total report(s), {users} distinct user(s)). "
                "These are third-party abuse reports — not confirmed malicious activity.",
                [
                    "Review AbuseIPDB report details and linked categories manually.",
                    "Correlate with other case evidence before escalation.",
                    "Document analyst assessment and any planned follow-up.",
                ],
            )
        )
    elif score is not None and int(score) >= 1:
        findings.append(
            make_finding(
                "Abuse confidence score observed",
                severity,
                confidence,
                f"AbuseIPDB reported an abuse confidence score of {score} for {target} "
                f"({reports} total report(s), {users} distinct user(s)). "
                "Reported by AbuseIPDB — treat as intelligence for review, not confirmed fact.",
                [
                    "Review whether the score aligns with other case context.",
                    "Consider WHOIS/RDAP or VirusTotal enrichment for the same IP.",
                    "Document analyst assessment in case notes.",
                ],
            )
        )
    else:
        findings.append(
            make_finding(
                "AbuseIPDB reputation data observed",
                "info",
                78,
                f"AbuseIPDB returned reputation metadata for {target} "
                f"({reports} total report(s), {users} distinct user(s)). "
                "Results are reported by AbuseIPDB and require analyst review.",
                [
                    "Review ISP, usage type, and country context.",
                    "Correlate with other passive modules where useful.",
                ],
            )
        )

    if parsed_data.get("is_whitelisted"):
        findings.append(
            make_finding(
                "AbuseIPDB whitelist flag reported",
                "info",
                70,
                f"AbuseIPDB reported a whitelist flag for {target}. "
                "Whitelist status is reported metadata only — not a security guarantee.",
                [
                    "Confirm whitelist context in the AbuseIPDB dashboard if relevant.",
                    "Do not treat whitelist status as proof of trustworthiness.",
                ],
            )
        )

    return findings

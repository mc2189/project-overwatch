"""Advisory interpretation of VirusTotal Reputation Intelligence results."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding


def _vendor_flag_severity(flagged: int, total: int) -> tuple[str, int]:
    if total <= 0:
        return "info", 65
    ratio = flagged / total
    if flagged >= 10 or ratio >= 0.25:
        return "medium", 82
    if flagged >= 3 or ratio >= 0.1:
        return "low", 78
    if flagged > 0:
        return "low", 75
    return "info", 72


def interpret_virustotal_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return cautious analyst findings from VirusTotal data."""
    findings: list[dict[str, Any]] = []
    target = parsed_data.get("target") or "target"
    target_type = parsed_data.get("target_type") or "unknown"
    stats = parsed_data.get("last_analysis_stats") or {}
    api = parsed_data.get("api") or {}

    if parsed_data.get("private_local_ip"):
        findings.append(
            make_finding(
                "Private/local IP not applicable for VirusTotal",
                "info",
                90,
                "Private/local IP address — public reputation lookup is not applicable.",
                [
                    "Use other local or case context for private address review.",
                    "Run passive modules against related public hosts if needed.",
                ],
            )
        )
        return findings

    if api.get("error") == "VirusTotal API key is not configured." or api.get("status_code") in {401, 403}:
        findings.append(
            make_finding(
                "VirusTotal API key missing or rejected",
                "info",
                95,
                "VirusTotal API key is not configured or was rejected. "
                "Add VIRUSTOTAL_API_KEY to your local .env file.",
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
                "VirusTotal rate limit reached",
                "info",
                80,
                "VirusTotal reported a rate limit for this lookup. "
                "This is an operational limitation, not a target risk indicator.",
                [
                    "Wait before retrying or reduce batch queue frequency.",
                    "Document the delay in case notes if follow-up is required.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if api.get("error") and not stats:
        findings.append(
            make_finding(
                "VirusTotal lookup unavailable",
                "info",
                70,
                f"VirusTotal could not return a complete report for {target}. "
                f"Observed detail: {api.get('error')}.",
                [
                    "Confirm VIRUSTOTAL_API_KEY is valid and within rate limits.",
                    "Retry the lookup later if the source timed out.",
                    "Document the limitation in case notes.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    malicious = int(stats.get("malicious") or 0)
    suspicious = int(stats.get("suspicious") or 0)
    harmless = int(stats.get("harmless") or 0)
    undetected = int(stats.get("undetected") or 0)
    timeout = int(stats.get("timeout") or 0)
    total = malicious + suspicious + harmless + undetected + timeout
    flagged = malicious + suspicious

    if total == 0:
        findings.append(
            make_finding(
                "VirusTotal returned no data",
                "info",
                65,
                f"VirusTotal returned no engine analysis counts for this {target_type} ({target}). "
                "The resource may be newly submitted or not yet analysed.",
                [
                    "Retry the lookup after analysis completes if a URL was just submitted.",
                    "Treat absence of stats as inconclusive, not benign.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    severity, confidence = _vendor_flag_severity(flagged, total)

    if flagged > 0:
        findings.append(
            make_finding(
                "Security vendor flags reported by VirusTotal",
                severity,
                confidence,
                f"VirusTotal reported {malicious} malicious and {suspicious} suspicious security vendor "
                f"result(s) for {target} (harmless={harmless}, undetected={undetected}). "
                "These are third-party reputation signals — not confirmed compromise.",
                [
                    "Review the VirusTotal report and linked submissions manually.",
                    "Correlate with other case evidence before escalation.",
                    "Document analyst assessment and any planned follow-up.",
                ],
            )
        )
    else:
        findings.append(
            make_finding(
                "No security vendor flags reported by VirusTotal",
                "info",
                75,
                f"VirusTotal reported no malicious or suspicious security vendor flags for {target} "
                f"(harmless={harmless}, undetected={undetected}). "
                "Clean counts are reported results only — not confirmed safe status.",
                [
                    "Treat clean third-party counts as one data point only.",
                    "Continue review using other modules and analyst context.",
                ],
            )
        )

    reputation = parsed_data.get("reputation")
    if isinstance(reputation, int):
        findings.append(
            make_finding(
                "Reputation data observed (VirusTotal)",
                "info",
                68,
                f"VirusTotal community reputation score for {target} is {reputation}. "
                "Community votes are contextual signals reported by VirusTotal.",
                [
                    "Review community comments in VirusTotal with caution.",
                    "Correlate reputation with engine detections and case scope.",
                ],
            )
        )

    return findings

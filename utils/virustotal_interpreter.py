"""Advisory interpretation of VirusTotal lookup results."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding


def interpret_virustotal_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return cautious analyst findings from VirusTotal data."""
    findings: list[dict[str, Any]] = []
    target = parsed_data.get("target") or "target"
    target_type = parsed_data.get("target_type") or "unknown"
    stats = parsed_data.get("last_analysis_stats") or {}
    api = parsed_data.get("api") or {}

    if api.get("error"):
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
    total = malicious + suspicious + harmless + undetected

    if total == 0:
        findings.append(
            make_finding(
                "No VirusTotal analysis stats available",
                "info",
                65,
                f"VirusTotal returned no engine analysis counts for this {target_type} ({target}). "
                "The resource may be newly submitted or not yet analysed.",
                [
                    "Retry the lookup after analysis completes if a URL was just submitted.",
                    "Treat absence of stats as inconclusive, not benign.",
                    "Document whether follow-up is required.",
                ],
            )
        )
        return findings

    if malicious > 0:
        findings.append(
            make_finding(
                "VirusTotal engines flagged malicious",
                "high",
                88,
                f"VirusTotal reported {malicious} malicious and {suspicious} suspicious detections "
                f"for {target} (harmless={harmless}, undetected={undetected}). "
                "This indicates third-party engines associated malicious or suspicious labels — "
                "not confirmed compromise.",
                [
                    "Review the full VirusTotal report and linked sandbox submissions manually.",
                    "Correlate with other case evidence before escalation.",
                    "Document analyst assessment and any planned follow-up.",
                ],
            )
        )
    elif suspicious > 0:
        findings.append(
            make_finding(
                "VirusTotal engines flagged suspicious",
                "medium",
                80,
                f"VirusTotal reported {suspicious} suspicious detections for {target} "
                f"(malicious={malicious}, harmless={harmless}, undetected={undetected}). "
                "Suspicious labels are leads for review, not confirmed threats.",
                [
                    "Review engine comments and related submissions in VirusTotal.",
                    "Correlate suspicious counts with other passive and active case data.",
                    "Document whether the finding is expected or needs follow-up.",
                ],
            )
        )
    else:
        findings.append(
            make_finding(
                "No malicious VirusTotal detections observed",
                "info",
                75,
                f"VirusTotal reported no malicious or suspicious engine detections for {target} "
                f"(harmless={harmless}, undetected={undetected}). "
                "Clean counts do not prove the target is safe or in scope.",
                [
                    "Treat clean third-party counts as one data point only.",
                    "Continue review using other modules and analyst context.",
                    "Document whether the result matches expectations.",
                ],
            )
        )

    reputation = parsed_data.get("reputation")
    if isinstance(reputation, int) and reputation < 0:
        findings.append(
            make_finding(
                "Negative VirusTotal community reputation",
                "medium",
                72,
                f"VirusTotal community reputation score for {target} is {reputation}. "
                "Community votes are contextual signals, not verified intelligence.",
                [
                    "Review community comments in VirusTotal with caution.",
                    "Correlate reputation with engine detections and case scope.",
                    "Document analyst assessment.",
                ],
            )
        )

    return findings

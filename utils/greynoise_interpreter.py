"""Advisory interpretation of GreyNoise Internet Noise Intelligence results."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding

MISSING_KEY_WARNING = (
    "GreyNoise API key is not configured. Community lookup may be limited or unavailable."
)


def _classification_severity(classification: str | None, *, noise: bool) -> tuple[str, int]:
    cleaned = (classification or "").strip().lower()
    if cleaned == "malicious" and noise:
        return "medium", 80
    if cleaned in {"malicious", "suspicious"}:
        return "low", 78
    if noise:
        return "low", 75
    return "info", 72


def interpret_greynoise_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return cautious analyst findings from GreyNoise data."""
    findings: list[dict[str, Any]] = []
    target = parsed_data.get("ip_address") or parsed_data.get("target") or "target"
    api = parsed_data.get("api") or {}

    if parsed_data.get("private_local_ip"):
        findings.append(
            make_finding(
                "Private/local IP not applicable for GreyNoise",
                "info",
                90,
                "Private/local IP address — public GreyNoise internet-noise lookup is not applicable.",
                [
                    "Use other local or case context for private address review.",
                    "Run passive modules against related public hosts if needed.",
                ],
            )
        )
        return findings

    if api.get("status_code") == 429:
        findings.append(
            make_finding(
                "GreyNoise rate limit reached",
                "info",
                80,
                "GreyNoise reported a rate limit for this lookup. "
                "This is an operational limitation, not a target risk indicator.",
                [
                    "Wait before retrying or reduce batch queue frequency.",
                    "Document the delay in case notes if follow-up is required.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if api.get("status_code") in {401, 403} and api.get("authenticated"):
        findings.append(
            make_finding(
                "GreyNoise API key rejected",
                "info",
                95,
                "GreyNoise rejected the configured API key. Check GREYNOISE_API_KEY in your local .env file.",
                [
                    "Configure a valid key locally — it is never stored in the database.",
                    "Retry after updating .env and reloading the app.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    noise = parsed_data.get("noise")
    riot = parsed_data.get("riot")
    classification = parsed_data.get("classification")
    name = parsed_data.get("name")
    message = parsed_data.get("message")

    if riot:
        findings.append(
            make_finding(
                "IP appears in RIOT/benign common service data reported by GreyNoise",
                "info",
                82,
                f"GreyNoise reported {target} in RIOT data"
                + (f" as {name}." if name else ".")
                + " RIOT entries describe known common business services — not a security guarantee.",
                [
                    "Confirm the service is expected for your investigation context.",
                    "Treat RIOT classification as third-party context only.",
                ],
            )
        )

    if noise:
        severity, confidence = _classification_severity(
            str(classification) if classification is not None else None,
            noise=True,
        )
        findings.append(
            make_finding(
                "IP observed as internet noise by GreyNoise",
                severity,
                confidence,
                f"GreyNoise reported {target} as internet noise"
                + (f" with classification {classification}." if classification else ".")
                + " Reported by GreyNoise — scanning/noise context requires analyst review, not automatic escalation.",
                [
                    "Review GreyNoise visualizer link and case context before escalation.",
                    "Correlate with VirusTotal, AbuseIPDB, or Nmap results where useful.",
                ],
            )
        )
    elif noise is False and not riot:
        detail = message or "GreyNoise returned no internet-noise or RIOT match for this IP."
        findings.append(
            make_finding(
                "IP not observed as internet noise by GreyNoise",
                "info",
                75,
                f"{detail} Absence of noise is reported third-party data only — not confirmed safe status.",
                [
                    "Treat non-noise results as one data point only.",
                    "Continue review using other modules and analyst context.",
                ],
            )
        )
    elif not findings:
        findings.append(
            make_finding(
                "GreyNoise internet-noise data observed",
                "info",
                70,
                f"GreyNoise returned community metadata for {target}. "
                "Results are reported by GreyNoise and require analyst review.",
                [
                    "Review classification, RIOT/noise flags, and last-seen date.",
                    "Correlate with other passive modules where useful.",
                ],
            )
        )

    if not api.get("authenticated"):
        findings.append(
            make_finding(
                "GreyNoise key missing or unauthenticated lookup",
                "info",
                85,
                MISSING_KEY_WARNING,
                [
                    "Add GREYNOISE_API_KEY to .env for authenticated community lookups.",
                    "Unauthenticated lookups may be rate-limited or incomplete.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    return findings

"""Advisory interpretation of passive domain email security posture results."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding


def interpret_email_security_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return cautious analyst findings from email security DNS review."""
    findings: list[dict[str, Any]] = []
    domain = parsed_data.get("domain") or parsed_data.get("target") or "target"
    spf = parsed_data.get("spf") or {}
    dmarc = parsed_data.get("dmarc") or {}
    mx = parsed_data.get("mx") or []
    caa = parsed_data.get("caa") or []
    mta_sts = parsed_data.get("mta_sts") or {}
    tls_rpt = parsed_data.get("tls_rpt") or {}
    bimi = parsed_data.get("bimi") or {}
    warning = parsed_data.get("warning")

    if warning and "MTA-STS" in warning:
        findings.append(
            make_finding(
                "MTA-STS policy file unavailable",
                "info",
                75,
                f"{warning} This does not confirm mail transport is insecure — only that the "
                "published MTA-STS policy file could not be retrieved in this passive review.",
                [
                    "Retry later or verify MTA-STS hosting separately if relevant to the case.",
                    "Treat as a lookup limitation unless corroborated by other evidence.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    if spf.get("present"):
        policy = spf.get("policy") or "unknown"
        severity = "info"
        explanation = (
            f"A public SPF TXT record was observed for {domain} with terminal policy {policy!r}. "
            "SPF records describe which senders may be authorised to send mail for the domain — "
            "they do not prove messages cannot be spoofed and were not independently verified by Overwatch."
        )
        if policy == "+all":
            severity = "medium"
            explanation = (
                f"A public SPF TXT record was observed for {domain} with permissive +all policy. "
                "This may allow any sender to pass SPF checks and should be reviewed by a human. "
                "Overwatch did not send email or test inboxes."
            )
        elif policy == "?all":
            severity = "low"
        elif policy == "~all":
            severity = "low"
        findings.append(
            make_finding(
                "SPF record observed",
                severity,
                85,
                explanation,
                [
                    "Review whether the SPF mechanisms match expected authorised senders.",
                    "Correlate with DMARC policy before drawing conclusions about spoofing risk.",
                ],
            )
        )
        if spf.get("many_includes"):
            findings.append(
                make_finding(
                    "SPF record has many include mechanisms",
                    "low",
                    70,
                    f"The SPF record for {domain} includes {spf.get('include_count')} include mechanism(s). "
                    "Complex SPF records may be harder to maintain and can approach DNS lookup limits.",
                    [
                        "Review include chains and redirects during mail posture assessment.",
                        "Consider simplification if the record is operationally brittle.",
                    ],
                )
            )
    else:
        findings.append(
            make_finding(
                "SPF public DNS record not observed",
                "low",
                80,
                f"No SPF TXT record (v=spf1) was observed in public DNS for {domain} during this review. "
                "Absence in this lookup does not prove SPF is not configured elsewhere or on a parent zone.",
                [
                    "Confirm whether the domain is expected to send email.",
                    "Review DMARC and MX records for additional mail posture context.",
                ],
            )
        )

    if dmarc.get("present"):
        policy = (dmarc.get("policy") or "unknown").lower()
        severity = "info"
        title = "DMARC record observed"
        if policy == "none":
            severity = "low"
            title = "DMARC policy set to none"
            explanation = (
                f"A public DMARC TXT record was observed for {domain} with p=none. "
                "This is an advisory/monitoring posture and does not enforce rejection or quarantine by itself."
            )
        elif policy == "quarantine":
            explanation = (
                f"A public DMARC TXT record was observed for {domain} with p=quarantine. "
                "This indicates a quarantine enforcement policy in DMARC data — not independently verified by Overwatch."
            )
        elif policy == "reject":
            title = "DMARC enforcement policy observed"
            explanation = (
                f"A public DMARC TXT record was observed for {domain} with p=reject. "
                "This indicates a reject enforcement policy in DMARC data — not independently verified by Overwatch."
            )
        else:
            explanation = (
                f"A public DMARC TXT record was observed for {domain} (p={policy}). "
                "DMARC policy values are reported from public DNS only."
            )
        findings.append(
            make_finding(
                title,
                severity,
                85,
                explanation,
                [
                    "Review rua/ruf reporting addresses if present.",
                    "Correlate with SPF alignment settings (adkim/aspf) during human review.",
                ],
            )
        )
        if not dmarc.get("rua_present"):
            findings.append(
                make_finding(
                    "DMARC aggregate reporting not observed",
                    "low",
                    75,
                    f"The DMARC record for {domain} does not declare an rua reporting URI in this lookup. "
                    "Aggregate reporting helps monitor spoofing attempts but may be configured elsewhere.",
                    [
                        "Confirm whether DMARC reporting is expected for this domain.",
                        "Document that no rua URI was observed in public DNS.",
                    ],
                )
            )
        pct = dmarc.get("pct")
        if pct is not None and pct < 100:
            findings.append(
                make_finding(
                    "DMARC partial enforcement percentage observed",
                    "info",
                    75,
                    f"The DMARC record for {domain} sets pct={pct}, meaning policy may apply to a subset of messages.",
                    [
                        "Review whether partial enforcement is intentional during rollout.",
                        "Monitor aggregate reports if available.",
                    ],
                )
            )
    else:
        findings.append(
            make_finding(
                "DMARC public DNS record not observed",
                "low",
                80,
                f"No DMARC TXT record (v=DMARC1) was observed at _dmarc.{domain} during this passive DNS review. "
                "This does not prove DMARC is absent on all mail streams or parent domains.",
                [
                    "Review whether the domain sends email that could be spoofed.",
                    "Consider SPF and MX posture alongside this advisory finding.",
                ],
            )
        )

    if mx:
        hostnames = ", ".join(item.get("hostname", "") for item in mx[:5])
        suffix = "..." if len(mx) > 5 else ""
        findings.append(
            make_finding(
                "MX records observed",
                "info",
                85,
                f"{len(mx)} MX record(s) were observed for {domain}: {hostnames}{suffix}. "
                "MX hostnames indicate mail routing targets from public DNS only.",
                [
                    "Verify whether listed mail hosts match expected providers.",
                    "Do not infer provider security solely from hostnames.",
                ],
            )
        )
    else:
        findings.append(
            make_finding(
                "No MX records observed",
                "low",
                80,
                f"No MX records were observed in public DNS for {domain}. "
                "The domain may not receive email, use non-standard routing, or DNS may be incomplete in this lookup.",
                [
                    "Confirm whether the domain is expected to receive email.",
                    "Review SPF/DMARC only if outbound mail is in scope.",
                ],
            )
        )

    if caa:
        tags = sorted({item.get("tag") for item in caa if item.get("tag")})
        findings.append(
            make_finding(
                "CAA records observed",
                "info",
                80,
                f"CAA record(s) were observed for {domain} (tags: {', '.join(tags) or 'unknown'}). "
                "CAA records restrict which certificate authorities may issue certificates for the domain.",
                [
                    "Review whether CAA tags match expected certificate issuance policy.",
                    "Correlate with certificate intelligence if collected.",
                ],
            )
        )
    else:
        findings.append(
            make_finding(
                "CAA public DNS record not observed",
                "info",
                75,
                f"No CAA records were observed in public DNS for {domain}. "
                "Many domains omit CAA; absence is advisory and does not indicate misconfiguration by itself.",
                [
                    "Consider whether certificate issuance restrictions are expected for this domain.",
                    "Review certificate transparency data separately if relevant.",
                ],
            )
        )

    if mta_sts.get("txt_present"):
        mode = mta_sts.get("mode")
        if mode == "enforce":
            findings.append(
                make_finding(
                    "MTA-STS enforce mode observed",
                    "info",
                    80,
                    f"MTA-STS TXT and policy data for {domain} indicate mode=enforce. "
                    "This is reported from public DNS/HTTPS policy fetch only.",
                    [
                        "Verify policy mx patterns match expected mail infrastructure.",
                        "Confirm policy max_age and update processes operationally.",
                    ],
                )
            )
        elif mode == "testing":
            findings.append(
                make_finding(
                    "MTA-STS testing mode observed",
                    "low",
                    75,
                    f"MTA-STS policy for {domain} indicates mode=testing. "
                    "Testing mode does not enforce TLS requirements for inbound mail.",
                    [
                        "Review whether the domain is still rolling out MTA-STS.",
                        "Re-check when enforcement is expected.",
                    ],
                )
            )
        else:
            findings.append(
                make_finding(
                    "MTA-STS TXT record observed",
                    "info",
                    80,
                    f"An MTA-STS TXT record was observed for {domain}. "
                    f"Policy mode from HTTPS fetch: {mode or 'unavailable'}.",
                    [
                        "Retrieve and review the MTA-STS policy file if not already available.",
                        "Treat HTTPS fetch failures as lookup limitations.",
                    ],
                )
            )
    else:
        findings.append(
            make_finding(
                "MTA-STS public DNS record not observed",
                "info",
                75,
                f"No MTA-STS TXT record was observed at _mta-sts.{domain}. "
                "MTA-STS is optional and absence is advisory only.",
                [
                    "Review whether strict inbound TLS policy is expected for this domain.",
                    "Correlate with TLS-RPT if present.",
                ],
            )
        )

    if tls_rpt.get("present"):
        findings.append(
            make_finding(
                "TLS-RPT record observed",
                "info",
                80,
                f"A TLS-RPT TXT record was observed for {domain}. "
                "TLS-RPT enables reporting on TLS connectivity for mail transport.",
                [
                    "Review reporting URIs if declared.",
                    "Use alongside MTA-STS posture during human review.",
                ],
            )
        )
    else:
        findings.append(
            make_finding(
                "TLS-RPT public DNS record not observed",
                "info",
                70,
                f"No TLS-RPT TXT record was observed at _smtp._tls.{domain}. "
                "TLS-RPT is optional and absence is advisory only.",
                [
                    "Document that TLS reporting was not observed in public DNS.",
                    "Review MTA-STS posture if mail transport security is in scope.",
                ],
            )
        )

    if bimi.get("present"):
        findings.append(
            make_finding(
                "BIMI record observed",
                "info",
                75,
                f"A BIMI TXT record was observed for {domain}. "
                "BIMI declares brand logo indicators for supporting mail clients — logos/certs were not fetched.",
                [
                    "Review logo and VMC locations if declared.",
                    "Do not treat BIMI presence as a security control.",
                ],
            )
        )
    else:
        findings.append(
            make_finding(
                "BIMI public DNS record not observed",
                "info",
                65,
                f"No BIMI TXT record was observed at default._bimi.{domain}. "
                "BIMI is optional branding metadata and absence is informational only.",
                [
                    "No action required unless brand indicators are investigation scope.",
                ],
            )
        )

    return findings

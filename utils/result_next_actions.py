"""Per-result practical next-step suggestions."""

from __future__ import annotations

from typing import Any

from utils.next_actions import make_action
from utils.finding_interpreter import risk_findings


def suggest_result_action(result: dict[str, Any], *, target: str) -> dict[str, Any]:
    """Return one actionable next step for a concise result card."""
    module_id = result.get("module_id") or ""
    parsed = result.get("parsed_data") or {}
    risk = risk_findings(result.get("interpreter_findings") or [])

    if module_id == "infra_email_security":
        dmarc = (parsed.get("dmarc") or {}).get("present")
        if not dmarc or any("dmarc" in (f.get("title") or "").lower() for f in risk):
            return make_action(
                title="Review email security finding",
                reason="DMARC or SPF posture may need analyst review.",
                action_type="open_finding",
                priority="high",
                target=target,
                module_id=module_id,
                button_label="Review findings",
            )

    if module_id == "infra_cert_subdomain":
        subs = parsed.get("subdomains") or []
        if subs:
            return make_action(
                title="Add subdomains to queue",
                reason=f"{len(subs)} certificate-derived names discovered.",
                action_type="add_to_queue",
                priority="medium",
                target=(subs[0] if subs else target),
                module_id="infra_domain_intel",
                button_label="Add to queue",
            )

    if module_id in {"intel_virustotal", "intel_abuseipdb"} and result.get("success"):
        stats = (parsed.get("last_analysis_stats") or {}) if module_id == "intel_virustotal" else {}
        malicious = int(stats.get("malicious") or 0)
        score = parsed.get("abuse_confidence_score") if module_id == "intel_abuseipdb" else None
        if malicious == 0 and (score is None or int(score or 0) < 25):
            return make_action(
                title="Run Shodan exposure lookup",
                reason="Reputation signals are clean — check internet exposure next.",
                action_type="run_module",
                priority="medium",
                target=target,
                module_id="intel_shodan",
                button_label="Select Shodan",
            )

    if module_id == "infra_http_security" and risk:
        return make_action(
            title="Add HTTP findings to report",
            reason="Security header gaps were observed — include in client output.",
            action_type="create_report",
            priority="medium",
            target=target,
            button_label="Generate report",
        )

    if module_id == "infra_tls_review":
        cert = parsed.get("certificate") or {}
        days = cert.get("days_until_expiry")
        if days is not None and int(days) < 30:
            return make_action(
                title="Add TLS remediation note",
                reason=f"Certificate expires in {days} days.",
                action_type="add_note",
                priority="high",
                target=target,
                module_id=module_id,
                button_label="Add note",
            )

    if risk:
        top = risk[0]
        return make_action(
            title=f"Review: {top.get('title', 'Finding')[:50]}",
            reason=(top.get("explanation") or "Review interpreter finding.")[:100],
            action_type="open_finding",
            priority=top.get("severity", "medium"),
            target=target,
            module_id=module_id,
            button_label="Review finding",
        )

    if result.get("warnings"):
        return make_action(
            title="Review module warnings",
            reason=str(result["warnings"][0])[:100],
            action_type="no_action",
            priority="low",
            target=target,
            module_id=module_id,
            button_label="Info",
        )

    return make_action(
        title="No immediate follow-up",
        reason="Review details if this target remains in scope.",
        action_type="no_action",
        priority="low",
        target=target,
        module_id=module_id,
        button_label="Info",
    )

"""Standardised next-action schema and guardrail-aware suggestions."""

from __future__ import annotations

import hashlib
import re
from typing import Any

from database.db_setup import ACTIVE_FINDING_STATUSES, effective_finding_severity, list_findings
from database.engagements import get_engagement_for_case
from modules.module_registry import get_module, is_executable
from ui.constants import IMPLEMENTED_MODULE_IDS, MODULE_CARD_TITLES
from utils.assessment_goals import (
    GOAL_CUSTOM,
    GOAL_EMAIL_SPOOFING,
    GOAL_EVIDENCE_REVIEW,
    GOAL_EXTERNAL_EXPOSURE,
    GOAL_THREAT_REPUTATION,
    GOAL_WEBSITE_POSTURE,
)
from utils.module_compatibility import get_compatible_modules, get_incompatible_reason
from utils.module_testing_levels import get_module_testing_level, is_active_testing_level
from utils.operating_context import (
    CLIENT_ENGAGEMENT,
    PASSIVE_RESEARCH,
    PERSONAL_LAB,
    check_module_execution_guardrails,
)
from database.personal_lab import list_personal_lab_scope
from utils.pivot_discovery import discover_pivots_from_results
from utils.security import is_private_or_local_ip
from utils.service_discovery import build_http_url, scheme_for_classification, web_tls_service_rows
from utils.web_port_planner import is_private_ipv4_target
from utils.settings_manager import check_module_preflight, has_api_key
from utils.target_detection import get_target_type

ACTION_TYPES = frozenset(
    {
        "run_module",
        "add_to_queue",
        "open_entity",
        "open_finding",
        "review_evidence",
        "create_report",
        "update_scope",
        "add_lab_scope",
        "add_note",
        "no_action",
        "try_common_web_ports",
    }
)

_API_KEY_HINTS: dict[str, str] = {
    "intel_virustotal": "VIRUSTOTAL_API_KEY",
    "intel_abuseipdb": "ABUSEIPDB_API_KEY",
    "intel_shodan": "SHODAN_API_KEY",
    "intel_urlhaus": "ABUSECH_AUTH_KEY",
    "intel_greynoise": "GREYNOISE_API_KEY",
}

_DEFAULT_BUTTON_LABELS: dict[str, str] = {
    "run_module": "Select module",
    "add_to_queue": "Add to queue",
    "open_entity": "Open entity",
    "open_finding": "Open finding",
    "review_evidence": "Review evidence",
    "create_report": "Generate report",
    "update_scope": "Open engagements",
    "add_lab_scope": "Add lab scope",
    "add_note": "Add note",
    "no_action": "Info",
    "try_common_web_ports": "Try common web ports",
}


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9]+", "_", value.strip().lower()).strip("_")
    return cleaned[:48] or "action"


def make_action_id(action_type: str, title: str, *, target: str | None = None, module_id: str | None = None) -> str:
    parts = [action_type, module_id or "", target or "", title]
    digest = hashlib.sha256("|".join(parts).encode()).hexdigest()[:10]
    return f"{_slug(action_type)}_{digest}"


def make_action(
    *,
    title: str,
    reason: str,
    action_type: str,
    priority: str = "medium",
    target: str | None = None,
    entity_id: int | None = None,
    module_id: str | None = None,
    finding_id: int | None = None,
    goal_id: str | None = None,
    enabled: bool = True,
    blocked_reason: str | None = None,
    button_label: str | None = None,
    why_detail: str | None = None,
    action_id: str | None = None,
) -> dict[str, Any]:
    if action_type not in ACTION_TYPES:
        action_type = "no_action"
    resolved_id = action_id or make_action_id(action_type, title, target=target, module_id=module_id)
    module = get_module(module_id) if module_id else None
    return {
        "id": resolved_id,
        "title": title,
        "reason": reason,
        "priority": priority if priority in {"high", "medium", "low"} else "medium",
        "action_type": action_type,
        "target": target,
        "entity_id": entity_id,
        "module_id": module_id,
        "module_display_name": (
            MODULE_CARD_TITLES.get(module_id)
            or (module.display_name if module else None)
        ),
        "finding_id": finding_id,
        "goal_id": goal_id,
        "enabled": enabled and not blocked_reason,
        "blocked_reason": blocked_reason,
        "button_label": button_label or _DEFAULT_BUTTON_LABELS.get(action_type, "Go"),
        "why_detail": why_detail or reason,
    }


def _module_ran(module_id: str, latest_results: list[dict[str, Any]]) -> bool:
    return any(
        result.get("module_id") == module_id and result.get("success")
        for result in latest_results
    )


def _finding_titles(latest_results: list[dict[str, Any]], needle: str) -> list[str]:
    titles: list[str] = []
    needle_lower = needle.lower()
    for result in latest_results:
        for finding in result.get("interpreter_findings") or []:
            title = (finding.get("title") or "").lower()
            explanation = (finding.get("explanation") or "").lower()
            if needle_lower in title or needle_lower in explanation:
                titles.append(finding.get("title") or "Finding")
    return titles


def _api_key_block_reason(module_id: str) -> str | None:
    env_key = _API_KEY_HINTS.get(module_id)
    if not env_key:
        return None
    if has_api_key(env_key):
        return None
    return f"Add {env_key} to .env to enable this module."


def enrich_action_readiness(
    action: dict[str, Any],
    *,
    case_id: int,
    operating_context: str,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
    conn: Any | None = None,
) -> dict[str, Any]:
    """Apply guardrail and availability checks to a suggested action."""
    enriched = dict(action)
    action_type = enriched.get("action_type")
    module_id = enriched.get("module_id")
    target = (enriched.get("target") or "").strip()
    blocked: str | None = None

    if action_type in {"run_module", "add_to_queue"} and module_id:
        module = get_module(module_id)
        if module is None or not is_executable(module):
            blocked = f"{module_id} is not available in this release."
        elif target:
            target_type = get_target_type(target)
            incompatible = get_incompatible_reason(module, target_type)
            if incompatible:
                blocked = incompatible
        api_block = _api_key_block_reason(module_id)
        if api_block:
            enriched["action_type"] = "no_action"
            enriched["button_label"] = "Info"
            blocked = api_block
        elif module and target and is_active_testing_level(get_module_testing_level(module_id)):
            preflight = check_module_execution_guardrails(
                module_id,
                target,
                case_id=case_id,
                authorisation_confirmed=authorisation_confirmed,
                operating_context=operating_context,
                personal_lab_confirmed=personal_lab_confirmed,
                conn=conn,
            )
            if not preflight.get("allowed"):
                if operating_context == PASSIVE_RESEARCH:
                    blocked = "Switch to Personal Lab or Client Engagement for active modules."
                    enriched["button_label"] = "Switch context"
                    enriched["action_type"] = "no_action"
                elif operating_context == PERSONAL_LAB and not personal_lab_confirmed:
                    blocked = "Tick Personal Lab confirmation to continue."
                    enriched["button_label"] = "Needs confirmation"
                    enriched["action_type"] = "no_action"
                else:
                    blocked = preflight.get("blocked_reason") or "Active check blocked by guardrails."
            elif action_type == "add_to_queue" and module.mode == "active":
                blocked = "Active modules are not auto-queued — select the module and confirm in the run panel."
                enriched["action_type"] = "run_module"
                enriched["button_label"] = "Select module"
        elif module and action_type == "add_to_queue":
            preflight = check_module_preflight(module)
            if not preflight.get("ok"):
                blocked = preflight.get("reason") or "Module blocked by settings."

    if action_type == "add_lab_scope":
        if not personal_lab_confirmed and operating_context == PERSONAL_LAB:
            blocked = "Tick Personal Lab confirmation before adding lab scope."
        elif target and case_id is not None and conn is not None:
            from utils.engagement_guardrails import resolve_scope_match

            items = list_personal_lab_scope(case_id, conn=conn)
            if resolve_scope_match(target, items) is not None:
                blocked = "Target is already in Personal Lab scope."
                enriched["action_type"] = "no_action"

    if action_type == "try_common_web_ports":
        if operating_context == PASSIVE_RESEARCH:
            blocked = "Switch to Personal Lab or Client Engagement for active port probes."
            enriched["action_type"] = "no_action"
        elif operating_context == PERSONAL_LAB and not personal_lab_confirmed:
            blocked = "Tick Personal Lab confirmation to probe web ports."
            enriched["action_type"] = "no_action"
        elif operating_context == CLIENT_ENGAGEMENT and not authorisation_confirmed:
            blocked = "Confirm authorisation before probing web ports."
            enriched["action_type"] = "no_action"

    if action_type == "update_scope" and operating_context != CLIENT_ENGAGEMENT:
        enriched["why_detail"] = "Open Client Engagements to manage formal scope and ROE."

    if blocked:
        enriched["enabled"] = False
        enriched["blocked_reason"] = blocked
    else:
        enriched["enabled"] = True
        enriched["blocked_reason"] = None

    return enriched


def finalize_actions(
    actions: list[dict[str, Any]],
    *,
    case_id: int,
    operating_context: str,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
    conn: Any | None = None,
) -> list[dict[str, Any]]:
    return [
        enrich_action_readiness(
            action,
            case_id=case_id,
            operating_context=operating_context,
            personal_lab_confirmed=personal_lab_confirmed,
            authorisation_confirmed=authorisation_confirmed,
            conn=conn,
        )
        for action in actions
    ]


def suggest_next_actions(
    *,
    case_id: int,
    target: str,
    goal_id: str,
    target_profile: dict[str, Any],
    latest_results: list[dict[str, Any]] | None = None,
    operating_context: str = PASSIVE_RESEARCH,
    personal_lab_confirmed: bool = False,
    authorisation_confirmed: bool = False,
    conn: Any | None = None,
) -> list[dict[str, Any]]:
    """Return ordered, guardrail-aware next-best-action suggestions."""
    latest_results = latest_results or []
    cleaned = target.strip()
    target_type = get_target_type(cleaned) if cleaned else "unknown"
    compatible_ids = set(target_profile.get("compatible_module_ids") or [])
    entity_id = target_profile.get("entity_id")
    actions: list[dict[str, Any]] = []

    if not cleaned:
        return finalize_actions(
            [
                make_action(
                    title="Enter an investigation target",
                    reason="The workspace needs a target before it can recommend checks.",
                    action_type="no_action",
                    priority="high",
                )
            ],
            case_id=case_id,
            operating_context=operating_context,
            personal_lab_confirmed=personal_lab_confirmed,
            authorisation_confirmed=authorisation_confirmed,
            conn=conn,
        )

    if goal_id == GOAL_EVIDENCE_REVIEW:
        return finalize_actions(
            [
                make_action(
                    title="Open Evidence Locker",
                    reason="Review uploaded artefacts from the Evidence Locker.",
                    action_type="review_evidence",
                    priority="high",
                    button_label="Open evidence",
                )
            ],
            case_id=case_id,
            operating_context=operating_context,
            personal_lab_confirmed=personal_lab_confirmed,
            authorisation_confirmed=authorisation_confirmed,
            conn=conn,
        )

    if (
        operating_context == PERSONAL_LAB
        and not personal_lab_confirmed
        and any(is_active_testing_level(get_module_testing_level(mid)) for mid in compatible_ids)
    ):
        actions.append(
            make_action(
                title="Tick Personal Lab confirmation to continue",
                reason="One checkbox authorises safe active checks and auto-adds lab scope on run.",
                action_type="no_action",
                priority="high",
                target=cleaned,
                button_label="Needs confirmation",
            )
        )

    ran_module_ids = {
        result.get("module_id") for result in latest_results if result.get("success")
    }

    service_context = target_profile.get("service_context") or {}
    services = service_context.get("services") or []
    has_service_data = bool(target_profile.get("has_service_data") or services)
    if is_private_ipv4_target(cleaned) and conn is not None and not services:
        from utils.web_port_planner import build_service_context

        service_context = build_service_context(
            case_id, cleaned, conn=conn, latest_results=latest_results
        )
        services = service_context.get("services") or []
        has_service_data = bool(services)

    def _http_tls_unreachable(result: dict[str, Any]) -> bool:
        parsed = result.get("parsed_data") or {}
        module_id = result.get("module_id")
        if module_id == "infra_http_security":
            response = parsed.get("response") or {}
            return not response.get("success")
        if module_id == "infra_tls_review":
            conn_info = parsed.get("connection") or {}
            return not conn_info.get("success")
        return False

    if is_private_ipv4_target(cleaned):
        if any(_http_tls_unreachable(result) for result in latest_results):
            if "infra_nmap" not in ran_module_ids and "infra_nmap" in compatible_ids:
                actions.append(
                    make_action(
                        title="Run Network Service Check",
                        reason="HTTP/TLS did not respond — discover open ports and service hints first.",
                        action_type="run_module",
                        priority="high",
                        module_id="infra_nmap",
                        target=cleaned,
                        entity_id=entity_id,
                        button_label="Select module",
                    )
                )
            actions.append(
                make_action(
                    title="Try common web ports",
                    reason="Probe 80, 443, 8080, 8443, 8000, 8888 sequentially for reachability.",
                    action_type="try_common_web_ports",
                    priority="medium",
                    target=cleaned,
                    button_label="Try common web ports",
                )
            )
            actions.append(
                make_action(
                    title="Confirm host and port",
                    reason="Add a note if the target may be offline or firewalled.",
                    action_type="add_note",
                    priority="low",
                    target=cleaned,
                    button_label="Add note",
                )
            )
        elif not has_service_data:
            if "infra_nmap" not in ran_module_ids and "infra_nmap" in compatible_ids:
                actions.insert(
                    0,
                    make_action(
                        title="Run Network Service Check first",
                        reason="Local/private IP — service discovery identifies which HTTP/TLS checks make sense.",
                        action_type="run_module",
                        priority="high",
                        module_id="infra_nmap",
                        target=cleaned,
                        entity_id=entity_id,
                        button_label="Select module",
                    ),
                )
            actions.append(
                make_action(
                    title="Try common web ports",
                    reason="Optional sequential probe of common web ports before full HTTP/TLS review.",
                    action_type="try_common_web_ports",
                    priority="medium",
                    target=cleaned,
                    button_label="Try common web ports",
                )
            )
        else:
            for service in web_tls_service_rows(services)[:4]:
                port = int(service["port"])
                scheme = scheme_for_classification(service["classification"], port)
                url = build_http_url(cleaned, port, scheme=scheme)
                classification = service.get("classification")
                if classification in {"http_candidate", "https_candidate"}:
                    actions.append(
                        make_action(
                            title=f"HTTP review on port {port}",
                            reason=f"Discovered {service.get('service_name') or 'web'} service on {port}/tcp.",
                            action_type="run_module",
                            priority="high",
                            module_id="infra_http_security",
                            target=url,
                            button_label="Select HTTP review",
                        )
                    )
                if classification in {"https_candidate", "tls_candidate"}:
                    actions.append(
                        make_action(
                            title=f"TLS review on port {port}",
                            reason=f"Discovered TLS service on {port}/tcp.",
                            action_type="run_module",
                            priority="high",
                            module_id="infra_tls_review",
                            target=cleaned,
                            button_label="Select TLS review",
                            why_detail=f"Use port {port} in advanced TLS settings.",
                        )
                    )

    _reputation_modules = (
        ("intel_virustotal", "VirusTotal reputation"),
        ("intel_abuseipdb", "AbuseIPDB lookup"),
        ("intel_greynoise", "GreyNoise lookup"),
        ("intel_shodan", "Shodan exposure lookup"),
        ("intel_urlhaus", "URLhaus lookup"),
    )
    if target_type == "ipv4" and not is_private_or_local_ip(cleaned):
        for module_id, label in _reputation_modules:
            if module_id not in compatible_ids or module_id in ran_module_ids:
                continue
            api_block = _api_key_block_reason(module_id)
            if api_block:
                actions.append(
                    make_action(
                        title=f"Configure {label}",
                        reason=api_block,
                        action_type="no_action",
                        priority="medium",
                        module_id=module_id,
                        target=cleaned,
                        goal_id=GOAL_THREAT_REPUTATION,
                    )
                )
            else:
                actions.append(
                    make_action(
                        title=f"Run {label}",
                        reason="Public IP — passive reputation enrichment is often useful.",
                        action_type="run_module",
                        priority="medium",
                        module_id=module_id,
                        target=cleaned,
                        goal_id=GOAL_THREAT_REPUTATION,
                        button_label="Select module",
                    )
                )

    goal_modules = {
        "infra_email_security": (GOAL_EMAIL_SPOOFING, "Review email security posture"),
        "infra_http_security": (GOAL_WEBSITE_POSTURE, "Run HTTP header review"),
        "infra_tls_review": (GOAL_WEBSITE_POSTURE, "Run TLS configuration review"),
        "infra_shodan": (GOAL_EXTERNAL_EXPOSURE, "Run Shodan exposure lookup"),
        "infra_domain_intel": (GOAL_WEBSITE_POSTURE, "Run domain intelligence"),
        "infra_website_metadata": (GOAL_WEBSITE_POSTURE, "Run website metadata review"),
        "infra_cert_subdomain": (GOAL_WEBSITE_POSTURE, "Review certificate subdomains"),
    }
    for module_id, (suggested_goal, title) in goal_modules.items():
        if module_id not in compatible_ids or module_id in ran_module_ids:
            continue
        if (
            is_private_ipv4_target(cleaned)
            and not has_service_data
            and module_id in {"infra_http_security", "infra_tls_review"}
        ):
            continue
        if (
            is_private_ipv4_target(cleaned)
            and has_service_data
            and module_id in {"infra_http_security", "infra_tls_review"}
            and not any(
                row.get("classification") in {"http_candidate", "https_candidate", "tls_candidate"}
                for row in services
            )
        ):
            continue
        api_block = _api_key_block_reason(module_id)
        if api_block:
            actions.append(
                make_action(
                    title=f"Configure {MODULE_CARD_TITLES.get(module_id, module_id)}",
                    reason=api_block,
                    action_type="no_action",
                    priority="low",
                    module_id=module_id,
                    target=cleaned,
                )
            )
            continue
        actions.append(
            make_action(
                title=title,
                reason=f"Compatible with this {target_profile.get('target_type_label', 'target')}.",
                action_type="run_module",
                priority="medium",
                module_id=module_id,
                target=cleaned,
                entity_id=entity_id,
                goal_id=suggested_goal,
                button_label="Select module",
            )
        )

    if target_type in {"domain", "url"}:
        dmarc_findings = _finding_titles(latest_results, "dmarc")
        if dmarc_findings:
            actions.append(
                make_action(
                    title="Review missing DMARC finding",
                    reason=dmarc_findings[0],
                    action_type="open_finding",
                    priority="high",
                    target=cleaned,
                    button_label="Review findings",
                )
            )

    if conn is not None:
        db_findings = list_findings(case_id=case_id, conn=conn)
        for finding in db_findings:
            if (finding.get("status") or "open") not in ACTIVE_FINDING_STATUSES:
                continue
            severity = effective_finding_severity(finding)
            if severity not in {"critical", "high", "medium"}:
                continue
            actions.append(
                make_action(
                    title=f"Review {severity} finding: {finding.get('title', 'Finding')[:60]}",
                    reason=finding.get("explanation", "Open finding requires triage.")[:120],
                    action_type="open_finding",
                    priority="high" if severity in {"critical", "high"} else "medium",
                    finding_id=int(finding["id"]),
                    entity_id=finding.get("entity_id"),
                    target=cleaned,
                    button_label="Open finding",
                )
            )
            if len([a for a in actions if a.get("action_type") == "open_finding"]) >= 3:
                break

    if (
        operating_context == PERSONAL_LAB
        and target_profile.get("needs_lab_scope")
        and personal_lab_confirmed
    ):
        actions.insert(
            0,
            make_action(
                title="Add target to Personal Lab scope",
                reason="Auto-scope is unavailable for this module — add scope manually.",
                action_type="add_lab_scope",
                priority="high",
                target=cleaned,
                button_label="Add lab scope",
            ),
        )

    if operating_context == PASSIVE_RESEARCH and any(
        is_active_testing_level(get_module_testing_level(module_id))
        for module_id in compatible_ids
    ):
        actions.append(
            make_action(
                title="Switch to Personal Lab for active checks",
                reason="Active modules require Personal Lab or Client Engagement context.",
                action_type="no_action",
                priority="high",
                button_label="Info",
            )
        )

    engagement = get_engagement_for_case(case_id, conn=conn) if conn else get_engagement_for_case(case_id)
    if engagement is None and operating_context == CLIENT_ENGAGEMENT:
        actions.append(
            make_action(
                title="Link a client engagement",
                reason="Client Engagement mode requires a linked engagement on this case.",
                action_type="update_scope",
                priority="high",
                button_label="Open engagements",
            )
        )

    pivots = discover_pivots_from_results(latest_results)
    for pivot in pivots[:5]:
        module_id = (pivot.get("suggested_checks") or [None])[0]
        actions.append(
            make_action(
                title=f"Queue pivot: {pivot['value']}",
                reason=f"Discovered {pivot.get('pivot_type', 'entity')} from {pivot.get('source_module', 'run')}.",
                action_type="add_to_queue",
                priority="medium",
                target=pivot["value"],
                module_id=module_id,
                button_label="Add to queue",
                why_detail=f"Adds {module_id or 'module'} for `{pivot['value']}` to Batch Queue.",
            )
        )

    if latest_results:
        actions.append(
            make_action(
                title="Generate case report",
                reason="Summarise findings and evidence after completing checks.",
                action_type="create_report",
                priority="medium",
                button_label="Generate report",
            )
        )
        actions.append(
            make_action(
                title="Review evidence before report",
                reason="Confirm evidence locker contents and provenance.",
                action_type="review_evidence",
                priority="medium",
                button_label="Review evidence",
            )
        )
        actions.append(
            make_action(
                title="Review open findings",
                reason="Triage severity, dismiss false positives, and add analyst notes.",
                action_type="open_finding",
                priority="medium",
                button_label="Open findings",
            )
        )

    if target_type == "ipv4" and is_private_or_local_ip(cleaned) and "infra_nmap" in compatible_ids:
        if "infra_nmap" not in ran_module_ids and not any(
            action.get("module_id") == "infra_nmap" for action in actions
        ):
            actions.append(
                make_action(
                    title="Run network service check",
                    reason="Private/local IP — conservative port scan when authorised.",
                    action_type="run_module",
                    priority="high",
                    module_id="infra_nmap",
                    target=cleaned,
                    entity_id=entity_id,
                    button_label="Select module",
                )
            )

    priority_rank = {"high": 0, "medium": 1, "low": 2}
    actions.sort(key=lambda item: priority_rank.get(item.get("priority", "medium"), 1))

    seen_ids: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for action in actions:
        if action["id"] in seen_ids:
            continue
        seen_ids.add(action["id"])
        deduped.append(action)

    return finalize_actions(
        deduped[:14],
        case_id=case_id,
        operating_context=operating_context,
        personal_lab_confirmed=personal_lab_confirmed,
        authorisation_confirmed=authorisation_confirmed,
        conn=conn,
    )

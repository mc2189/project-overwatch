"""Passive WHOIS/RDAP registration and allocation intelligence for Project Overwatch."""

from __future__ import annotations

from typing import Any

from utils.module_sdk import build_module_result, normalise_result
from utils.result_status import STATUS_COMPLETED, STATUS_COMPLETED_WITH_WARNINGS, STATUS_PARTIAL, resolve_collection_status
from utils.target_detection import DOMAIN_PATTERN
from utils.whois_rdap_client import lookup_registration_metadata
from utils.whois_rdap_helpers import normalise_whois_rdap_target
from utils.whois_rdap_parser import parse_rdap_response, parse_whois_text

MODULE_ID = "infra_whois_rdap"


def _build_raw_output(parsed_data: dict[str, Any]) -> str:
    lines = [
        f"Target: {parsed_data.get('original_target')}",
        f"Query: {parsed_data.get('query_value')} ({parsed_data.get('target_type')})",
        f"Source: {parsed_data.get('source') or 'n/a'}",
        f"Lookup status: {parsed_data.get('lookup_status')}",
    ]
    if parsed_data.get("from_cache"):
        lines.append("Result served from case RDAP/WHOIS cache.")
    if parsed_data.get("private_local_ip"):
        lines.append("Result: private/local IP — public RDAP not applicable.")
        return "\n".join(lines)

    if parsed_data.get("warning"):
        lines.append(f"Warning: {parsed_data['warning']}")

    rdap = parsed_data.get("rdap_summary") or {}
    if rdap.get("handle"):
        lines.append(f"Handle: {rdap['handle']}")
    if rdap.get("status"):
        lines.append(f"Status: {', '.join(rdap['status'])}")
    events = rdap.get("events") or {}
    for key in ("registration", "last_changed", "expiration"):
        if events.get(key):
            lines.append(f"{key.replace('_', ' ').title()}: {events[key]}")
    if rdap.get("nameservers"):
        lines.append(f"Nameservers: {', '.join(rdap['nameservers'])}")
    registrar = rdap.get("registrar") or {}
    if registrar.get("name") or registrar.get("handle"):
        lines.append(f"Registrar: {registrar.get('name') or registrar.get('handle')}")
    if rdap.get("network_name"):
        lines.append(f"Network: {rdap['network_name']}")
    if rdap.get("country"):
        lines.append(f"Country: {rdap['country']}")
    abuse = rdap.get("abuse_contact") or {}
    if abuse.get("email") or abuse.get("name"):
        lines.append(f"Abuse contact: {abuse.get('email') or abuse.get('name')}")
    if (parsed_data.get("whois_fallback") or {}).get("whois_server"):
        lines.append(f"WHOIS server: {parsed_data['whois_fallback']['whois_server']}")
    return "\n".join(lines)


def _build_module_notes(parsed_data: dict[str, Any]) -> list[str]:
    if parsed_data.get("private_local_ip"):
        return ["Private/local IP address — public RDAP allocation lookup is not applicable."]
    rdap = parsed_data.get("rdap_summary") or {}
    notes: list[str] = []
    source = parsed_data.get("source") or "lookup"
    if parsed_data.get("from_cache"):
        notes.append("Result served from case RDAP/WHOIS cache.")
    if source == "whois":
        notes.append("Registration metadata collected via WHOIS fallback after RDAP was unavailable.")
    elif source == "rdap":
        notes.append("Registration metadata collected via public RDAP.")
    if (rdap.get("registrar") or {}).get("name"):
        notes.append(f"Registrar observed: {rdap['registrar']['name']}.")
    if rdap.get("nameservers"):
        notes.append(f"Nameservers observed: {', '.join(rdap['nameservers'][:5])}.")
    if not notes and parsed_data.get("lookup_status") == "completed":
        notes.append("Registration metadata collected — review structured output for details.")
    return notes


def run_whois_rdap_lookup(
    target: str,
    *,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Collect passive registration/allocation metadata via public RDAP."""
    options = options or {}
    normalised = normalise_whois_rdap_target(target)
    original_target = normalised["original_target"]
    query_value = normalised["query_value"]
    target_type = normalised["target_type"]
    domain_or_ip = normalised["domain_or_ip"]

    base_data: dict[str, Any] = {
        "original_target": original_target,
        "query_value": query_value,
        "target_type": target_type,
        "domain_or_ip": domain_or_ip,
        "private_local_ip": normalised["is_private_ip"],
        "source": None,
        "lookup_status": "blocked",
        "warning": None,
        "rdap_url": None,
        "rdap_summary": None,
        "raw_response": None,
        "whois_fallback": None,
        "from_cache": False,
    }

    if not normalised["is_valid"]:
        result = build_module_result(
            MODULE_ID,
            STATUS_PARTIAL,
            f"Unsupported or invalid target for WHOIS/RDAP lookup: {original_target}.",
            success=False,
            data=base_data,
            raw_output=f"Error: invalid target for WHOIS/RDAP: {original_target}",
            errors=[f"Unsupported target type: {target_type}"],
        )
        return normalise_result(result)

    if normalised["is_private_ip"]:
        base_data["lookup_status"] = "not_applicable"
        base_data["source"] = "system"
        summary = (
            f"Private/local IP address ({query_value}) — public RDAP allocation lookup is not applicable."
        )
        result = build_module_result(
            MODULE_ID,
            STATUS_COMPLETED,
            summary,
            success=True,
            data=base_data,
            raw_output=_build_raw_output(base_data),
            findings=_build_module_notes(base_data),
        )
        return normalise_result(result)

    if target_type in {"domain", "url"} and not DOMAIN_PATTERN.match(query_value):
        result = build_module_result(
            MODULE_ID,
            STATUS_PARTIAL,
            f"Invalid domain extracted from target: {original_target}.",
            success=False,
            data=base_data,
            raw_output=f"Error: invalid domain: {query_value}",
            errors=[f"Invalid domain: {query_value}"],
        )
        return normalise_result(result)

    lookup_type = "ipv4" if target_type == "ipv4" else "domain"
    lookup = lookup_registration_metadata(query_value, lookup_type, options=options)
    base_data["from_cache"] = bool(lookup.get("from_cache"))
    base_data["rdap_url"] = (lookup.get("meta") or {}).get("rdap_url")

    if lookup.get("lookup_status") == "unavailable":
        meta = lookup.get("meta") or {}
        whois_meta = lookup.get("whois_meta") or {}
        base_data["lookup_status"] = "unavailable"
        base_data["source"] = "rdap"
        base_data["warning"] = meta.get("error") or whois_meta.get("error") or "RDAP/WHOIS lookup unavailable."
        warnings = [base_data["warning"]]
        status = resolve_collection_status(warnings=warnings, has_core_data=False)
        summary = f"RDAP/WHOIS lookup unavailable for {domain_or_ip}."
        result = build_module_result(
            MODULE_ID,
            status,
            summary,
            success=False,
            data=base_data,
            raw_output=_build_raw_output(base_data),
            findings=_build_module_notes(base_data),
            warnings=warnings,
            errors=[base_data["warning"]],
        )
        return normalise_result(result)

    source = lookup.get("source") or "rdap"
    base_data["source"] = source
    base_data["lookup_status"] = "completed"
    warnings: list[str] = []
    if source == "whois":
        whois_meta = lookup.get("whois_meta") or {}
        whois_text = lookup.get("whois_text") or ""
        base_data["whois_fallback"] = whois_meta
        rdap_summary = parse_whois_text(
            whois_text,
            query_value=query_value,
            target_type=lookup_type,
        )
        base_data["rdap_summary"] = rdap_summary
        base_data["raw_response"] = {"whois_text_preview": whois_text[:8000]}
        warnings.append("RDAP was unavailable — WHOIS port-43 fallback was used for this run.")
    else:
        payload = lookup.get("payload") or {}
        rdap_summary = parse_rdap_response(payload, query_value=query_value, target_type=lookup_type)
        base_data["rdap_summary"] = rdap_summary
        base_data["raw_response"] = payload
        base_data["registrar"] = rdap_summary.get("registrar")
        base_data["abuse_contact"] = rdap_summary.get("abuse_contact")

    summary = f"WHOIS/RDAP metadata collected for {domain_or_ip} via {source.upper()}."
    status = STATUS_COMPLETED_WITH_WARNINGS if warnings else STATUS_COMPLETED
    result = build_module_result(
        MODULE_ID,
        status,
        summary,
        success=True,
        data=base_data,
        raw_output=_build_raw_output(base_data),
        findings=_build_module_notes(base_data),
        warnings=warnings,
    )
    return normalise_result(result)

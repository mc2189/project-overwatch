"""Passive certificate transparency and subdomain discovery for Project Overwatch."""

from __future__ import annotations

import json
from typing import Any
from urllib.parse import quote

import requests

from utils.target_detection import DOMAIN_PATTERN, get_target_type, normalize_target_value

MODULE_ID = "infra_cert_subdomain"
SOURCE_NAME = "crt.sh"
CRT_SH_URL = "https://crt.sh/"
REQUEST_TIMEOUT = 20
MAX_SUBDOMAINS = 100


def normalize_domain(value: str) -> str:
    """Normalise a domain name or URL to a lowercase hostname."""
    return normalize_target_value(value, get_target_type(value))


def is_valid_domain(domain: str) -> bool:
    return bool(domain) and bool(DOMAIN_PATTERN.match(domain))


def _clean_hostname(name: str) -> str:
    cleaned = name.strip().lower().rstrip(".")
    if cleaned.startswith("*."):
        cleaned = cleaned[2:]
    return cleaned


def _name_related_to_domain(name: str, domain: str) -> bool:
    return name == domain or name.endswith(f".{domain}")


def process_subdomain_names(raw_names: list[str], domain: str, *, limit: int = MAX_SUBDOMAINS) -> tuple[list[str], bool]:
    """Clean, deduplicate, and limit subdomain names related to the queried domain."""
    seen: set[str] = set()
    ordered: list[str] = []
    saw_wildcard = False

    for raw in raw_names:
        if not raw:
            continue
        if "*." in raw or raw.strip().startswith("*."):
            saw_wildcard = True
        for part in raw.replace(",", "\n").splitlines():
            cleaned = _clean_hostname(part)
            if not cleaned or not DOMAIN_PATTERN.match(cleaned):
                continue
            if not _name_related_to_domain(cleaned, domain):
                continue
            if cleaned in seen:
                continue
            seen.add(cleaned)
            ordered.append(cleaned)

    ordered.sort()
    return ordered[:limit], saw_wildcard


def _fetch_crt_sh_entries(domain: str) -> tuple[list[dict[str, Any]], str | None]:
    """Query crt.sh JSON output for certificate transparency names."""
    query = quote(f"%.{domain}", safe="")
    url = f"{CRT_SH_URL}?q={query}&output=json"

    try:
        response = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": "ProjectOverwatch/1.3 (passive certificate intelligence)"},
        )
    except requests.Timeout:
        return [], "Certificate transparency lookup timed out. crt.sh may be slow or unavailable."
    except requests.RequestException as exc:
        return [], f"Certificate transparency lookup failed: {exc}"

    if response.status_code == 429:
        return [], "crt.sh rate limited the request. Try again later."
    if response.status_code >= 500:
        return [], f"crt.sh returned server error {response.status_code}."
    if response.status_code != 200:
        return [], f"crt.sh returned unexpected status {response.status_code}."

    text = response.text.strip()
    if not text:
        return [], "crt.sh returned no certificate data for this domain."

    try:
        payload = response.json()
    except json.JSONDecodeError:
        return [], "crt.sh returned a non-JSON response. The source may be temporarily unavailable."

    if not isinstance(payload, list):
        return [], "crt.sh returned an unexpected response format."

    entries: list[dict[str, Any]] = []
    for item in payload:
        if isinstance(item, dict):
            entries.append(item)
    return entries, None


def _extract_certificates_and_names(
    entries: list[dict[str, Any]],
    domain: str,
) -> tuple[list[dict[str, Any]], list[str], bool]:
    certificates: list[dict[str, Any]] = []
    raw_names: list[str] = []
    saw_wildcard = False
    seen_cert_ids: set[str] = set()

    for entry in entries:
        cert_id = entry.get("id")
        cert_key = str(cert_id) if cert_id is not None else None
        if cert_key and cert_key in seen_cert_ids:
            continue
        if cert_key:
            seen_cert_ids.add(cert_key)

        name_value = entry.get("name_value") or entry.get("common_name") or ""
        if isinstance(name_value, str) and "*." in name_value:
            saw_wildcard = True

        names_in_cert: list[str] = []
        if isinstance(name_value, str):
            for part in name_value.splitlines():
                cleaned = _clean_hostname(part)
                if cleaned and _name_related_to_domain(cleaned, domain):
                    names_in_cert.append(cleaned)
                    raw_names.append(part.strip())

        common_name = entry.get("common_name")
        if isinstance(common_name, str):
            raw_names.append(common_name)
            cleaned_cn = _clean_hostname(common_name)
            if cleaned_cn and _name_related_to_domain(cleaned_cn, domain):
                names_in_cert.append(cleaned_cn)

        certificates.append(
            {
                "id": cert_id,
                "issuer": entry.get("issuer_name") or entry.get("issuer_ca_id"),
                "common_name": common_name,
                "names": sorted(set(names_in_cert)),
                "not_before": entry.get("not_before"),
                "not_after": entry.get("not_after"),
                "entry_timestamp": entry.get("entry_timestamp"),
            }
        )

    subdomains, wildcard_from_names = process_subdomain_names(raw_names, domain)
    return certificates, subdomains, saw_wildcard or wildcard_from_names


def _build_raw_output(data: dict[str, Any]) -> str:
    lines = [
        f"Certificate & subdomain intelligence for {data['domain']}",
        f"Source: {data.get('source', SOURCE_NAME)}",
        "",
    ]
    warning = data.get("warning")
    if warning:
        lines.append(f"Warning: {warning}")
        lines.append("")

    lines.append(f"Subdomains discovered: {len(data.get('subdomains', []))}")
    for name in data.get("subdomains", [])[:25]:
        lines.append(f"  - {name}")
    if len(data.get("subdomains", [])) > 25:
        lines.append(f"  ... and {len(data['subdomains']) - 25} more")

    lines.append("")
    lines.append(f"Certificate entries reviewed: {len(data.get('certificates', []))}")
    for cert in data.get("certificates", [])[:10]:
        lines.append(
            f"  - id={cert.get('id')} cn={cert.get('common_name')} "
            f"issuer={cert.get('issuer')} valid={cert.get('not_before')} -> {cert.get('not_after')}"
        )
    if len(data.get("certificates", [])) > 10:
        lines.append(f"  ... and {len(data['certificates']) - 10} more certificate entries")
    return "\n".join(lines)


def _build_module_notes(data: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    count = len(data.get("subdomains", []))
    if count:
        notes.append(f"{count} public name(s) observed in certificate transparency data.")
    if data.get("wildcard_observed"):
        notes.append("Wildcard certificate names were observed in the source data.")
    if data.get("warning"):
        notes.append(data["warning"])
    if data.get("truncated"):
        notes.append(f"Results limited to {MAX_SUBDOMAINS} names for usability.")
    return notes


def run_cert_subdomain_intel(target: str) -> dict[str, Any]:
    """Collect passive certificate/subdomain intelligence and return structured data."""
    original_target = target.strip()
    domain = normalize_domain(original_target)

    base_data = {
        "original_target": original_target,
        "domain": domain,
        "subdomains": [],
        "certificates": [],
        "source": SOURCE_NAME,
        "warning": None,
        "wildcard_observed": False,
        "truncated": False,
    }

    if not is_valid_domain(domain):
        return {
            "module_id": MODULE_ID,
            "success": False,
            "status": "error",
            "summary": f"Invalid domain or URL: {original_target}",
            "raw_output": f"Error: invalid domain or URL: {original_target}",
            "findings": [],
            "errors": [f"Invalid domain or URL: {original_target}"],
            "data": base_data,
        }

    entries, fetch_warning = _fetch_crt_sh_entries(domain)
    if fetch_warning:
        base_data["warning"] = fetch_warning
        return {
            "module_id": MODULE_ID,
            "success": True,
            "status": "completed",
            "summary": (
                f"Certificate transparency data was unavailable for {domain}. "
                f"{fetch_warning}"
            ),
            "raw_output": _build_raw_output(base_data),
            "findings": [fetch_warning],
            "errors": [fetch_warning],
            "data": base_data,
        }

    certificates, subdomains, wildcard_observed = _extract_certificates_and_names(entries, domain)
    truncated = len(subdomains) >= MAX_SUBDOMAINS
    base_data.update(
        {
            "subdomains": subdomains,
            "certificates": certificates,
            "wildcard_observed": wildcard_observed,
            "truncated": truncated,
        }
    )

    summary = (
        f"Passive certificate intelligence collected for {domain}: "
        f"{len(subdomains)} related name(s) observed from {SOURCE_NAME}."
    )
    if truncated:
        summary += f" Results limited to {MAX_SUBDOMAINS} names."

    return {
        "module_id": MODULE_ID,
        "success": True,
        "status": "completed",
        "summary": summary,
        "raw_output": _build_raw_output(base_data),
        "findings": _build_module_notes(base_data),
        "errors": [],
        "data": base_data,
    }

"""Passive domain email security posture review for Project Overwatch."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

import dns.exception
import dns.resolver
import requests

from utils.api_module_helpers import project_user_agent, request_timeout_seconds
from utils.result_status import resolve_collection_status
from utils.target_detection import DOMAIN_PATTERN, get_target_type, normalize_target_value

MODULE_ID = "infra_email_security"
REQUEST_TIMEOUT = 12
MAX_MTA_STS_REDIRECTS = 3
MAX_POLICY_BYTES = 16_384
MAX_TXT_DISPLAY = 512
SPF_INCLUDE_ADVISORY_THRESHOLD = 10


def normalize_domain(value: str) -> str:
    """Extract hostname from a domain or URL target."""
    cleaned = value.strip()
    if not cleaned:
        return ""
    target_type = get_target_type(cleaned)
    if target_type == "url":
        parsed = urlparse(cleaned if "://" in cleaned else f"https://{cleaned}")
        host = parsed.hostname or ""
        return host.lower().rstrip(".")
    return normalize_target_value(cleaned, "domain")


def is_valid_domain(domain: str) -> bool:
    return bool(domain) and bool(DOMAIN_PATTERN.match(domain))


def _query_txt(name: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=REQUEST_TIMEOUT)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []
    values: list[str] = []
    for answer in answers:
        if hasattr(answer, "strings"):
            parts = [part.decode("utf-8", errors="replace") for part in answer.strings]
            values.append("".join(parts))
        else:
            values.append(str(answer).strip('"'))
    return sorted(set(values))


def _query_mx(domain: str) -> list[dict[str, Any]]:
    try:
        answers = dns.resolver.resolve(domain, "MX", lifetime=REQUEST_TIMEOUT)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []
    records: list[dict[str, Any]] = []
    for answer in answers:
        records.append(
            {
                "priority": int(answer.preference),
                "hostname": str(answer.exchange).rstrip(".").lower(),
            }
        )
    return sorted(records, key=lambda item: (item["priority"], item["hostname"]))


def _query_caa(domain: str) -> list[dict[str, Any]]:
    try:
        answers = dns.resolver.resolve(domain, "CAA", lifetime=REQUEST_TIMEOUT)
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.NoNameservers, dns.exception.Timeout):
        return []
    except Exception:
        return []
    records: list[dict[str, Any]] = []
    for answer in answers:
        tag = answer.tag.decode("utf-8", errors="replace") if isinstance(answer.tag, bytes) else str(answer.tag)
        value = answer.value.decode("utf-8", errors="replace") if isinstance(answer.value, bytes) else str(answer.value)
        records.append({"flags": int(answer.flags), "tag": tag, "value": value})
    return records


def _truncate_text(value: str | None, limit: int = MAX_TXT_DISPLAY) -> str | None:
    if value is None:
        return None
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."


def _find_spf_record(txt_records: list[str]) -> str | None:
    for record in txt_records:
        if record.lower().startswith("v=spf1"):
            return record
    return None


def parse_spf_record(record: str | None) -> dict[str, Any]:
    parsed: dict[str, Any] = {
        "present": bool(record),
        "record": _truncate_text(record),
        "policy": "unknown",
        "includes": [],
        "redirect": None,
        "include_count": 0,
        "many_includes": False,
    }
    if not record:
        return parsed

    lowered = record.lower()
    for policy in ("-all", "~all", "?all", "+all"):
        if re.search(rf"(?:^|\s){re.escape(policy)}(?:\s|$)", lowered):
            parsed["policy"] = policy
            break

    includes = re.findall(r"(?:^|\s)include:([^\s]+)", record, flags=re.IGNORECASE)
    parsed["includes"] = includes
    parsed["include_count"] = len(includes)
    parsed["many_includes"] = len(includes) >= SPF_INCLUDE_ADVISORY_THRESHOLD

    redirect_match = re.search(r"(?:^|\s)redirect=([^\s]+)", record, flags=re.IGNORECASE)
    if redirect_match:
        parsed["redirect"] = redirect_match.group(1).rstrip(".")

    return parsed


def _find_dmarc_record(txt_records: list[str]) -> str | None:
    for record in txt_records:
        if record.lower().startswith("v=dmarc1"):
            return record
    return None


def parse_dmarc_record(record: str | None) -> dict[str, Any]:
    parsed: dict[str, Any] = {
        "present": bool(record),
        "record": _truncate_text(record),
        "policy": None,
        "subdomain_policy": None,
        "rua_present": False,
        "ruf_present": False,
        "pct": None,
        "adkim": None,
        "aspf": None,
    }
    if not record:
        return parsed

    def _tag(name: str) -> str | None:
        match = re.search(rf"(?:^|;)\s*{name}\s*=\s*([^;]+)", record, flags=re.IGNORECASE)
        return match.group(1).strip() if match else None

    parsed["policy"] = (_tag("p") or "").lower() or None
    parsed["subdomain_policy"] = (_tag("sp") or "").lower() or None
    parsed["rua_present"] = bool(_tag("rua"))
    parsed["ruf_present"] = bool(_tag("ruf"))
    pct = _tag("pct")
    if pct and pct.isdigit():
        parsed["pct"] = int(pct)
    parsed["adkim"] = _tag("adkim")
    parsed["aspf"] = _tag("aspf")
    return parsed


def _find_tagged_txt(txt_records: list[str], prefix: str) -> str | None:
    prefix_lower = prefix.lower()
    for record in txt_records:
        if record.lower().startswith(prefix_lower):
            return record
    return None


def parse_tls_rpt_record(record: str | None) -> dict[str, Any]:
    parsed: dict[str, Any] = {
        "present": bool(record),
        "record": _truncate_text(record),
        "reporting_uris": [],
    }
    if not record:
        return parsed
    match = re.search(r"rua\s*=\s*([^;]+)", record, flags=re.IGNORECASE)
    if match:
        parsed["reporting_uris"] = [item.strip() for item in match.group(1).split(",") if item.strip()]
    return parsed


def parse_bimi_record(record: str | None) -> dict[str, Any]:
    parsed: dict[str, Any] = {
        "present": bool(record),
        "record": _truncate_text(record),
        "logo_location": None,
        "vmc_location": None,
    }
    if not record:
        return parsed

    def _tag(name: str) -> str | None:
        match = re.search(rf"(?:^|;)\s*{name}\s*=\s*([^;]+)", record, flags=re.IGNORECASE)
        return match.group(1).strip() if match else None

    parsed["logo_location"] = _tag("l")
    parsed["vmc_location"] = _tag("a")
    return parsed


def parse_mta_sts_txt(record: str | None) -> dict[str, Any]:
    parsed: dict[str, Any] = {
        "txt_present": bool(record),
        "record": _truncate_text(record),
        "id": None,
    }
    if not record:
        return parsed
    match = re.search(r"id\s*=\s*([^;]+)", record, flags=re.IGNORECASE)
    if match:
        parsed["id"] = match.group(1).strip()
    return parsed


def parse_mta_sts_policy_file(body: str) -> dict[str, Any]:
    parsed: dict[str, Any] = {
        "mode": None,
        "max_age": None,
        "mx": [],
        "version": None,
    }
    for line in body.splitlines():
        cleaned = line.strip()
        if not cleaned or cleaned.startswith("#"):
            continue
        if ":" not in cleaned:
            continue
        key, value = cleaned.split(":", 1)
        key = key.strip().lower()
        value = value.strip()
        if key == "version":
            parsed["version"] = value
        elif key == "mode":
            parsed["mode"] = value.lower()
        elif key == "max_age":
            parsed["max_age"] = value
        elif key == "mx":
            parsed["mx"].append(value.lower().rstrip("."))
    return parsed


def _fetch_mta_sts_policy(domain: str) -> dict[str, Any]:
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    result: dict[str, Any] = {
        "url": url,
        "policy_reachable": False,
        "status_code": None,
        "error": None,
        "body_preview": None,
        "parsed": {},
    }
    try:
        response = requests.get(
            url,
            timeout=request_timeout_seconds(),
            allow_redirects=True,
            headers={"User-Agent": project_user_agent()},
            stream=True,
        )
        if len(response.history) > MAX_MTA_STS_REDIRECTS:
            result["error"] = "MTA-STS policy fetch stopped after excessive redirects."
            return result
        result["status_code"] = response.status_code
        if response.status_code != 200:
            result["error"] = f"MTA-STS policy returned HTTP {response.status_code}."
            return result
        chunks: list[bytes] = []
        total = 0
        for chunk in response.iter_content(chunk_size=2048):
            if not chunk:
                continue
            chunks.append(chunk)
            total += len(chunk)
            if total >= MAX_POLICY_BYTES:
                break
        body = b"".join(chunks).decode("utf-8", errors="replace")
        result["policy_reachable"] = True
        result["body_preview"] = _truncate_text(body, 1024)
        result["parsed"] = parse_mta_sts_policy_file(body)
    except requests.Timeout:
        result["error"] = "MTA-STS policy fetch timed out."
    except requests.RequestException as exc:
        result["error"] = str(exc)
    return result


def _collect_email_security(domain: str, *, fetch_mta_sts_policy: bool = True) -> dict[str, Any]:
    apex_txt = _query_txt(domain)
    spf_record = _find_spf_record(apex_txt)
    spf = parse_spf_record(spf_record)

    dmarc_txt = _query_txt(f"_dmarc.{domain}")
    dmarc_record = _find_dmarc_record(dmarc_txt)
    dmarc = parse_dmarc_record(dmarc_record)

    mx = _query_mx(domain)
    caa = _query_caa(domain)

    mta_sts_txt_records = _query_txt(f"_mta-sts.{domain}")
    mta_sts_record = _find_tagged_txt(mta_sts_txt_records, "v=STSv1")
    mta_sts_txt = parse_mta_sts_txt(mta_sts_record)
    mta_sts: dict[str, Any] = {
        **mta_sts_txt,
        "policy_reachable": False,
        "mode": None,
        "max_age": None,
        "mx": [],
        "policy_fetch": {},
    }
    if mta_sts_txt.get("txt_present") and fetch_mta_sts_policy:
        policy_fetch = _fetch_mta_sts_policy(domain)
        mta_sts["policy_fetch"] = {
            "url": policy_fetch.get("url"),
            "status_code": policy_fetch.get("status_code"),
            "error": policy_fetch.get("error"),
            "body_preview": policy_fetch.get("body_preview"),
        }
        mta_sts["policy_reachable"] = bool(policy_fetch.get("policy_reachable"))
        policy_parsed = policy_fetch.get("parsed") or {}
        mta_sts["mode"] = policy_parsed.get("mode")
        mta_sts["max_age"] = policy_parsed.get("max_age")
        mta_sts["mx"] = policy_parsed.get("mx") or []

    tls_rpt_txt = _query_txt(f"_smtp._tls.{domain}")
    tls_rpt_record = _find_tagged_txt(tls_rpt_txt, "v=TLSRPTv1")
    tls_rpt = parse_tls_rpt_record(tls_rpt_record)

    bimi_txt = _query_txt(f"default._bimi.{domain}")
    bimi_record = _find_tagged_txt(bimi_txt, "v=BIMI1")
    bimi = parse_bimi_record(bimi_record)

    return {
        "target": domain,
        "domain": domain,
        "mx": mx,
        "spf": spf,
        "dmarc": dmarc,
        "caa": caa,
        "mta_sts": mta_sts,
        "tls_rpt": tls_rpt,
        "bimi": bimi,
        "dns_errors": [],
    }


def _build_raw_output(data: dict[str, Any]) -> str:
    lines = [
        f"Domain email security posture for {data.get('domain')}",
        "",
        f"SPF present: {data.get('spf', {}).get('present')}",
        f"SPF policy: {data.get('spf', {}).get('policy')}",
        f"DMARC present: {data.get('dmarc', {}).get('present')}",
        f"DMARC policy (p=): {data.get('dmarc', {}).get('policy')}",
        f"MX records: {len(data.get('mx') or [])}",
        f"CAA records: {len(data.get('caa') or [])}",
        f"MTA-STS TXT present: {data.get('mta_sts', {}).get('txt_present')}",
        f"MTA-STS policy reachable: {data.get('mta_sts', {}).get('policy_reachable')}",
        f"MTA-STS mode: {data.get('mta_sts', {}).get('mode')}",
        f"TLS-RPT present: {data.get('tls_rpt', {}).get('present')}",
        f"BIMI present: {data.get('bimi', {}).get('present')}",
        "",
        "Raw DNS/TXT details are available in structured data (collapsed in UI).",
    ]
    if data.get("warning"):
        lines.extend(["", f"Warning: {data['warning']}"])
    return "\n".join(lines)


def _build_module_notes(data: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    domain = data.get("domain") or "target"
    spf = data.get("spf") or {}
    dmarc = data.get("dmarc") or {}
    mx = data.get("mx") or []
    caa = data.get("caa") or []
    mta_sts = data.get("mta_sts") or {}
    tls_rpt = data.get("tls_rpt") or {}
    bimi = data.get("bimi") or {}

    if spf.get("present"):
        notes.append(f"SPF record observed for {domain} (policy {spf.get('policy')}).")
    else:
        notes.append(f"SPF public DNS record not observed for {domain}.")

    if dmarc.get("present"):
        notes.append(f"DMARC record observed for {domain} (p={dmarc.get('policy') or 'unknown'}).")
    else:
        notes.append(f"DMARC public DNS record not observed for {domain}.")

    if mx:
        notes.append(f"{len(mx)} MX record(s) observed for {domain}.")
    else:
        notes.append(f"No MX records observed for {domain}.")

    if caa:
        notes.append(f"CAA record(s) observed for {domain}.")
    else:
        notes.append(f"CAA public DNS record not observed for {domain}.")

    if mta_sts.get("txt_present"):
        notes.append(f"MTA-STS TXT record observed for {domain}.")
    else:
        notes.append(f"MTA-STS public DNS record not observed for {domain}.")

    if tls_rpt.get("present"):
        notes.append(f"TLS-RPT record observed for {domain}.")
    else:
        notes.append(f"TLS-RPT public DNS record not observed for {domain}.")

    if bimi.get("present"):
        notes.append(f"BIMI record observed for {domain}.")
    else:
        notes.append(f"BIMI public DNS record not observed for {domain}.")

    if data.get("warning"):
        notes.append(data["warning"])
    return notes


def _build_summary(data: dict[str, Any]) -> str:
    domain = data.get("domain") or "target"
    spf = data.get("spf") or {}
    dmarc = data.get("dmarc") or {}
    mx_count = len(data.get("mx") or [])
    parts = [
        f"Email security posture reviewed for {domain}.",
        f"SPF: {'present' if spf.get('present') else 'not observed'}",
        f"({spf.get('policy')}).",
        f"DMARC: {'present' if dmarc.get('present') else 'not observed'}",
    ]
    if dmarc.get("policy"):
        parts.append(f"(p={dmarc['policy']}).")
    parts.append(f"MX: {mx_count}.")
    summary = " ".join(parts)
    if data.get("warning"):
        summary += f" {data['warning']}"
    return summary


def run_email_security_review(target: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Collect passive DNS-based email security posture for a domain or URL."""
    options = options or {}
    original_target = target.strip()
    domain = normalize_domain(original_target)

    base_data: dict[str, Any] = {
        "original_target": original_target,
        "domain": domain,
        "mx": [],
        "spf": parse_spf_record(None),
        "dmarc": parse_dmarc_record(None),
        "caa": [],
        "mta_sts": {
            "txt_present": False,
            "policy_reachable": False,
            "mode": None,
            "max_age": None,
            "mx": [],
        },
        "tls_rpt": parse_tls_rpt_record(None),
        "bimi": parse_bimi_record(None),
        "warning": None,
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
            "warnings": [],
            "data": base_data,
        }

    if options.get("mock_data") is not None:
        base_data = {**base_data, **options["mock_data"]}
        base_data["domain"] = base_data.get("domain") or domain
        base_data["target"] = base_data.get("target") or base_data["domain"]
    else:
        collected = _collect_email_security(
            domain,
            fetch_mta_sts_policy=not options.get("skip_mta_sts_policy_fetch"),
        )
        base_data.update(collected)

    warnings: list[str] = []
    mta_sts = base_data.get("mta_sts") or {}
    if mta_sts.get("txt_present") and not mta_sts.get("policy_reachable"):
        fetch_error = (mta_sts.get("policy_fetch") or {}).get("error")
        warning = (
            "MTA-STS TXT record observed but the HTTPS policy file was not retrieved."
            + (f" {fetch_error}" if fetch_error else "")
        )
        base_data["warning"] = warning
        warnings.append(warning)

    spf = base_data.get("spf") or {}
    if spf.get("many_includes"):
        include_warning = (
            f"SPF record includes {spf.get('include_count')} include mechanism(s) — "
            "review DNS lookup limits and record complexity."
        )
        warnings.append(include_warning)
        if not base_data.get("warning"):
            base_data["warning"] = include_warning

    has_core_data = True
    status = resolve_collection_status(warnings=warnings, has_core_data=has_core_data)
    summary = _build_summary(base_data)

    return {
        "module_id": MODULE_ID,
        "success": True,
        "status": status,
        "summary": summary,
        "raw_output": _build_raw_output(base_data),
        "findings": _build_module_notes(base_data),
        "warnings": warnings,
        "errors": warnings if status == "partial" and not has_core_data else [],
        "data": base_data,
    }

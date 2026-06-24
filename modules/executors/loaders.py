"""Lazy module handler loading for executor dispatch."""

from __future__ import annotations

import importlib.util
import shutil
import sys
from typing import Any, Callable

from modules.executors.paths import (
    ABUSEIPDB_MODULE_PATH,
    CERT_SUBDOMAIN_MODULE_PATH,
    DOMAIN_INTEL_MODULE_PATH,
    EMAIL_SECURITY_MODULE_PATH,
    GREYNOISE_MODULE_PATH,
    HTTP_SECURITY_MODULE_PATH,
    LIVE_CAPTURE_MODULE_PATH,
    NMAP_MODULE_PATH,
    PCAP_REVIEW_MODULE_PATH,
    REMOTE_ACCESS_MODULE_PATH,
    SHODAN_MODULE_PATH,
    TLS_REVIEW_MODULE_PATH,
    URLHAUS_MODULE_PATH,
    VIRUSTOTAL_MODULE_PATH,
    WEB_STACK_MODULE_PATH,
    WEBSITE_METADATA_MODULE_PATH,
    WHOIS_RDAP_MODULE_PATH,
)

_nmap_handlers: tuple[Any, Any] | None = None
_nmap_load_error: str | None = None
_nmap_load_attempted = False
_domain_intel_handler: Any | None = None
_domain_intel_load_error: str | None = None
_domain_intel_load_attempted = False
_cert_subdomain_handler: Any | None = None
_cert_subdomain_load_error: str | None = None
_cert_subdomain_load_attempted = False
_website_metadata_handler: Any | None = None
_website_metadata_load_error: str | None = None
_website_metadata_load_attempted = False
_email_security_handler: Any | None = None
_email_security_load_error: str | None = None
_email_security_load_attempted = False
_tls_review_handler: Any | None = None
_tls_review_load_error: str | None = None
_tls_review_load_attempted = False
_http_security_handler: Any | None = None
_http_security_load_error: str | None = None
_http_security_load_attempted = False
_remote_access_handler: Any | None = None
_remote_access_load_error: str | None = None
_remote_access_load_attempted = False
_web_stack_handler: Any | None = None
_web_stack_load_error: str | None = None
_web_stack_load_attempted = False
_whois_rdap_handler: Any | None = None
_whois_rdap_load_error: str | None = None
_whois_rdap_load_attempted = False
_virustotal_handler: Any | None = None
_virustotal_load_error: str | None = None
_virustotal_load_attempted = False
_abuseipdb_handler: Any | None = None
_abuseipdb_load_error: str | None = None
_abuseipdb_load_attempted = False
_greynoise_handler: Any | None = None
_greynoise_load_error: str | None = None
_greynoise_load_attempted = False
_shodan_handler: Any | None = None
_shodan_load_error: str | None = None
_shodan_load_attempted = False
_urlhaus_handler: Any | None = None
_urlhaus_load_error: str | None = None
_urlhaus_load_attempted = False
_pcap_review_handler: Any | None = None
_pcap_review_load_error: str | None = None
_pcap_review_load_attempted = False
_live_capture_handler: Any | None = None
_live_capture_load_error: str | None = None
_live_capture_load_attempted = False


def _observation_evidence_kwargs(module_id: str, result: dict[str, Any]) -> dict[str, Any]:
    """Build observation evidence fields from module defaults and run result."""
    meta = observation_evidence_for_module(module_id, result)
    return {
        key: meta[key]
        for key in (
            "evidence_type",
            "source_name",
            "source_url",
            "reliability",
            "collection_method",
            "collected_at",
            "module_version",
        )
        if meta.get(key) is not None
    }


def _prepare_module_result(result: dict[str, Any]) -> dict[str, Any]:
    """Normalise and attach non-fatal validation notes to a module result."""
    normalized = normalise_result(result)
    validation = validate_module_result(normalized)
    if validation["errors"]:
        for message in validation["errors"]:
            note = f"Result validation error: {message}"
            if note not in normalized["warnings"]:
                normalized["warnings"].append(note)
    for message in validation["warnings"]:
        note = f"Result validation: {message}"
        if note not in normalized["warnings"]:
            normalized["warnings"].append(note)
    return normalized


def make_result(
    module_id: str,
    *,
    success: bool,
    status: str,
    summary: str,
    raw_output: str = "",
    findings: list[str] | None = None,
    warnings: list[str] | None = None,
    errors: list[str] | None = None,
    parsed_data: dict[str, Any] | None = None,
    interpreter_findings: list[dict[str, Any]] | None = None,
    selected_options: dict[str, Any] | None = None,
    evidence: list[dict[str, Any]] | None = None,
    data: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a standard execution result payload."""
    result = build_module_result(
        module_id,
        status,
        summary,
        success=success,
        data=data or parsed_data,
        findings=findings,
        warnings=warnings,
        errors=errors,
        raw_output=raw_output,
        evidence=evidence,
    )
    if interpreter_findings is not None:
        result["interpreter_findings"] = interpreter_findings
    if selected_options is not None:
        result["selected_options"] = selected_options
    if parsed_data is not None:
        result["parsed_data"] = parsed_data
        if not result.get("data"):
            result["data"] = parsed_data
    return _prepare_module_result(result)


def _load_nmap_handlers() -> None:
    global _nmap_handlers, _nmap_load_error, _nmap_load_attempted

    if _nmap_load_attempted:
        return

    _nmap_load_attempted = True

    if not NMAP_MODULE_PATH.is_file():
        _nmap_load_error = f"Module file not found: {NMAP_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("infra_nmap", NMAP_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {NMAP_MODULE_PATH}")
        infra_nmap = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(infra_nmap)
        _nmap_handlers = (infra_nmap.run_nmap_scan, infra_nmap.parse_nmap_problems)
    except Exception as exc:
        _nmap_load_error = str(exc)


def _load_domain_intel_handler() -> None:
    global _domain_intel_handler, _domain_intel_load_error, _domain_intel_load_attempted

    if _domain_intel_load_attempted:
        return

    _domain_intel_load_attempted = True

    if not DOMAIN_INTEL_MODULE_PATH.is_file():
        _domain_intel_load_error = f"Module file not found: {DOMAIN_INTEL_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("infra_domain_intel", DOMAIN_INTEL_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {DOMAIN_INTEL_MODULE_PATH}")
        infra_domain_intel = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(infra_domain_intel)
        _domain_intel_handler = infra_domain_intel.run_domain_intel
    except Exception as exc:
        _domain_intel_load_error = str(exc)


def _load_cert_subdomain_handler() -> None:
    global _cert_subdomain_handler, _cert_subdomain_load_error, _cert_subdomain_load_attempted

    if _cert_subdomain_load_attempted:
        return

    _cert_subdomain_load_attempted = True

    if not CERT_SUBDOMAIN_MODULE_PATH.is_file():
        _cert_subdomain_load_error = f"Module file not found: {CERT_SUBDOMAIN_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("infra_cert_subdomain", CERT_SUBDOMAIN_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {CERT_SUBDOMAIN_MODULE_PATH}")
        infra_cert_subdomain = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(infra_cert_subdomain)
        _cert_subdomain_handler = infra_cert_subdomain.run_cert_subdomain_intel
    except Exception as exc:
        _cert_subdomain_load_error = str(exc)


def _load_website_metadata_handler() -> None:
    global _website_metadata_handler, _website_metadata_load_error, _website_metadata_load_attempted

    if _website_metadata_load_attempted:
        return

    _website_metadata_load_attempted = True

    if not WEBSITE_METADATA_MODULE_PATH.is_file():
        _website_metadata_load_error = f"Module file not found: {WEBSITE_METADATA_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("infra_website_metadata", WEBSITE_METADATA_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {WEBSITE_METADATA_MODULE_PATH}")
        infra_website_metadata = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(infra_website_metadata)
        _website_metadata_handler = infra_website_metadata.run_website_metadata_review
    except Exception as exc:
        _website_metadata_load_error = str(exc)


def _load_email_security_handler() -> None:
    global _email_security_handler, _email_security_load_error, _email_security_load_attempted

    if _email_security_load_attempted:
        return

    _email_security_load_attempted = True

    if not EMAIL_SECURITY_MODULE_PATH.is_file():
        _email_security_load_error = f"Module file not found: {EMAIL_SECURITY_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("infra_email_security", EMAIL_SECURITY_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {EMAIL_SECURITY_MODULE_PATH}")
        infra_email_security = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(infra_email_security)
        _email_security_handler = infra_email_security.run_email_security_review
    except Exception as exc:
        _email_security_load_error = str(exc)


def _load_tls_review_handler() -> None:
    global _tls_review_handler, _tls_review_load_error, _tls_review_load_attempted

    if _tls_review_load_attempted:
        return

    _tls_review_load_attempted = True

    if not TLS_REVIEW_MODULE_PATH.is_file():
        _tls_review_load_error = f"Module file not found: {TLS_REVIEW_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("infra_tls_review", TLS_REVIEW_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {TLS_REVIEW_MODULE_PATH}")
        infra_tls_review = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(infra_tls_review)
        _tls_review_handler = infra_tls_review.run_tls_review
    except Exception as exc:
        _tls_review_load_error = str(exc)


def _load_http_security_handler() -> None:
    global _http_security_handler, _http_security_load_error, _http_security_load_attempted

    if _http_security_load_attempted:
        return

    _http_security_load_attempted = True

    if not HTTP_SECURITY_MODULE_PATH.is_file():
        _http_security_load_error = f"Module file not found: {HTTP_SECURITY_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("infra_http_security", HTTP_SECURITY_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {HTTP_SECURITY_MODULE_PATH}")
        infra_http_security = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(infra_http_security)
        _http_security_handler = infra_http_security.run_http_security_review
    except Exception as exc:
        _http_security_load_error = str(exc)


def _load_remote_access_handler() -> None:
    global _remote_access_handler, _remote_access_load_error, _remote_access_load_attempted

    if _remote_access_load_attempted:
        return

    _remote_access_load_attempted = True

    if not REMOTE_ACCESS_MODULE_PATH.is_file():
        _remote_access_load_error = f"Module file not found: {REMOTE_ACCESS_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("infra_remote_access_review", REMOTE_ACCESS_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {REMOTE_ACCESS_MODULE_PATH}")
        infra_remote_access_review = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(infra_remote_access_review)
        _remote_access_handler = infra_remote_access_review.run_remote_access_review
    except Exception as exc:
        _remote_access_load_error = str(exc)


def _load_web_stack_handler() -> None:
    global _web_stack_handler, _web_stack_load_error, _web_stack_load_attempted

    if _web_stack_load_attempted:
        return

    _web_stack_load_attempted = True

    if not WEB_STACK_MODULE_PATH.is_file():
        _web_stack_load_error = f"Module file not found: {WEB_STACK_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("infra_web_stack_identifier", WEB_STACK_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {WEB_STACK_MODULE_PATH}")
        infra_web_stack_identifier = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(infra_web_stack_identifier)
        _web_stack_handler = infra_web_stack_identifier.run_web_stack_identifier
    except Exception as exc:
        _web_stack_load_error = str(exc)


def _load_whois_rdap_handler() -> None:
    global _whois_rdap_handler, _whois_rdap_load_error, _whois_rdap_load_attempted

    if _whois_rdap_load_attempted:
        return

    _whois_rdap_load_attempted = True

    if not WHOIS_RDAP_MODULE_PATH.is_file():
        _whois_rdap_load_error = f"Module file not found: {WHOIS_RDAP_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("infra_whois_rdap", WHOIS_RDAP_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {WHOIS_RDAP_MODULE_PATH}")
        infra_whois_rdap = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(infra_whois_rdap)
        _whois_rdap_handler = infra_whois_rdap.run_whois_rdap_lookup
    except Exception as exc:
        _whois_rdap_load_error = str(exc)


def _load_virustotal_handler() -> None:
    global _virustotal_handler, _virustotal_load_error, _virustotal_load_attempted

    if _virustotal_load_attempted:
        return

    _virustotal_load_attempted = True

    if not VIRUSTOTAL_MODULE_PATH.is_file():
        _virustotal_load_error = f"Module file not found: {VIRUSTOTAL_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("intel_virustotal", VIRUSTOTAL_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {VIRUSTOTAL_MODULE_PATH}")
        intel_virustotal = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(intel_virustotal)
        _virustotal_handler = intel_virustotal.run_virustotal_lookup
    except Exception as exc:
        _virustotal_load_error = str(exc)


def _load_abuseipdb_handler() -> None:
    global _abuseipdb_handler, _abuseipdb_load_error, _abuseipdb_load_attempted

    if _abuseipdb_load_attempted:
        return

    _abuseipdb_load_attempted = True

    if not ABUSEIPDB_MODULE_PATH.is_file():
        _abuseipdb_load_error = f"Module file not found: {ABUSEIPDB_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("intel_abuseipdb", ABUSEIPDB_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {ABUSEIPDB_MODULE_PATH}")
        intel_abuseipdb = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(intel_abuseipdb)
        _abuseipdb_handler = intel_abuseipdb.run_abuseipdb_lookup
    except Exception as exc:
        _abuseipdb_load_error = str(exc)


def _load_greynoise_handler() -> None:
    global _greynoise_handler, _greynoise_load_error, _greynoise_load_attempted

    if _greynoise_load_attempted:
        return

    _greynoise_load_attempted = True

    if not GREYNOISE_MODULE_PATH.is_file():
        _greynoise_load_error = f"Module file not found: {GREYNOISE_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("intel_greynoise", GREYNOISE_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {GREYNOISE_MODULE_PATH}")
        intel_greynoise = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(intel_greynoise)
        _greynoise_handler = intel_greynoise.run_greynoise_lookup
    except Exception as exc:
        _greynoise_load_error = str(exc)


def _load_shodan_handler() -> None:
    global _shodan_handler, _shodan_load_error, _shodan_load_attempted

    if _shodan_load_attempted:
        return

    _shodan_load_attempted = True

    if not SHODAN_MODULE_PATH.is_file():
        _shodan_load_error = f"Module file not found: {SHODAN_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("intel_shodan", SHODAN_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {SHODAN_MODULE_PATH}")
        intel_shodan = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(intel_shodan)
        _shodan_handler = intel_shodan.run_shodan_lookup
    except Exception as exc:
        _shodan_load_error = str(exc)


def _load_urlhaus_handler() -> None:
    global _urlhaus_handler, _urlhaus_load_error, _urlhaus_load_attempted

    if _urlhaus_load_attempted:
        return

    _urlhaus_load_attempted = True

    if not URLHAUS_MODULE_PATH.is_file():
        _urlhaus_load_error = f"Module file not found: {URLHAUS_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("intel_urlhaus", URLHAUS_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {URLHAUS_MODULE_PATH}")
        intel_urlhaus = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(intel_urlhaus)
        _urlhaus_handler = intel_urlhaus.run_urlhaus_lookup
    except Exception as exc:
        _urlhaus_load_error = str(exc)


def _load_pcap_review_handler() -> None:
    global _pcap_review_handler, _pcap_review_load_error, _pcap_review_load_attempted

    if _pcap_review_load_attempted:
        return

    _pcap_review_load_attempted = True

    if not PCAP_REVIEW_MODULE_PATH.is_file():
        _pcap_review_load_error = f"Module file not found: {PCAP_REVIEW_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("net_pcap_review", PCAP_REVIEW_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {PCAP_REVIEW_MODULE_PATH}")
        net_pcap_review = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(net_pcap_review)
        _pcap_review_handler = net_pcap_review.run_pcap_review
    except Exception as exc:
        _pcap_review_load_error = str(exc)


def _load_live_capture_handler() -> None:
    global _live_capture_handler, _live_capture_load_error, _live_capture_load_attempted

    if _live_capture_load_attempted:
        return

    _live_capture_load_attempted = True

    if not LIVE_CAPTURE_MODULE_PATH.is_file():
        _live_capture_load_error = f"Module file not found: {LIVE_CAPTURE_MODULE_PATH}"
        return

    try:
        spec = importlib.util.spec_from_file_location("net_live_capture", LIVE_CAPTURE_MODULE_PATH)
        if spec is None or spec.loader is None:
            raise ImportError(f"Could not load module spec from {LIVE_CAPTURE_MODULE_PATH}")
        net_live_capture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(net_live_capture)
        _live_capture_handler = net_live_capture.run_live_capture
    except Exception as exc:
        _live_capture_load_error = str(exc)


def _nmap_binary_available() -> bool:
    return shutil.which("nmap") is not None


def loaded_handler(
    load_fn: Callable[[], None],
    handler_attr: str,
    error_attr: str,
) -> tuple[Any | None, str | None]:
    """Return a lazily loaded handler and its load error from this module."""
    load_fn()
    module = sys.modules[__name__]
    return getattr(module, handler_attr), getattr(module, error_attr)

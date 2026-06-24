"""Register all module dispatch entries with modules.executor_dispatch."""

from __future__ import annotations

import sqlite3
from typing import Any, Callable

from modules.executor_dispatch import ExecuteFn, ModuleDispatchEntry, register_executor
from modules.executors import infrastructure, loaders, network_analysis, threat_intelligence
from modules.executors.persistence import _persist_nmap_services_and_relationships


def register_all_executors() -> None:
    """Wire all module handlers into the central dispatch registry."""

    def _module_ready(load_fn: Callable[[], None], handler_getter: Callable[[], Any]) -> Callable[[], bool]:
        def _ready() -> bool:
            load_fn()
            return handler_getter() is not None

        return _ready

    def _module_error(load_fn: Callable[[], None], error_getter: Callable[[], str | None]) -> Callable[[], str | None]:
        def _error() -> str | None:
            load_fn()
            return error_getter()

        return _error

    def _nmap_ready() -> bool:
        loaders._load_nmap_handlers()
        return loaders._nmap_handlers is not None and loaders._nmap_binary_available()

    def _nmap_error() -> str | None:
        loaders._load_nmap_handlers()
        if not loaders._nmap_binary_available():
            return (
                "Nmap is not installed or not on your PATH. "
                "Install from https://nmap.org/download.html and restart the app."
            )
        return loaders._nmap_load_error

    def _wrap_no_options(execute_fn: ExecuteFn) -> ExecuteFn:
        def _wrapped(
            module_id: str,
            target: str,
            options: dict[str, Any],
            db_context: sqlite3.Connection | None,
            authorisation_confirmed: bool,
            case_id: int | None,
            entity_id: int | None,
            run_mode_id: str | None,
            run_mode_label: str | None,
        ) -> dict[str, Any]:
            return execute_fn(
                module_id,
                target,
                db_context,
                authorisation_confirmed,
                case_id,
                entity_id,
                run_mode_id,
                run_mode_label,
            )

        return _wrapped

    entries = (
        ModuleDispatchEntry(
            "infra_nmap",
            load=loaders._load_nmap_handlers,
            is_ready=_nmap_ready,
            get_error=_nmap_error,
            execute=infrastructure._execute_nmap,
            unavailable_label="Network Service Check",
            persist_hook=_persist_nmap_services_and_relationships,
        ),
        ModuleDispatchEntry(
            "infra_domain_intel",
            load=loaders._load_domain_intel_handler,
            is_ready=_module_ready(loaders._load_domain_intel_handler, lambda: loaders._domain_intel_handler),
            get_error=_module_error(loaders._load_domain_intel_handler, lambda: loaders._domain_intel_load_error),
            execute=_wrap_no_options(infrastructure._execute_domain_intel),
            unavailable_label="Domain Intelligence",
        ),
        ModuleDispatchEntry(
            "infra_cert_subdomain",
            load=loaders._load_cert_subdomain_handler,
            is_ready=_module_ready(loaders._load_cert_subdomain_handler, lambda: loaders._cert_subdomain_handler),
            get_error=_module_error(loaders._load_cert_subdomain_handler, lambda: loaders._cert_subdomain_load_error),
            execute=_wrap_no_options(infrastructure._execute_cert_subdomain),
            unavailable_label="Certificate & Subdomain Intelligence",
        ),
        ModuleDispatchEntry(
            "infra_website_metadata",
            load=loaders._load_website_metadata_handler,
            is_ready=_module_ready(loaders._load_website_metadata_handler, lambda: loaders._website_metadata_handler),
            get_error=_module_error(loaders._load_website_metadata_handler, lambda: loaders._website_metadata_load_error),
            execute=_wrap_no_options(infrastructure._execute_website_metadata),
            unavailable_label="Website Metadata Review",
        ),
        ModuleDispatchEntry(
            "infra_email_security",
            load=loaders._load_email_security_handler,
            is_ready=_module_ready(loaders._load_email_security_handler, lambda: loaders._email_security_handler),
            get_error=_module_error(loaders._load_email_security_handler, lambda: loaders._email_security_load_error),
            execute=infrastructure._execute_email_security,
            unavailable_label="Domain Email Security Posture",
        ),
        ModuleDispatchEntry(
            "infra_tls_review",
            load=loaders._load_tls_review_handler,
            is_ready=_module_ready(loaders._load_tls_review_handler, lambda: loaders._tls_review_handler),
            get_error=_module_error(loaders._load_tls_review_handler, lambda: loaders._tls_review_load_error),
            execute=infrastructure._execute_tls_review,
            unavailable_label="SSL / TLS Configuration Review",
        ),
        ModuleDispatchEntry(
            "infra_http_security",
            load=loaders._load_http_security_handler,
            is_ready=_module_ready(loaders._load_http_security_handler, lambda: loaders._http_security_handler),
            get_error=_module_error(loaders._load_http_security_handler, lambda: loaders._http_security_load_error),
            execute=infrastructure._execute_http_security,
            unavailable_label="HTTP Security Header Review",
        ),
        ModuleDispatchEntry(
            "infra_whois_rdap",
            load=loaders._load_whois_rdap_handler,
            is_ready=_module_ready(loaders._load_whois_rdap_handler, lambda: loaders._whois_rdap_handler),
            get_error=_module_error(loaders._load_whois_rdap_handler, lambda: loaders._whois_rdap_load_error),
            execute=infrastructure._execute_whois_rdap,
            unavailable_label="WHOIS/RDAP Intelligence",
        ),
        ModuleDispatchEntry(
            "intel_virustotal",
            load=loaders._load_virustotal_handler,
            is_ready=_module_ready(loaders._load_virustotal_handler, lambda: loaders._virustotal_handler),
            get_error=_module_error(loaders._load_virustotal_handler, lambda: loaders._virustotal_load_error),
            execute=threat_intelligence._execute_virustotal,
            unavailable_label="VirusTotal",
        ),
        ModuleDispatchEntry(
            "intel_abuseipdb",
            load=loaders._load_abuseipdb_handler,
            is_ready=_module_ready(loaders._load_abuseipdb_handler, lambda: loaders._abuseipdb_handler),
            get_error=_module_error(loaders._load_abuseipdb_handler, lambda: loaders._abuseipdb_load_error),
            execute=threat_intelligence._execute_abuseipdb,
            unavailable_label="AbuseIPDB",
        ),
        ModuleDispatchEntry(
            "intel_greynoise",
            load=loaders._load_greynoise_handler,
            is_ready=_module_ready(loaders._load_greynoise_handler, lambda: loaders._greynoise_handler),
            get_error=_module_error(loaders._load_greynoise_handler, lambda: loaders._greynoise_load_error),
            execute=threat_intelligence._execute_greynoise,
            unavailable_label="GreyNoise",
        ),
        ModuleDispatchEntry(
            "intel_shodan",
            load=loaders._load_shodan_handler,
            is_ready=_module_ready(loaders._load_shodan_handler, lambda: loaders._shodan_handler),
            get_error=_module_error(loaders._load_shodan_handler, lambda: loaders._shodan_load_error),
            execute=threat_intelligence._execute_shodan,
            unavailable_label="Shodan",
        ),
        ModuleDispatchEntry(
            "intel_urlhaus",
            load=loaders._load_urlhaus_handler,
            is_ready=_module_ready(loaders._load_urlhaus_handler, lambda: loaders._urlhaus_handler),
            get_error=_module_error(loaders._load_urlhaus_handler, lambda: loaders._urlhaus_load_error),
            execute=threat_intelligence._execute_urlhaus,
            unavailable_label="URLhaus",
        ),
        ModuleDispatchEntry(
            "net_pcap_review",
            load=loaders._load_pcap_review_handler,
            is_ready=_module_ready(loaders._load_pcap_review_handler, lambda: loaders._pcap_review_handler),
            get_error=_module_error(loaders._load_pcap_review_handler, lambda: loaders._pcap_review_load_error),
            execute=network_analysis._execute_pcap_review,
            unavailable_label="PCAP Evidence Review",
        ),
        ModuleDispatchEntry(
            "net_live_capture",
            load=loaders._load_live_capture_handler,
            is_ready=_module_ready(loaders._load_live_capture_handler, lambda: loaders._live_capture_handler),
            get_error=_module_error(loaders._load_live_capture_handler, lambda: loaders._live_capture_load_error),
            execute=network_analysis._execute_live_capture,
            unavailable_label="Personal Lab Packet Capture",
        ),
    )
    for entry in entries:
        register_executor(entry)

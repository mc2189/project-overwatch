"""Registry of module result interpreters for the unified findings pipeline."""

from __future__ import annotations

from typing import Any, Callable

from utils.greynoise_interpreter import interpret_greynoise_results
from utils.shodan_interpreter import interpret_shodan_results
from utils.urlhaus_interpreter import interpret_urlhaus_results
from utils.abuseipdb_interpreter import interpret_abuseipdb_results
from utils.cert_subdomain_interpreter import interpret_cert_subdomain_results
from utils.domain_intel_interpreter import interpret_domain_intel_results
from utils.nmap_interpreter import interpret_nmap_results
from utils.virustotal_interpreter import interpret_virustotal_results
from utils.website_metadata_interpreter import interpret_website_metadata_results
from utils.whois_rdap_interpreter import interpret_whois_rdap_results

InterpreterFn = Callable[[dict[str, Any], dict[str, Any]], list[dict[str, Any]]]


def _interpret_cert_subdomain(parsed_data: dict[str, Any], _options: dict[str, Any]) -> list[dict[str, Any]]:
    return interpret_cert_subdomain_results(parsed_data)


def _interpret_domain_intel(parsed_data: dict[str, Any], _options: dict[str, Any]) -> list[dict[str, Any]]:
    return interpret_domain_intel_results(parsed_data)


def _interpret_urlhaus(parsed_data: dict[str, Any], _options: dict[str, Any]) -> list[dict[str, Any]]:
    return interpret_urlhaus_results(parsed_data)


def _interpret_shodan(parsed_data: dict[str, Any], _options: dict[str, Any]) -> list[dict[str, Any]]:
    return interpret_shodan_results(parsed_data)


def _interpret_greynoise(parsed_data: dict[str, Any], _options: dict[str, Any]) -> list[dict[str, Any]]:
    return interpret_greynoise_results(parsed_data)


def _interpret_abuseipdb(parsed_data: dict[str, Any], _options: dict[str, Any]) -> list[dict[str, Any]]:
    return interpret_abuseipdb_results(parsed_data)


def _interpret_virustotal(parsed_data: dict[str, Any], _options: dict[str, Any]) -> list[dict[str, Any]]:
    return interpret_virustotal_results(parsed_data)


def _interpret_whois_rdap(parsed_data: dict[str, Any], _options: dict[str, Any]) -> list[dict[str, Any]]:
    return interpret_whois_rdap_results(parsed_data)


def _interpret_website_metadata(parsed_data: dict[str, Any], _options: dict[str, Any]) -> list[dict[str, Any]]:
    return interpret_website_metadata_results(parsed_data)


def _interpret_nmap(parsed_data: dict[str, Any], options: dict[str, Any]) -> list[dict[str, Any]]:
    return interpret_nmap_results(parsed_data, options)


MODULE_FINDING_INTERPRETERS: dict[str, InterpreterFn] = {
    "infra_nmap": _interpret_nmap,
    "infra_domain_intel": _interpret_domain_intel,
    "infra_cert_subdomain": _interpret_cert_subdomain,
    "infra_website_metadata": _interpret_website_metadata,
    "infra_whois_rdap": _interpret_whois_rdap,
    "intel_virustotal": _interpret_virustotal,
    "intel_abuseipdb": _interpret_abuseipdb,
    "intel_greynoise": _interpret_greynoise,
    "intel_shodan": _interpret_shodan,
    "intel_urlhaus": _interpret_urlhaus,
}


def interpret_module_findings(
    module_id: str,
    parsed_data: dict[str, Any],
    options: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Run the registered interpreter for a module, if one exists."""
    interpreter = MODULE_FINDING_INTERPRETERS.get(module_id)
    if interpreter is None:
        return []
    return interpreter(parsed_data, options or {})


def module_has_findings_pipeline(module_id: str) -> bool:
    return module_id in MODULE_FINDING_INTERPRETERS

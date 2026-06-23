"""Advisory interpretation of Shodan Internet Exposure Intelligence results."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding

MISSING_KEY_MESSAGE = "Shodan API key is not configured."

_ADMIN_PORTS: dict[int, str] = {
    22: "SSH",
    23: "Telnet",
    3389: "RDP",
    5900: "VNC",
    5985: "WinRM",
    5986: "WinRM",
}

_DB_PORTS: dict[int, str] = {
    3306: "MySQL",
    5432: "PostgreSQL",
    1433: "MSSQL",
    27017: "MongoDB",
    6379: "Redis",
    9200: "Elasticsearch",
}


def _service_ports(parsed_data: dict[str, Any]) -> list[int]:
    services = parsed_data.get("services") or []
    ports: list[int] = []
    for item in services:
        port = item.get("port")
        if isinstance(port, int):
            ports.append(port)
    if ports:
        return ports
    raw_ports = parsed_data.get("ports") or []
    return [int(port) for port in raw_ports if isinstance(port, int)]


def interpret_shodan_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Return cautious analyst findings from Shodan host data."""
    findings: list[dict[str, Any]] = []
    target = parsed_data.get("ip_address") or parsed_data.get("target") or "target"
    api = parsed_data.get("api") or {}

    if parsed_data.get("private_local_ip"):
        findings.append(
            make_finding(
                "Private/local IP not applicable for Shodan",
                "info",
                90,
                "Private/local IP address — public Shodan internet-exposure lookup is not applicable.",
                [
                    "Use other local or case context for private address review.",
                    "Run passive modules against related public hosts if needed.",
                ],
            )
        )
        return findings

    if api.get("error") == MISSING_KEY_MESSAGE or (
        api.get("status_code") in {401, 403} and not parsed_data.get("service_count")
    ):
        findings.append(
            make_finding(
                "Shodan API key missing or rejected",
                "info",
                95,
                "Shodan API key is not configured or was rejected. Add SHODAN_API_KEY to your local .env file.",
                [
                    "Configure the key locally — it is never stored in the database.",
                    "Retry after updating .env and reloading the app.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if api.get("status_code") == 429:
        findings.append(
            make_finding(
                "Shodan rate limit reached",
                "info",
                80,
                "Shodan reported a rate limit for this lookup. "
                "This is an operational limitation, not a target risk indicator.",
                [
                    "Wait before retrying or reduce batch queue frequency.",
                    "Document the delay in case notes if follow-up is required.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    service_count = int(parsed_data.get("service_count") or 0)
    ports = _service_ports(parsed_data)

    if service_count == 0 and not ports:
        findings.append(
            make_finding(
                "No Shodan host data observed",
                "info",
                70,
                f"Shodan returned no prior internet-exposure host data for {target}. "
                "Absence of Shodan data is inconclusive — it does not prove the host has no exposure history.",
                [
                    "Treat missing Shodan data as one data point only.",
                    "Use authorised Nmap on in-scope targets if current local verification is required.",
                ],
            )
        )
        return findings

    findings.append(
        make_finding(
            "Shodan host exposure data observed",
            "info",
            75,
            f"Shodan reported prior internet-exposure metadata for {target} "
            f"({service_count or len(ports)} service(s) in summary). "
            "Data is reported by Shodan and may be stale or incomplete — not proof services are currently open.",
            [
                "Review reported ports and services in context of the investigation.",
                "Correlate with VirusTotal, AbuseIPDB, GreyNoise, or authorised Nmap where useful.",
            ],
        )
    )

    if len(ports) >= 2:
        findings.append(
            make_finding(
                "Public service exposure reported by Shodan",
                "low",
                76,
                f"Shodan reported multiple services on {target} "
                f"({len(ports)} port(s) in summary). "
                "Reported by Shodan — treat as exposure context, not confirmed current openness.",
                [
                    "Identify whether reported services are expected for this asset.",
                    "Use authorised active verification only on approved targets.",
                ],
            )
        )

    admin_hits = sorted({port for port in ports if port in _ADMIN_PORTS})
    if admin_hits:
        labels = ", ".join(f"{port}/{_ADMIN_PORTS[port]}" for port in admin_hits)
        severity = "medium" if len(admin_hits) > 1 or 3389 in admin_hits else "low"
        findings.append(
            make_finding(
                "Potentially sensitive remote admin service reported by Shodan",
                severity,
                78,
                f"Shodan reported remote administration-related port(s) for {target}: {labels}. "
                "Reported by Shodan — verify scope and authorisation before any active follow-up.",
                [
                    "Confirm whether remote admin exposure is expected and authorised.",
                    "Do not attempt access or exploitation through Project Overwatch.",
                ],
            )
        )

    db_hits = sorted({port for port in ports if port in _DB_PORTS})
    if db_hits:
        labels = ", ".join(f"{port}/{_DB_PORTS[port]}" for port in db_hits)
        severity = "medium" if len(db_hits) > 1 else "low"
        findings.append(
            make_finding(
                "Database-related service reported by Shodan",
                severity,
                77,
                f"Shodan reported database-related port(s) for {target}: {labels}. "
                "Reported by Shodan — exposure context only, not confirmed breach or misconfiguration.",
                [
                    "Review whether database services should be internet-reachable.",
                    "Correlate with case context and change records where available.",
                ],
            )
        )

    vuln_count = int(parsed_data.get("vulnerability_count") or 0)
    if vuln_count > 0:
        findings.append(
            make_finding(
                "Vulnerability references present in Shodan metadata",
                "medium",
                74,
                f"Shodan metadata for {target} references {vuln_count} vulnerability identifier(s). "
                "These are third-party references only — not validated or exploitable through this module.",
                [
                    "Review vulnerability references manually in Shodan or vendor advisories.",
                    "Do not treat Shodan vulnerability tags as confirmed active issues.",
                ],
            )
        )

    return findings

"""Parse structured data from Nmap XML output."""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import Any

from utils.nmap_parser import parse_nmap_open_ports


def parse_nmap_xml(xml_content: str) -> dict[str, Any]:
    """Parse Nmap XML into structured host, port, OS, and script data."""
    empty: dict[str, Any] = {
        "hosts": [],
        "parsed_ports": [],
        "parsed_services": [],
        "os_matches": [],
        "script_results": [],
        "parse_source": "none",
    }

    if not xml_content or not xml_content.strip():
        return empty

    try:
        root = ET.fromstring(xml_content)
    except ET.ParseError:
        return empty

    hosts: list[dict[str, Any]] = []
    parsed_ports: list[dict[str, Any]] = []
    parsed_services: list[dict[str, Any]] = []
    os_matches: list[dict[str, Any]] = []
    script_results: list[dict[str, Any]] = []

    for host in root.findall("host"):
        host_status = host.find("status")
        if host_status is not None and host_status.get("state") not in (None, "up", "unknown"):
            continue

        addresses = [
            {"addr": addr.get("addr", ""), "type": addr.get("addrtype", "")}
            for addr in host.findall("address")
        ]
        hostnames = [name.get("name", "") for name in host.findall("hostnames/hostname") if name.get("name")]

        host_entry: dict[str, Any] = {
            "addresses": addresses,
            "hostnames": hostnames,
            "ports": [],
            "os_matches": [],
        }

        for port in host.findall("ports/port"):
            state_el = port.find("state")
            state = state_el.get("state", "") if state_el is not None else ""
            protocol = port.get("protocol", "")
            port_id = port.get("portid", "")

            service_el = port.find("service")
            service_name = service_el.get("name", "") if service_el is not None else ""
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            extra_info = service_el.get("extrainfo", "") if service_el is not None else ""

            version_text = " ".join(part for part in [product, version, extra_info] if part).strip()

            port_entry = {
                "port": port_id,
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "product": product,
                "version": version_text or version,
                "extra_info": extra_info,
                "scripts": [],
            }

            for script in port.findall("script"):
                script_entry = {
                    "port": port_id,
                    "protocol": protocol,
                    "script_id": script.get("id", ""),
                    "output": script.get("output", ""),
                }
                port_entry["scripts"].append(script_entry)
                script_results.append(script_entry)

            host_entry["ports"].append(port_entry)

            if state.lower() == "open":
                parsed_ports.append(
                    {
                        "port": port_id,
                        "protocol": protocol.lower(),
                        "state": state.lower(),
                        "service": service_name,
                        "version": version_text,
                        "product": product,
                        "extra_info": extra_info,
                    }
                )
                parsed_services.append(
                    {
                        "port": port_id,
                        "protocol": protocol.lower(),
                        "service": service_name,
                        "product": product,
                        "version": version_text,
                        "extra_info": extra_info,
                    }
                )

        for os_match in host.findall("os/osmatch"):
            match_entry = {
                "name": os_match.get("name", ""),
                "accuracy": os_match.get("accuracy", ""),
                "line": os_match.get("line", ""),
            }
            host_entry["os_matches"].append(match_entry)
            os_matches.append(match_entry)

        for hostscript in host.findall("hostscript/script"):
            script_results.append(
                {
                    "port": None,
                    "protocol": None,
                    "script_id": hostscript.get("id", ""),
                    "output": hostscript.get("output", ""),
                }
            )

        hosts.append(host_entry)

    return {
        "hosts": hosts,
        "parsed_ports": parsed_ports,
        "parsed_services": parsed_services,
        "os_matches": os_matches,
        "script_results": script_results,
        "parse_source": "xml",
    }


def parse_nmap_results(raw_output: str, xml_content: str | None = None) -> dict[str, Any]:
    """Prefer XML parsing and fall back to text parsing for open ports."""
    parsed = parse_nmap_xml(xml_content or "")
    if parsed["parsed_ports"]:
        return parsed

    text_ports = parse_nmap_open_ports(raw_output)
    return {
        "hosts": [],
        "parsed_ports": text_ports,
        "parsed_services": [
            {
                "port": item["port"],
                "protocol": item["protocol"],
                "service": item.get("service", ""),
                "product": "",
                "version": item.get("version", ""),
                "extra_info": "",
            }
            for item in text_ports
        ],
        "os_matches": [],
        "script_results": [],
        "parse_source": "text",
    }

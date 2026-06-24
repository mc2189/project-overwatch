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
    scan_stats: dict[str, Any] = {}

    runstats = root.find("runstats/finished")
    if runstats is not None:
        scan_stats = {
            "elapsed_seconds": runstats.get("elapsed"),
            "exit": runstats.get("exit"),
            "summary": runstats.get("summary", ""),
        }

    for host in root.findall("host"):
        host_status_el = host.find("status")
        host_state = host_status_el.get("state", "unknown") if host_status_el is not None else "unknown"
        if host_state not in (None, "up", "unknown"):
            hosts.append({"host_status": host_state, "addresses": [], "hostnames": [], "ports": [], "os_matches": []})
            continue

        addresses = []
        mac_address = ""
        mac_vendor = ""
        primary_ip = ""
        for addr in host.findall("address"):
            entry = {
                "addr": addr.get("addr", ""),
                "type": addr.get("addrtype", ""),
                "vendor": addr.get("vendor", "") or "",
            }
            addresses.append(entry)
            if entry["type"] == "ipv4" and not primary_ip:
                primary_ip = entry["addr"]
            if entry["type"] == "mac":
                mac_address = entry["addr"]
                mac_vendor = entry["vendor"]

        hostnames = [name.get("name", "") for name in host.findall("hostnames/hostname") if name.get("name")]

        host_entry: dict[str, Any] = {
            "host_status": host_state,
            "primary_ip": primary_ip,
            "mac_address": mac_address,
            "mac_vendor": mac_vendor,
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
            cpes = [cpe.text or "" for cpe in service_el.findall("cpe")] if service_el is not None else []
            cpes = [cpe for cpe in cpes if cpe]

            version_text = " ".join(part for part in [product, version, extra_info] if part).strip()

            port_entry = {
                "port": port_id,
                "protocol": protocol,
                "state": state,
                "service": service_name,
                "product": product,
                "version": version_text or version,
                "extra_info": extra_info,
                "cpes": cpes,
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
                        "cpes": cpes,
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
                        "cpes": cpes,
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

    primary_host = hosts[0] if hosts else {}
    return {
        "hosts": hosts,
        "primary_host": primary_host,
        "host_status": primary_host.get("host_status"),
        "primary_ip": primary_host.get("primary_ip"),
        "hostname": (primary_host.get("hostnames") or [None])[0],
        "mac_address": primary_host.get("mac_address"),
        "mac_vendor": primary_host.get("mac_vendor"),
        "parsed_ports": parsed_ports,
        "parsed_services": parsed_services,
        "os_matches": os_matches,
        "script_results": script_results,
        "scan_stats": scan_stats,
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

"""Lightweight IoT / device-role heuristics from LAN discovery hints."""

from __future__ import annotations

import re
from typing import Any

_ROLE_LABELS: dict[str, str] = {
    "router": "Router / gateway",
    "computer": "Computer / workstation",
    "phone": "Phone / tablet",
    "smart_tv": "Smart TV / streaming",
    "speaker": "Smart speaker / audio",
    "camera": "Camera / doorbell",
    "iot_hub": "Smart home hub",
    "printer": "Printer",
    "iot_unknown": "IoT / embedded device",
    "unknown": "Unknown device",
}

_HOSTNAME_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"(iphone|ipad|android|pixel|galaxy|oneplus)", re.I), "phone"),
    (re.compile(r"(macbook|imac|laptop|desktop|pc-|win-|thinkpad)", re.I), "computer"),
    (re.compile(r"(router|gateway|fw-|unifi|synology|nas)", re.I), "router"),
    (re.compile(r"(roku|firetv|appletv|bravia|tizen|lg-tv|samsung-tv|chromecast)", re.I), "smart_tv"),
    (re.compile(r"(echo|alexa|homepod|sonos|google-home|nest-audio)", re.I), "speaker"),
    (re.compile(r"(ring-|nest-cam|arlo|wyze|blink|camera)", re.I), "camera"),
    (re.compile(r"(hue|smartthings|hubitat|homeassistant|home-assistant)", re.I), "iot_hub"),
    (re.compile(r"(printer|hp-|epson|brother)", re.I), "printer"),
    (re.compile(r"(esp|esp32|esp8266|tasmota|shelly|meross|tplink|kasa)", re.I), "iot_unknown"),
)

_SERVICE_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"_googlecast\._tcp", re.I), "smart_tv"),
    (re.compile(r"_airplay\._tcp", re.I), "speaker"),
    (re.compile(r"_hap\._tcp", re.I), "iot_hub"),
    (re.compile(r"_ipp\._tcp|_printer\._tcp", re.I), "printer"),
    (re.compile(r"_smb\._tcp|_afpovertcp\._tcp", re.I), "computer"),
    (re.compile(r"_androidtvremote|_androidtv", re.I), "smart_tv"),
    (re.compile(r"_spotify-connect|_raop\._tcp", re.I), "speaker"),
)

_VENDOR_RULES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"amazon", re.I), "speaker"),
    (re.compile(r"google|android", re.I), "phone"),
    (re.compile(r"apple", re.I), "phone"),
    (re.compile(r"roku", re.I), "smart_tv"),
    (re.compile(r"sonos", re.I), "speaker"),
    (re.compile(r"ring", re.I), "camera"),
    (re.compile(r"espressif|tuya|shelly", re.I), "iot_unknown"),
)


def _match_rules(text: str, rules: tuple[tuple[re.Pattern[str], str], ...]) -> str | None:
    for pattern, role in rules:
        if pattern.search(text):
            return role
    return None


def classify_device_role(device: dict[str, Any]) -> dict[str, Any]:
    """Return role guess metadata for a LAN device row."""
    hostname = str(device.get("hostname") or "")
    vendor = str(device.get("dhcp_vendor_class") or "")
    services = " ".join(str(s) for s in (device.get("mdns_services") or []))
    haystack = " ".join(part for part in (hostname, vendor, services) if part)

    role = "unknown"
    signals: list[str] = []

    for label, value in (("hostname", hostname), ("vendor", vendor), ("mdns", services)):
        if not value:
            continue
        matched = _match_rules(value, _HOSTNAME_RULES if label == "hostname" else ())
        if matched:
            role = matched
            signals.append(f"{label} pattern")
            break

    if role == "unknown" and services:
        matched = _match_rules(services, _SERVICE_RULES)
        if matched:
            role = matched
            signals.append("mDNS service")

    if role == "unknown" and vendor:
        matched = _match_rules(vendor, _VENDOR_RULES)
        if matched:
            role = matched
            signals.append("DHCP vendor class")

    if role == "unknown" and hostname:
        matched = _match_rules(hostname, _HOSTNAME_RULES)
        if matched:
            role = matched
            signals.append("hostname pattern")

    if role == "unknown" and (device.get("mdns_services") or device.get("dhcp_vendor_class")):
        role = "iot_unknown"
        signals.append("generic IoT hints")

    confidence = "low"
    if len(signals) >= 2:
        confidence = "high"
    elif signals:
        confidence = "medium"

    return {
        "role": role,
        "role_label": _ROLE_LABELS.get(role, _ROLE_LABELS["unknown"]),
        "role_confidence": confidence,
        "role_signals": signals,
    }


def enrich_devices_with_roles(devices: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Attach IoT / device-role heuristics to LAN device rows."""
    enriched: list[dict[str, Any]] = []
    for device in devices:
        row = dict(device)
        row.update(classify_device_role(row))
        enriched.append(row)
    return enriched

"""Parse RDAP JSON responses into structured WHOIS/RDAP metadata."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any


def _parse_rdap_datetime(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = str(value).strip()
    if cleaned.endswith("Z"):
        cleaned = cleaned[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(cleaned).astimezone(timezone.utc).isoformat()
    except ValueError:
        return str(value)


def _vcard_value(vcard_array: list[Any] | None, prop: str) -> str | None:
    if not vcard_array or len(vcard_array) < 2:
        return None
    entries = vcard_array[1]
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, list) or len(entry) < 4:
            continue
        if entry[0] == prop:
            return str(entry[3]).strip() or None
    return None


def _entity_summary(entity: dict[str, Any]) -> dict[str, Any]:
    vcard = entity.get("vcardArray")
    return {
        "handle": entity.get("handle"),
        "roles": list(entity.get("roles") or []),
        "name": _vcard_value(vcard, "fn") or _vcard_value(vcard, "org"),
        "email": _vcard_value(vcard, "email"),
        "phone": _vcard_value(vcard, "tel"),
    }


def _events_map(events: list[dict[str, Any]] | None) -> dict[str, str | None]:
    mapped: dict[str, str | None] = {
        "registration": None,
        "expiration": None,
        "last_changed": None,
    }
    for event in events or []:
        action = str(event.get("eventAction") or "").strip().lower()
        parsed = _parse_rdap_datetime(event.get("eventDate"))
        if action in {"registration", "registered"}:
            mapped["registration"] = parsed
        elif action in {"expiration", "expiry", "expire"}:
            mapped["expiration"] = parsed
        elif action in {"last changed", "last update", "last updated"}:
            mapped["last_changed"] = parsed
    return mapped


def _nameserver_names(payload: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for item in payload.get("nameservers") or []:
        if isinstance(item, dict):
            name = item.get("ldhName") or item.get("unicodeName")
            if name:
                names.append(str(name).lower().rstrip("."))
    return sorted(set(names))


def _entity_by_roles(payload: dict[str, Any], roles: set[str]) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for entity in payload.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        entity_roles = {str(role).lower() for role in (entity.get("roles") or [])}
        if entity_roles & roles:
            matches.append(_entity_summary(entity))
    return matches


def parse_rdap_response(payload: dict[str, Any], *, query_value: str, target_type: str) -> dict[str, Any]:
    """Convert an RDAP JSON document into module parsed_data fields."""
    object_class = str(payload.get("objectClassName") or payload.get("type") or "").lower()
    events = _events_map(payload.get("events"))
    registrar_entities = _entity_by_roles(payload, {"registrar"})
    registrant_entities = _entity_by_roles(payload, {"registrant", "holder"})
    abuse_entities = _entity_by_roles(payload, {"abuse", "abuse mailbox"})
    registry_entities = _entity_by_roles(payload, {"registry", "iana registrar"})
    nameservers = _nameserver_names(payload)

    registrar = registrar_entities[0] if registrar_entities else None
    if not registrar and registry_entities:
        registrar = registry_entities[0]

    holder = registrant_entities[0] if registrant_entities else None
    if target_type == "ipv4" and not holder:
        network_holders = _entity_by_roles(payload, {"registrant", "administrative"})
        holder = network_holders[0] if network_holders else None

    abuse = abuse_entities[0] if abuse_entities else None

    links = [
        {"href": link.get("href"), "rel": link.get("rel"), "type": link.get("type")}
        for link in (payload.get("links") or [])
        if isinstance(link, dict) and link.get("href")
    ]
    notices = [
        {
            "title": notice.get("title"),
            "description": notice.get("description"),
        }
        for notice in (payload.get("notices") or [])
        if isinstance(notice, dict)
    ]

    return {
        "object_class": object_class or None,
        "handle": payload.get("handle"),
        "ldh_name": payload.get("ldhName") or query_value,
        "status": [str(item) for item in (payload.get("status") or []) if item],
        "events": events,
        "registrar": registrar,
        "registry": registry_entities[0] if registry_entities else None,
        "registrant": holder,
        "abuse_contact": abuse,
        "nameservers": nameservers,
        "entities": [
            _entity_summary(entity)
            for entity in (payload.get("entities") or [])
            if isinstance(entity, dict)
        ],
        "country": payload.get("country"),
        "network_name": payload.get("name"),
        "start_address": payload.get("startAddress"),
        "end_address": payload.get("endAddress"),
        "cidr": payload.get("cidr0_cidrs") or payload.get("cidr"),
        "links": links,
        "notices": notices,
        "port43": payload.get("port43"),
    }


def days_until_expiry(expiration_iso: str | None) -> int | None:
    if not expiration_iso:
        return None
    try:
        cleaned = expiration_iso
        if cleaned.endswith("Z"):
            cleaned = cleaned[:-1] + "+00:00"
        expiry = datetime.fromisoformat(cleaned)
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        delta = expiry - datetime.now(timezone.utc)
        return delta.days
    except ValueError:
        return None


def _whois_field(patterns: list[str], text: str) -> str | None:
    for pattern in patterns:
        match = re.search(pattern, text, re.IGNORECASE | re.MULTILINE)
        if match:
            value = match.group(match.lastindex or 1).strip()
            if value and value.lower() not in {"n/a", "redacted for privacy"}:
                return value
    return None


def parse_whois_text(text: str, *, query_value: str, target_type: str) -> dict[str, Any]:
    """Convert a port-43 WHOIS text response into an RDAP-like summary."""
    registrar_name = _whois_field(
        [
            r"^Registrar:\s*(.+)$",
            r"^Registrar Name:\s*(.+)$",
            r"^registrar:\s*(.+)$",
        ],
        text,
    )
    expiry = _whois_field(
        [
            r"^(Registry Expiry Date|Registrar Registration Expiration Date|Expiration Date|Expiry Date|paid-till):\s*(.+)$",
        ],
        text,
    )
    created = _whois_field(
        [
            r"^(Creation Date|Created On|Registered On|Registration Time):\s*(.+)$",
        ],
        text,
    )
    updated = _whois_field(
        [
            r"^(Updated Date|Last Updated On|Last Updated):\s*(.+)$",
        ],
        text,
    )
    abuse_email = _whois_field(
        [
            r"^Abuse Email:\s*(.+)$",
            r"^OrgAbuseEmail:\s*(.+)$",
            r"^abuse-mailbox:\s*(.+)$",
        ],
        text,
    )
    abuse_phone = _whois_field([r"^Abuse Phone:\s*(.+)$", r"^OrgAbusePhone:\s*(.+)$"], text)
    org_name = _whois_field([r"^OrgName:\s*(.+)$", r"^organisation:\s*(.+)$"], text)
    netname = _whois_field([r"^NetName:\s*(.+)$", r"^netname:\s*(.+)$"], text)
    country = _whois_field([r"^Country:\s*(.+)$", r"^country:\s*(.+)$"], text)

    nameservers = sorted(
        {
            match.group(1).lower().rstrip(".")
            for match in re.finditer(
                r"^(?:Name Server|nserver):\s*([a-z0-9.-]+)",
                text,
                re.IGNORECASE | re.MULTILINE,
            )
        }
    )
    statuses = sorted(
        {
            match.group(1).strip()
            for match in re.finditer(r"^(?:Domain Status|status):\s*(\S+)", text, re.IGNORECASE | re.MULTILINE)
        }
    )

    registrar = {"name": registrar_name, "handle": None, "roles": ["registrar"]} if registrar_name else None
    abuse = None
    if abuse_email or abuse_phone:
        abuse = {
            "email": abuse_email,
            "phone": abuse_phone,
            "name": "Abuse contact",
            "handle": None,
            "roles": ["abuse"],
        }

    return {
        "object_class": "domain" if target_type in {"domain", "url"} else "ip network",
        "handle": None,
        "ldh_name": query_value,
        "status": statuses,
        "events": {
            "registration": _parse_rdap_datetime(created) if created else None,
            "expiration": _parse_rdap_datetime(expiry) if expiry else None,
            "last_changed": _parse_rdap_datetime(updated) if updated else None,
        },
        "registrar": registrar,
        "registry": None,
        "registrant": {"name": org_name, "handle": None, "roles": ["registrant"]} if org_name else None,
        "abuse_contact": abuse,
        "nameservers": nameservers,
        "entities": [],
        "country": country,
        "network_name": netname,
        "start_address": query_value if target_type == "ipv4" else None,
        "end_address": query_value if target_type == "ipv4" else None,
        "cidr": None,
        "links": [],
        "notices": [],
        "port43": None,
        "whois_text_preview": text[:4000],
    }

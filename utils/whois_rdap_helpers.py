"""Target normalisation and IP classification helpers for WHOIS/RDAP lookups."""

from __future__ import annotations

import ipaddress
from typing import Any

from utils.target_detection import DOMAIN_PATTERN, get_target_type, normalize_target_value


def is_private_or_local_ipv4(value: str) -> bool:
    """Return True for RFC1918, loopback, link-local, and reserved IPv4 addresses."""
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError:
        return False
    if address.version != 4:
        return False
    return bool(
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
    )


def is_public_ipv4(value: str) -> bool:
    cleaned = value.strip()
    if get_target_type(cleaned) != "ipv4":
        return False
    return not is_private_or_local_ipv4(cleaned)


def normalise_whois_rdap_target(value: str) -> dict[str, Any]:
    """Normalise user input into module lookup fields."""
    original_target = value.strip()
    target_type = get_target_type(original_target)
    query_value = normalize_target_value(original_target, target_type)

    if target_type in {"domain", "url"}:
        domain_or_ip = query_value
    elif target_type == "ipv4":
        domain_or_ip = query_value
    else:
        domain_or_ip = query_value

    return {
        "original_target": original_target,
        "query_value": query_value,
        "target_type": target_type,
        "domain_or_ip": domain_or_ip,
        "is_private_ip": target_type == "ipv4" and is_private_or_local_ipv4(query_value),
        "is_valid": target_type in {"domain", "url", "ipv4"}
        and (
            target_type == "ipv4"
            or bool(DOMAIN_PATTERN.match(query_value))
        ),
    }

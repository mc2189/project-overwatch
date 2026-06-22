"""RDAP bootstrap lookup, retries, and port-43 WHOIS fallback."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
import time
from functools import lru_cache
from typing import Any
from urllib.parse import quote

import requests

IANA_DNS_BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
IANA_IPV4_BOOTSTRAP = "https://data.iana.org/rdap/ipv4.json"
RDAP_ORG_BASE = "https://rdap.org"
REQUEST_TIMEOUT = 20
USER_AGENT = "ProjectOverwatch/2.1 (passive RDAP/WHOIS lookup)"
RETRYABLE_STATUS_CODES = {429, 503}
MAX_RDAP_RETRIES = 2
RETRY_BACKOFF_SECONDS = 1.5


def _ipv4_to_int(value: str) -> int:
    return int(ipaddress.IPv4Address(value))


def _bootstrap_match_domain(domain: str, bootstrap: dict[str, Any]) -> str | None:
    labels = domain.lower().strip(".").split(".")
    for index in range(len(labels)):
        suffix = ".".join(labels[index:])
        for service_group in bootstrap.get("services") or []:
            if not isinstance(service_group, list):
                continue
            for entry in service_group:
                if not isinstance(entry, list) or len(entry) < 2:
                    continue
                suffixes, urls = entry[0], entry[1]
                if suffix in {str(item).lower() for item in suffixes} and urls:
                    return str(urls[0]).rstrip("/")
    return None


def _bootstrap_match_ipv4(ip: str, bootstrap: dict[str, Any]) -> str | None:
    address = ipaddress.IPv4Address(ip)
    best_url: str | None = None
    best_prefix = -1
    for service_group in bootstrap.get("services") or []:
        if not isinstance(service_group, list):
            continue
        for entry in service_group:
            if not isinstance(entry, list) or len(entry) < 2:
                continue
            prefixes, urls = entry[0], entry[1]
            if not urls:
                continue
            for prefix in prefixes:
                try:
                    network = ipaddress.ip_network(str(prefix), strict=False)
                except ValueError:
                    continue
                if network.version != 4:
                    continue
                if address in network and network.prefixlen > best_prefix:
                    best_url = str(urls[0]).rstrip("/")
                    best_prefix = network.prefixlen
    return best_url


@lru_cache(maxsize=2)
def _load_bootstrap(url: str) -> dict[str, Any]:
    response = requests.get(
        url,
        timeout=REQUEST_TIMEOUT,
        headers={"User-Agent": USER_AGENT, "Accept": "application/json"},
    )
    response.raise_for_status()
    payload = response.json()
    if not isinstance(payload, dict):
        raise ValueError(f"Unexpected bootstrap payload from {url}")
    return payload


def bootstrap_rdap_base_url(query_value: str, target_type: str) -> str | None:
    """Resolve an IANA bootstrap RDAP base URL for a domain or IPv4 target."""
    if target_type in {"domain", "url"}:
        bootstrap = _load_bootstrap(IANA_DNS_BOOTSTRAP)
        return _bootstrap_match_domain(query_value.lower(), bootstrap)
    if target_type == "ipv4":
        bootstrap = _load_bootstrap(IANA_IPV4_BOOTSTRAP)
        return _bootstrap_match_ipv4(query_value, bootstrap)
    return None


def _rdap_resource_urls(base_url: str, query_value: str, target_type: str) -> list[str]:
    encoded_domain = quote(query_value.lower(), safe="")
    encoded_ip = quote(query_value, safe="")
    if target_type in {"domain", "url"}:
        return [
            f"{base_url}/domain/{encoded_domain}",
            f"{base_url}/domains/domain/{encoded_domain}",
        ]
    return [
        f"{base_url}/ip/{encoded_ip}",
        f"{base_url}/ips/ip/{encoded_ip}",
    ]


def _request_rdap_url(
    url: str,
    *,
    session: requests.Session | None = None,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    http = session or requests
    meta: dict[str, Any] = {"rdap_url": url, "status_code": None, "attempts": 0}
    last_error: str | None = None

    for attempt in range(MAX_RDAP_RETRIES + 1):
        meta["attempts"] = attempt + 1
        try:
            response = http.get(
                url,
                timeout=REQUEST_TIMEOUT,
                headers={"User-Agent": USER_AGENT, "Accept": "application/rdap+json, application/json"},
            )
        except requests.Timeout:
            last_error = "RDAP lookup timed out."
            break
        except requests.RequestException as exc:
            last_error = f"RDAP lookup failed: {exc}"
            break

        meta["status_code"] = response.status_code
        if response.status_code in RETRYABLE_STATUS_CODES and attempt < MAX_RDAP_RETRIES:
            time.sleep(RETRY_BACKOFF_SECONDS * (attempt + 1))
            continue
        if response.status_code == 404:
            last_error = "RDAP object not found for this target."
            return None, meta
        if response.status_code >= 400:
            last_error = f"RDAP endpoint returned HTTP {response.status_code}."
            return None, meta

        try:
            payload = response.json()
        except ValueError:
            last_error = "RDAP endpoint returned a non-JSON response."
            return None, meta
        if not isinstance(payload, dict):
            last_error = "RDAP response was not a JSON object."
            return None, meta
        return payload, meta

    meta["error"] = last_error or "RDAP lookup unavailable."
    return None, meta


def fetch_rdap(
    query_value: str,
    target_type: str,
    *,
    session: requests.Session | None = None,
    skip_bootstrap: bool = False,
) -> tuple[dict[str, Any] | None, dict[str, Any]]:
    """Fetch RDAP using IANA bootstrap first, then rdap.org redirector."""
    lookup_type = "domain" if target_type in {"domain", "url"} else target_type
    attempts: list[dict[str, Any]] = []

    if not skip_bootstrap:
        try:
            base_url = bootstrap_rdap_base_url(query_value, lookup_type)
        except Exception as exc:
            base_url = None
            attempts.append({"source": "iana_bootstrap", "error": str(exc)})
        if base_url:
            for url in _rdap_resource_urls(base_url, query_value, lookup_type):
                payload, meta = _request_rdap_url(url, session=session)
                meta["source"] = "iana_bootstrap"
                attempts.append(meta)
                if payload is not None:
                    return payload, meta

    redirect_base = RDAP_ORG_BASE
    if lookup_type in {"domain", "url"}:
        redirect_urls = [f"{redirect_base}/domain/{quote(query_value.lower(), safe='')}"]
    else:
        redirect_urls = [f"{redirect_base}/ip/{quote(query_value, safe='')}"]
    for url in redirect_urls:
        payload, meta = _request_rdap_url(url, session=session)
        meta["source"] = "rdap.org"
        attempts.append(meta)
        if payload is not None:
            return payload, meta

    combined_error = attempts[-1].get("error") if attempts else "RDAP lookup unavailable."
    return None, {
        "rdap_url": attempts[-1].get("rdap_url") if attempts else None,
        "status_code": attempts[-1].get("status_code") if attempts else None,
        "error": combined_error,
        "attempts": attempts,
        "source": "rdap",
    }


def whois_port43_query(server: str, query: str, *, timeout: int = 15) -> str:
    """Perform a lightweight port-43 WHOIS query using the stdlib socket API."""
    host = server.strip().lower()
    if host.startswith("whois://"):
        host = host[8:]
    host = host.split("/")[0]
    with socket.create_connection((host, 43), timeout=timeout) as sock:
        sock.sendall(f"{query}\r\n".encode("utf-8"))
        chunks: list[bytes] = []
        while True:
            data = sock.recv(8192)
            if not data:
                break
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


def _follow_ip_whois_referrals(text: str, ip: str) -> tuple[str, str]:
    servers = ["whois.arin.net"]
    current = text
    for _ in range(3):
        match = re.search(r"ReferralServer:\s*whois://([^\s]+)", current, re.IGNORECASE)
        if not match:
            break
        server = match.group(1).split("/")[0]
        if server in servers:
            break
        servers.append(server)
        current = whois_port43_query(server, ip)
    return current, servers[-1]


def fetch_whois_fallback(
    query_value: str,
    target_type: str,
    *,
    port43_hint: str | None = None,
) -> tuple[str | None, dict[str, Any]]:
    """Fetch a raw WHOIS text response when RDAP is unavailable."""
    meta: dict[str, Any] = {"source": "whois", "whois_server": None}
    lookup_type = "domain" if target_type in {"domain", "url"} else target_type

    if lookup_type == "ipv4":
        try:
            text = whois_port43_query("whois.arin.net", f"n + {query_value}")
            text, server = _follow_ip_whois_referrals(text, query_value)
            meta["whois_server"] = server
            return text, meta
        except OSError as exc:
            meta["error"] = f"WHOIS lookup failed: {exc}"
            return None, meta

    servers: list[str] = []
    if port43_hint:
        servers.append(port43_hint)
    tld = query_value.lower().strip(".").split(".")[-1]
    servers.extend([f"whois.{tld}", "whois.iana.org"])
    seen: set[str] = set()
    for server in servers:
        if server in seen:
            continue
        seen.add(server)
        try:
            text = whois_port43_query(server, query_value.lower())
        except OSError:
            continue
        if text.strip():
            meta["whois_server"] = server
            return text, meta

    meta["error"] = "WHOIS lookup unavailable."
    return None, meta


def lookup_registration_metadata(
    query_value: str,
    target_type: str,
    *,
    options: dict[str, Any] | None = None,
    session: requests.Session | None = None,
) -> dict[str, Any]:
    """Resolve RDAP first, then WHOIS fallback. Supports mock and cache options."""
    options = options or {}
    if options.get("mock_rdap_response") is not None:
        return {
            "source": "rdap",
            "lookup_status": "completed",
            "payload": options["mock_rdap_response"],
            "meta": {"rdap_url": "mock://rdap", "status_code": 200, "mock": True, "source": "mock"},
            "whois_text": None,
            "whois_meta": None,
            "from_cache": False,
        }
    if options.get("mock_whois_text") is not None:
        return {
            "source": "whois",
            "lookup_status": "completed",
            "payload": None,
            "meta": {"source": "whois", "whois_server": "mock", "mock": True},
            "whois_text": options["mock_whois_text"],
            "whois_meta": {"source": "whois", "whois_server": "mock", "mock": True},
            "from_cache": False,
        }

    case_id = options.get("case_id")
    use_cache = options.get("use_cache", True)
    cache_key = f"{target_type}:{query_value.lower()}"
    if case_id is not None and use_cache:
        from utils.rdap_cache import get_rdap_cache_entry

        cached = get_rdap_cache_entry(int(case_id), cache_key)
        if cached:
            if cached.get("source") == "rdap" and cached.get("response_json"):
                try:
                    payload = json.loads(cached["response_json"])
                except json.JSONDecodeError:
                    payload = None
                if isinstance(payload, dict):
                    return {
                        "source": "rdap",
                        "lookup_status": "completed",
                        "payload": payload,
                        "meta": {
                            "rdap_url": cached.get("rdap_url"),
                            "source": "cache",
                            "cached_at": cached.get("fetched_at"),
                        },
                        "whois_text": None,
                        "whois_meta": None,
                        "from_cache": True,
                    }
            if cached.get("source") == "whois" and cached.get("response_json"):
                return {
                    "source": "whois",
                    "lookup_status": "completed",
                    "payload": None,
                    "meta": {"source": "cache", "cached_at": cached.get("fetched_at")},
                    "whois_text": cached["response_json"],
                    "whois_meta": {"source": "whois", "whois_server": cached.get("whois_server"), "cached": True},
                    "from_cache": True,
                }

    payload, meta = fetch_rdap(
        query_value,
        target_type if target_type != "url" else "domain",
        session=session,
        skip_bootstrap=bool(options.get("skip_bootstrap")),
    )
    if payload is not None:
        result = {
            "source": "rdap",
            "lookup_status": "completed",
            "payload": payload,
            "meta": meta,
            "whois_text": None,
            "whois_meta": None,
            "from_cache": False,
        }
        if case_id is not None and use_cache:
            from utils.rdap_cache import set_rdap_cache_entry

            set_rdap_cache_entry(
                int(case_id),
                cache_key,
                target_type if target_type != "url" else "domain",
                "rdap",
                json.dumps(payload),
                rdap_url=meta.get("rdap_url"),
            )
        return result

    port43_hint = None
    if isinstance(meta.get("attempts"), list):
        for attempt in meta["attempts"]:
            if attempt.get("port43"):
                port43_hint = attempt["port43"]

    whois_text, whois_meta = fetch_whois_fallback(
        query_value,
        target_type if target_type != "url" else "domain",
        port43_hint=port43_hint,
    )
    if whois_text:
        result = {
            "source": "whois",
            "lookup_status": "completed",
            "payload": None,
            "meta": meta,
            "whois_text": whois_text,
            "whois_meta": whois_meta,
            "from_cache": False,
        }
        if case_id is not None and use_cache:
            from utils.rdap_cache import set_rdap_cache_entry

            set_rdap_cache_entry(
                int(case_id),
                cache_key,
                target_type if target_type != "url" else "domain",
                "whois",
                whois_text,
                rdap_url=None,
                whois_server=(whois_meta or {}).get("whois_server"),
            )
        return result

    return {
        "source": "rdap",
        "lookup_status": "unavailable",
        "payload": None,
        "meta": meta,
        "whois_text": None,
        "whois_meta": whois_meta,
        "from_cache": False,
    }

"""Classify network service observations for port-aware HTTP/TLS planning."""

from __future__ import annotations

import re
from typing import Any

CLASS_HTTP_CANDIDATE = "http_candidate"
CLASS_HTTPS_CANDIDATE = "https_candidate"
CLASS_TLS_CANDIDATE = "tls_candidate"
CLASS_NON_WEB_SERVICE = "non_web_service"
CLASS_UNKNOWN_SERVICE = "unknown_service"

_CLASSIFICATION_LABELS: dict[str, str] = {
    CLASS_HTTP_CANDIDATE: "Web service",
    CLASS_HTTPS_CANDIDATE: "Web/TLS service",
    CLASS_TLS_CANDIDATE: "TLS service",
    CLASS_NON_WEB_SERVICE: "Non-web service",
    CLASS_UNKNOWN_SERVICE: "Unknown service",
}

_HTTP_HINT_PORTS = frozenset({80, 8080, 8000, 8888, 3000})
_HTTPS_HINT_PORTS = frozenset({443, 8443, 9443})
_CONDITIONAL_HTTP_PORTS = frozenset({5000, 7000})

_NON_WEB_SIGNATURES: tuple[tuple[str, frozenset[int]], ...] = (
    ("ssh", frozenset({22})),
    ("dns", frozenset({53})),
    ("ntp", frozenset({123})),
    ("smb", frozenset({445})),
    ("microsoft-ds", frozenset({445})),
    ("rdp", frozenset({3389})),
    ("ms-wbt-server", frozenset({3389})),
    ("vnc", frozenset({5900})),
    ("rtsp", frozenset({554, 5000, 7000})),
    ("kerberos", frozenset({88, 464})),
    ("ldap", frozenset({389, 636})),
    ("snmp", frozenset({161, 162})),
    ("smtp", frozenset({25, 465, 587})),
    ("pop3", frozenset({110, 995})),
    ("imap", frozenset({143, 993})),
)

_SERVICE_TOKEN_RE = re.compile(r"[a-z][a-z0-9+_.-]*")


def classification_label(classification: str) -> str:
    return _CLASSIFICATION_LABELS.get(classification, classification.replace("_", " ").title())


def _service_tokens(service_name: str | None, product: str | None = None, banner: str | None = None) -> set[str]:
    tokens: set[str] = set()
    for chunk in (service_name or "", product or "", banner or ""):
        for match in _SERVICE_TOKEN_RE.findall(chunk.lower()):
            tokens.add(match)
    return tokens


def _matches_non_web(tokens: set[str], port: int) -> str | None:
    for signature, ports in _NON_WEB_SIGNATURES:
        if signature in tokens and port in ports:
            return signature
        if signature in tokens and signature in {"ssh", "dns", "vnc", "rdp", "smb", "microsoft-ds"}:
            return signature
    return None


def _httpish_tokens(tokens: set[str]) -> bool:
    return bool(
        tokens
        & {
            "http",
            "http-alt",
            "https",
            "https-alt",
            "ssl",
            "ssl/http",
            "tls",
            "web",
            "www",
            "www-http",
            "nginx",
            "apache",
            "lighttpd",
        }
    )


def classify_service_observation(
    *,
    port: int,
    protocol: str = "tcp",
    service_name: str | None = None,
    product: str | None = None,
    banner: str | None = None,
    observation_text: str | None = None,
    module_source: str | None = None,
    prior_tls_handshake: bool = False,
    prior_certificate: bool = False,
    prior_http_response: bool = False,
) -> str:
    """Return a service classification label for planning HTTP/TLS checks."""
    tokens = _service_tokens(service_name, product, banner)
    if observation_text:
        tokens |= _service_tokens(observation_text)

    non_web = _matches_non_web(tokens, port)
    if non_web and not prior_http_response and not prior_tls_handshake:
        if non_web == "rtsp" and _httpish_tokens(tokens):
            pass
        else:
            return CLASS_NON_WEB_SERVICE

    if prior_http_response:
        scheme_hint = (service_name or "").lower()
        if "https" in scheme_hint or port in _HTTPS_HINT_PORTS:
            return CLASS_HTTPS_CANDIDATE
        return CLASS_HTTP_CANDIDATE

    if prior_tls_handshake or prior_certificate:
        if prior_http_response:
            return CLASS_HTTPS_CANDIDATE
        if _httpish_tokens(tokens) or port in _HTTPS_HINT_PORTS:
            return CLASS_HTTPS_CANDIDATE
        return CLASS_TLS_CANDIDATE

    if _httpish_tokens(tokens):
        if "https" in tokens or "ssl" in tokens or "tls" in tokens:
            return CLASS_HTTPS_CANDIDATE
        return CLASS_HTTP_CANDIDATE

    if port in _HTTPS_HINT_PORTS:
        return CLASS_HTTPS_CANDIDATE
    if port in _HTTP_HINT_PORTS:
        return CLASS_HTTP_CANDIDATE
    if port in _CONDITIONAL_HTTP_PORTS and _httpish_tokens(tokens):
        return CLASS_HTTP_CANDIDATE

    if module_source == "infra_tls_review" and prior_tls_handshake:
        return CLASS_TLS_CANDIDATE

    if tokens:
        return CLASS_UNKNOWN_SERVICE
    return CLASS_UNKNOWN_SERVICE


def recommended_checks_for_classification(classification: str) -> tuple[str, str]:
    """Return (recommended_check_label, reason) for journey table rows."""
    if classification == CLASS_HTTP_CANDIDATE:
        return "HTTP Header Review", "HTTP service discovered"
    if classification == CLASS_HTTPS_CANDIDATE:
        return "TLS Review + HTTP Header Review", "HTTPS service discovered"
    if classification == CLASS_TLS_CANDIDATE:
        return "TLS Review", "TLS service discovered"
    if classification == CLASS_NON_WEB_SERVICE:
        return "Service advisory", "Not an HTTP endpoint"
    return "Network Service Check", "Open port with limited service hint"


def service_advisory_label(service_name: str | None, port: int) -> str:
    name = (service_name or "service").lower()
    if "ssh" in name or port == 22:
        return "Remote access service (SSH)"
    if "vnc" in name or port == 5900:
        return "Remote access service (VNC)"
    if "rdp" in name or "wbt" in name or port == 3389:
        return "Remote access service (RDP)"
    if "smb" in name or "microsoft-ds" in name or port == 445:
        return "File sharing service (SMB)"
    if "rtsp" in name:
        return "Media/streaming service (RTSP)"
    return "Non-web service"

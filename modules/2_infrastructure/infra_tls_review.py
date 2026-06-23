"""Controlled SSL/TLS configuration review for Project Overwatch."""

from __future__ import annotations

import hashlib
import socket
import ssl
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from utils.api_module_helpers import request_timeout_seconds, respect_api_courtesy_delay
from utils.result_status import resolve_collection_status
from utils.security import is_private_or_local_ip
from utils.target_detection import DOMAIN_PATTERN, get_target_type, normalize_target_value

MODULE_ID = "infra_tls_review"
DEFAULT_PORT = 443
MIN_PORT = 1
MAX_PORT = 65535

_PROTOCOL_PROBE_ORDER: tuple[tuple[str, Any], ...] = (
    ("TLS 1.3", getattr(ssl.TLSVersion, "TLSv1_3", None)),
    ("TLS 1.2", getattr(ssl.TLSVersion, "TLSv1_2", None)),
    ("TLS 1.1", getattr(ssl.TLSVersion, "TLSv1_1", None)),
    ("TLS 1.0", getattr(ssl.TLSVersion, "TLSv1", None)),
)


def _format_cert_name(parts: tuple[tuple[str, str], ...] | list[tuple[tuple[str, str], ...]]) -> str | None:
    if not parts:
        return None
    flattened = dict(x[0] for x in parts[0]) if parts else {}
    return flattened.get("commonName") or flattened.get("organizationName")


def _parse_cert_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ"):
        try:
            parsed = datetime.strptime(value, fmt)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            continue
    return None


def _extract_san_dns_names(cert: dict[str, Any]) -> list[str]:
    names: list[str] = []
    for key, value in cert.get("subjectAltName") or []:
        if key == "DNS" and value:
            names.append(str(value))
    return sorted(set(names))


def parse_tls_target(
    target: str,
    *,
    target_type: str | None = None,
    port_override: int | None = None,
    sni_hostname: str | None = None,
) -> dict[str, Any]:
    """Derive host, port, and SNI from a domain, URL, or IPv4 target."""
    cleaned = target.strip()
    resolved_type = target_type or get_target_type(cleaned)
    host = ""
    port = DEFAULT_PORT
    sni: str | None = None

    if resolved_type == "url":
        parsed = urlparse(cleaned if "://" in cleaned else f"https://{cleaned}")
        host = (parsed.hostname or "").lower().rstrip(".")
        if parsed.port:
            port = parsed.port
        sni = host or None
    elif resolved_type == "domain":
        host = normalize_target_value(cleaned, "domain")
        sni = host or None
    elif resolved_type == "ipv4":
        host = normalize_target_value(cleaned, "ipv4")
        sni = (sni_hostname or "").strip().lower() or None
    else:
        return {
            "original_target": cleaned,
            "target_type": resolved_type,
            "host": "",
            "port": DEFAULT_PORT,
            "sni": None,
            "valid": False,
        }

    if port_override is not None:
        port = int(port_override)

    valid = bool(host) and MIN_PORT <= port <= MAX_PORT
    if resolved_type == "domain" and not DOMAIN_PATTERN.match(host):
        valid = False

    return {
        "original_target": cleaned,
        "target_type": resolved_type,
        "host": host,
        "port": port,
        "sni": sni,
        "valid": valid,
    }


def _probe_tls_version(
    host: str,
    port: int,
    sni: str | None,
    label: str,
    tls_version: Any,
    *,
    timeout: float,
) -> dict[str, Any]:
    if tls_version is None:
        return {
            "label": label,
            "tested": False,
            "accepted": None,
            "note": "not_supported_by_local_runtime",
        }
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    try:
        context.minimum_version = tls_version
        context.maximum_version = tls_version
    except (ValueError, ssl.SSLError) as exc:
        return {
            "label": label,
            "tested": False,
            "accepted": None,
            "note": "not_supported_by_local_runtime",
            "error": str(exc),
        }
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=sni or host) as secure:
                return {
                    "label": label,
                    "tested": True,
                    "accepted": True,
                    "negotiated": secure.version(),
                }
    except ssl.SSLError:
        return {"label": label, "tested": True, "accepted": False}
    except OSError as exc:
        return {"label": label, "tested": True, "accepted": False, "error": str(exc)}


def _perform_default_handshake(
    host: str,
    port: int,
    sni: str | None,
    *,
    timeout: float,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "success": False,
        "error": None,
        "tls": {"version": None, "cipher": None},
        "certificate": {
            "subject": None,
            "issuer": None,
            "serial_number": None,
            "not_before": None,
            "not_after": None,
            "days_until_expiry": None,
            "san_dns_names": [],
            "fingerprint_sha256": None,
            "hostname_valid": None,
            "chain_valid": None,
        },
        "raw_certificate": None,
    }

    verify_context = ssl.create_default_context()
    hostname_check = sni or (host if get_target_type(host) == "domain" else None)

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with verify_context.wrap_socket(sock, server_hostname=hostname_check) as secure:
                cert = secure.getpeercert()
                cert_bin = secure.getpeercert(binary_form=True)
                result["success"] = True
                result["tls"]["version"] = secure.version()
                cipher = secure.cipher()
                result["tls"]["cipher"] = cipher[0] if cipher else None
                result["certificate"]["subject"] = _format_cert_name(cert.get("subject", ()))
                result["certificate"]["issuer"] = _format_cert_name(cert.get("issuer", ()))
                result["certificate"]["serial_number"] = cert.get("serialNumber")
                not_before = _parse_cert_datetime(cert.get("notBefore"))
                not_after = _parse_cert_datetime(cert.get("notAfter"))
                if not_before:
                    result["certificate"]["not_before"] = not_before.isoformat()
                if not_after:
                    result["certificate"]["not_after"] = not_after.isoformat()
                    delta = not_after - datetime.now(timezone.utc)
                    result["certificate"]["days_until_expiry"] = delta.days
                result["certificate"]["san_dns_names"] = _extract_san_dns_names(cert)
                if cert_bin:
                    result["certificate"]["fingerprint_sha256"] = hashlib.sha256(cert_bin).hexdigest()
                result["certificate"]["hostname_valid"] = True if hostname_check else None
                result["certificate"]["chain_valid"] = True
                result["raw_certificate"] = {
                    "subject": cert.get("subject"),
                    "issuer": cert.get("issuer"),
                    "version": cert.get("version"),
                    "serialNumber": cert.get("serialNumber"),
                }
    except ssl.SSLCertVerificationError as exc:
        result["error"] = str(exc)
        result["certificate"]["chain_valid"] = False
        result["certificate"]["hostname_valid"] = False
    except ssl.SSLError as exc:
        result["error"] = str(exc)
        if "hostname" in str(exc).lower():
            result["certificate"]["hostname_valid"] = False
    except OSError as exc:
        result["error"] = str(exc)

    return result


def _probe_protocol_versions(
    host: str,
    port: int,
    sni: str | None,
    *,
    timeout: float,
) -> dict[str, Any]:
    probes: dict[str, Any] = {}
    for label, tls_constant in _PROTOCOL_PROBE_ORDER:
        respect_api_courtesy_delay()
        probes[label] = _probe_tls_version(host, port, sni, label, tls_constant, timeout=timeout)
    return probes


def _build_raw_output(data: dict[str, Any]) -> str:
    conn = data.get("connection") or {}
    tls = data.get("tls") or {}
    cert = data.get("certificate") or {}
    lines = [
        f"TLS review for {data.get('host')}:{data.get('port')}",
        f"SNI: {data.get('sni') or '(none)'}",
        f"Connection: {'success' if conn.get('success') else 'failed'}",
    ]
    if conn.get("error"):
        lines.append(f"Connection error: {conn['error']}")
    if tls.get("version"):
        lines.append(f"Negotiated TLS: {tls['version']} ({tls.get('cipher') or 'unknown cipher'})")
    if cert.get("subject"):
        lines.append(f"Certificate subject: {cert['subject']}")
    if cert.get("issuer"):
        lines.append(f"Issuer: {cert['issuer']}")
    if cert.get("not_after"):
        lines.append(f"Valid until: {cert['not_after']} ({cert.get('days_until_expiry')} days)")
    probes = (tls.get("protocol_probe") or {})
    if probes:
        lines.append("Protocol probes:")
        for label, probe in probes.items():
            if not probe.get("tested"):
                lines.append(f"  {label}: not tested ({probe.get('note')})")
            else:
                lines.append(f"  {label}: {'accepted' if probe.get('accepted') else 'rejected'}")
    return "\n".join(lines)


def _build_module_notes(data: dict[str, Any]) -> list[str]:
    notes: list[str] = []
    conn = data.get("connection") or {}
    cert = data.get("certificate") or {}
    if conn.get("success"):
        notes.append(
            f"TLS service observed on {data.get('host')}:{data.get('port')} during authorised TLS review."
        )
    if cert.get("subject"):
        notes.append(f"Certificate observed: {cert['subject']}")
    if cert.get("days_until_expiry") is not None and cert["days_until_expiry"] < 0:
        notes.append("Certificate appears expired (point-in-time result).")
    elif cert.get("days_until_expiry") is not None and cert["days_until_expiry"] <= 30:
        notes.append(f"Certificate expires within {cert['days_until_expiry']} days.")
    if data.get("warning"):
        notes.append(data["warning"])
    return notes


def _build_summary(data: dict[str, Any]) -> str:
    host = data.get("host") or "target"
    port = data.get("port") or DEFAULT_PORT
    conn = data.get("connection") or {}
    tls = data.get("tls") or {}
    if not conn.get("success"):
        error = conn.get("error") or "connection failed"
        return f"TLS review for {host}:{port} could not complete: {error}"
    version = tls.get("version") or "unknown"
    cert = data.get("certificate") or {}
    subject = cert.get("subject") or "unknown subject"
    return (
        f"TLS review completed for {host}:{port}: {version} negotiated; "
        f"certificate subject {subject!r}."
    )


def run_tls_review(target: str, options: dict[str, Any] | None = None) -> dict[str, Any]:
    """Perform a controlled TLS certificate and configuration review."""
    options = options or {}
    port_override = options.get("port_override")
    if port_override is not None:
        try:
            port_override = int(port_override)
        except (TypeError, ValueError):
            port_override = None
    if port_override is not None and not (MIN_PORT <= port_override <= MAX_PORT):
        port_override = None

    parsed_target = parse_tls_target(
        target,
        target_type=options.get("target_type"),
        port_override=port_override,
        sni_hostname=options.get("sni_hostname"),
    )

    base_data: dict[str, Any] = {
        "target": parsed_target.get("original_target"),
        "host": parsed_target.get("host"),
        "port": parsed_target.get("port"),
        "sni": parsed_target.get("sni"),
        "target_type": parsed_target.get("target_type"),
        "connection": {"success": False, "error": None},
        "tls": {"version": None, "cipher": None, "protocol_probe": {}},
        "certificate": {
            "subject": None,
            "issuer": None,
            "serial_number": None,
            "not_before": None,
            "not_after": None,
            "days_until_expiry": None,
            "san_dns_names": [],
            "hostname_valid": None,
            "chain_valid": None,
            "fingerprint_sha256": None,
        },
        "warning": None,
    }

    if not parsed_target.get("valid"):
        message = f"Invalid or unsupported target for TLS review: {target}"
        return {
            "module_id": MODULE_ID,
            "success": False,
            "status": "blocked",
            "summary": message,
            "raw_output": message,
            "findings": [],
            "warnings": [],
            "errors": [message],
            "data": base_data,
        }

    if options.get("mock_data") is not None:
        base_data.update(options["mock_data"])
        status = resolve_collection_status(warnings=base_data.get("warnings") or [], has_core_data=True)
        return {
            "module_id": MODULE_ID,
            "success": True,
            "status": status,
            "summary": _build_summary(base_data),
            "raw_output": _build_raw_output(base_data),
            "findings": _build_module_notes(base_data),
            "warnings": list(base_data.get("warnings") or []),
            "errors": [],
            "data": base_data,
        }

    timeout = float(request_timeout_seconds())
    warnings: list[str] = []

    if parsed_target.get("target_type") == "ipv4" and is_private_or_local_ip(parsed_target["host"]):
        warnings.append(
            "Private/local IP target — TLS review proceeds only when engagement scope and ROE permit safe active testing."
        )

    respect_api_courtesy_delay()
    handshake = _perform_default_handshake(
        parsed_target["host"],
        int(parsed_target["port"]),
        parsed_target.get("sni"),
        timeout=timeout,
    )

    base_data["connection"]["success"] = handshake["success"]
    base_data["connection"]["error"] = handshake.get("error")
    base_data["tls"]["version"] = handshake["tls"]["version"]
    base_data["tls"]["cipher"] = handshake["tls"]["cipher"]
    base_data["certificate"].update(handshake["certificate"])
    base_data["raw_certificate"] = handshake.get("raw_certificate")

    if options.get("protocol_probes", True) and handshake["success"]:
        base_data["tls"]["protocol_probe"] = _probe_protocol_versions(
            parsed_target["host"],
            int(parsed_target["port"]),
            parsed_target.get("sni"),
            timeout=timeout,
        )
        for probe in base_data["tls"]["protocol_probe"].values():
            if probe.get("note") == "not_supported_by_local_runtime":
                warnings.append(
                    f"Protocol probe {probe.get('label')}: not supported by local Python/OpenSSL runtime."
                )

    if handshake.get("error") and not handshake["success"]:
        warnings.append(f"TLS connection note: {handshake['error']}")

    has_core_data = handshake["success"] or bool(handshake.get("error"))
    status = resolve_collection_status(warnings=warnings, has_core_data=has_core_data)
    success = status in {"completed", "completed_with_warnings", "partial"}

    return {
        "module_id": MODULE_ID,
        "success": success,
        "status": status,
        "summary": _build_summary(base_data),
        "raw_output": _build_raw_output(base_data),
        "findings": _build_module_notes(base_data),
        "warnings": warnings,
        "errors": warnings if status == "error" else [],
        "data": base_data,
    }

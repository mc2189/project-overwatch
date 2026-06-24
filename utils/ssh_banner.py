"""SSH banner parsing and safe connection helpers."""

from __future__ import annotations

import re
import socket
from typing import Any

DEFAULT_SSH_PORT = 22
MIN_PORT = 1
MAX_PORT = 65535

_SSH_BANNER_RE = re.compile(
    r"^(?P<protocol>SSH-(?:1\.99|2\.0|1\.5))(?:-(?P<software>.+))?$",
    re.IGNORECASE,
)


def validate_port(value: Any) -> int | None:
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    if MIN_PORT <= port <= MAX_PORT:
        return port
    return None


def parse_ssh_banner(banner: str | None) -> dict[str, Any]:
    """Parse an SSH identification string."""
    if not banner:
        return {
            "raw_banner": None,
            "protocol": None,
            "software": None,
            "version": None,
            "software_family": None,
        }
    cleaned = banner.strip().splitlines()[0][:240]
    match = _SSH_BANNER_RE.match(cleaned)
    if not match:
        return {
            "raw_banner": cleaned,
            "protocol": None,
            "software": None,
            "version": None,
            "software_family": None,
        }
    software = (match.group("software") or "").strip()
    software_family = None
    version = None
    if software:
        if software.lower().startswith("openssh"):
            software_family = "OpenSSH"
            version = software.split("_", 1)[1] if "_" in software else None
        elif "dropbear" in software.lower():
            software_family = "Dropbear"
            version = software.split("_", 1)[1] if "_" in software else None
        else:
            software_family = software.split("_", 1)[0][:80]
            version = software.split("_", 1)[1] if "_" in software else None
    return {
        "raw_banner": cleaned,
        "protocol": match.group("protocol"),
        "software": software or None,
        "version": version,
        "software_family": software_family,
    }


def is_ssh_service_row(row: dict[str, Any]) -> bool:
    service = str(row.get("service_name") or row.get("service") or "").lower()
    product = str(row.get("product") or "").lower()
    try:
        port = int(row.get("port"))
    except (TypeError, ValueError):
        port = None
    if port == 22:
        return True
    return "ssh" in service or "ssh" in product


def filter_ssh_services(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [dict(row) for row in rows if is_ssh_service_row(row)]


def fetch_ssh_banner(host: str, port: int, *, timeout: float) -> dict[str, Any]:
    """Perform a single lightweight banner read — no authentication."""
    result: dict[str, Any] = {
        "success": False,
        "error": None,
        "banner": None,
        "parsed_banner": {},
    }
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            data = sock.recv(512)
            if not data:
                result["error"] = "no banner received"
                return result
            banner = data.decode("utf-8", errors="replace").strip()
            result["banner"] = banner
            result["parsed_banner"] = parse_ssh_banner(banner)
            result["success"] = banner.upper().startswith("SSH-")
            if not result["success"]:
                result["error"] = "response is not an SSH identification string"
    except OSError as exc:
        result["error"] = str(exc)
    return result


def fetch_optional_ssh_metadata(host: str, port: int, *, timeout: float) -> dict[str, Any] | None:
    """Collect handshake metadata via Paramiko when available — no authentication."""
    try:
        import paramiko
    except ImportError:
        return None
    metadata: dict[str, Any] = {"backend": "paramiko"}
    transport = None
    try:
        transport = paramiko.Transport((host, port))
        transport.start_client(timeout=timeout)
        security = transport.get_security_options()
        metadata["key_exchange"] = list(getattr(security, "kex", []) or [])[:20]
        metadata["host_key_types"] = list(getattr(security, "key_types", []) or [])[:20]
        metadata["ciphers"] = list(getattr(security, "ciphers", []) or [])[:20]
        metadata["macs"] = list(getattr(security, "macs", []) or [])[:20]
        metadata["compression"] = list(getattr(security, "compression", []) or [])[:10]
        remote_version = getattr(transport, "remote_version", None)
        if remote_version:
            metadata["remote_version"] = str(remote_version)[:200]
        return metadata
    except Exception as exc:
        metadata["error"] = str(exc)[:200]
        return metadata
    finally:
        if transport is not None:
            try:
                transport.close()
            except Exception:
                pass

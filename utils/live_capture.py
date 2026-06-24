"""Personal Lab live packet capture helpers — bounded subprocess capture."""

from __future__ import annotations

import grp
import hashlib
import os
import platform
import re
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from utils.security import is_safe_target_string, redact_secrets_from_text
from utils.target_detection import IPv4_PATTERN, get_target_type

PROJECT_ROOT = Path(__file__).resolve().parent.parent

DEFAULT_DURATION_SECONDS = 30
MAX_DURATION_SECONDS = 120
DEFAULT_PACKET_CAP = 1000
MAX_PACKET_CAP = 10_000

PERSONAL_LAB_CAPTURE_CONFIRMATION = (
    "I confirm this capture is on my own system, home network, lab environment, "
    "test asset, or otherwise authorised."
)

FILTER_PRESETS: dict[str, dict[str, str]] = {
    "all_traffic": {"label": "All traffic", "bpf": ""},
    "target_host": {"label": "Traffic involving target host", "bpf": ""},
    "web_traffic": {"label": "Web traffic", "bpf": "tcp port 80 or tcp port 443"},
    "dns_only": {"label": "DNS only", "bpf": "port 53"},
    "arp_dhcp": {"label": "ARP/DHCP", "bpf": "arp or port 67 or port 68"},
    "icmp_only": {"label": "ICMP only", "bpf": "icmp"},
}

_UNSAFE_BPF_RE = re.compile(r"[;&|`$<>]")
_INTERFACE_LINE_RE = re.compile(r"^\s*(\d+)\.\s*(\S+)(?:\s+(.*))?$")
_PACKETS_CAPTURED_RE = re.compile(r"(\d+)\s+packets?\s+captured", re.I)
_PERMISSION_MARKERS = (
    "permission denied",
    "operation not permitted",
    "not permitted",
    "requires root",
    "you don't have permission",
    "access denied",
    "bpf permission",
)


def tshark_available() -> bool:
    return shutil.which("tshark") is not None


def tcpdump_available() -> bool:
    return shutil.which("tcpdump") is not None


def capture_backend_status() -> dict[str, Any]:
    tshark = tshark_available()
    tcpdump = tcpdump_available()
    selected = None
    if tshark:
        selected = "tshark"
    elif tcpdump:
        selected = "tcpdump"
    return {
        "tshark_available": tshark,
        "tcpdump_available": tcpdump,
        "selected_backend": selected,
        "any_available": bool(selected),
    }


def validate_duration(seconds: int | float) -> tuple[int, str | None]:
    try:
        value = int(seconds)
    except (TypeError, ValueError):
        return DEFAULT_DURATION_SECONDS, "Duration must be a whole number of seconds."
    if value < 1:
        return DEFAULT_DURATION_SECONDS, "Duration must be at least 1 second."
    if value > MAX_DURATION_SECONDS:
        return MAX_DURATION_SECONDS, f"Duration capped at {MAX_DURATION_SECONDS} seconds."
    return value, None


def validate_packet_cap(count: int) -> tuple[int, str | None]:
    try:
        value = int(count)
    except (TypeError, ValueError):
        return DEFAULT_PACKET_CAP, "Packet cap must be a whole number."
    if value < 1:
        return DEFAULT_PACKET_CAP, "Packet cap must be at least 1."
    if value > MAX_PACKET_CAP:
        return MAX_PACKET_CAP, f"Packet cap limited to {MAX_PACKET_CAP:,} packets."
    return value, None


def _parse_interface_line(line: str) -> dict[str, str] | None:
    """Parse tshark -D or tcpdump -D lines (macOS tcpdump uses '1.en0' without a space)."""
    match = _INTERFACE_LINE_RE.match(line.strip())
    if not match:
        return None
    index = match.group(1)
    iface_id = match.group(2).strip()
    tail = (match.group(3) or "").strip()
    label = f"{iface_id} {tail}".strip() if tail else iface_id
    friendly = iface_id
    if tail.startswith("(") and ")" in tail:
        friendly = tail.strip("()").split(")")[0].strip() or iface_id
    elif tail.startswith("[") and "]" in tail:
        inner = tail[1 : tail.index("]")]
        friendly = inner.split(",")[0].strip() if inner else iface_id
    return {
        "index": index,
        "id": iface_id,
        "label": label,
        "friendly": friendly,
    }


def list_capture_interfaces() -> tuple[list[dict[str, str]], str | None]:
    """Return discovered interfaces from tshark or tcpdump."""
    command: list[str] | None = None
    if tshark_available():
        command = ["tshark", "-D"]
    elif tcpdump_available():
        command = ["tcpdump", "-D"]
    if command is None:
        return [], "Install Wireshark/tshark or tcpdump to list network interfaces."

    try:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return [], f"Interface discovery failed: {exc}"

    if completed.returncode != 0:
        stderr = (completed.stderr or completed.stdout or "").strip()
        return [], stderr or "Interface discovery command failed."

    interfaces: list[dict[str, str]] = []
    output = (completed.stdout or "").strip()
    if not output and completed.stderr:
        output = completed.stderr.strip()
    for line in output.splitlines():
        parsed = _parse_interface_line(line)
        if parsed:
            interfaces.append(parsed)
    if not interfaces:
        snippet = (output or completed.stderr or "")[:300]
        return [], (
            "No interfaces were returned by the capture tool."
            + (f" Raw output: {snippet}" if snippet else "")
        )
    return interfaces, None


def default_interface(interfaces: list[dict[str, str]]) -> str | None:
    if not interfaces:
        return None

    def _score(iface: dict[str, str]) -> int:
        label = (iface.get("label") or "").lower()
        iface_id = (iface.get("id") or "").lower()
        score = 0
        if "associated" in label and "not associated" not in label:
            score += 20
        if "wireless" in label or "wi-fi" in label or "wifi" in label:
            score += 10
        if iface_id == "en0":
            score += 15
        if iface_id in {"lo", "lo0", "nflog", "nfqueue", "any", "ap1"}:
            score -= 10
        if "disconnected" in label or "not associated" in label:
            score -= 5
        return score

    ranked = sorted(interfaces, key=_score, reverse=True)
    return ranked[0]["id"]


def validate_interface(interface_id: str, interfaces: list[dict[str, str]]) -> str | None:
    cleaned = interface_id.strip()
    if not cleaned:
        return "Select a network interface."
    allowed = {item["id"] for item in interfaces}
    if cleaned not in allowed:
        return "Selected interface is not in the discovered interface list."
    if not is_safe_target_string(cleaned, max_length=64):
        return "Interface name contains unsafe characters."
    return None


def build_host_filter(target: str) -> tuple[str | None, str | None]:
    cleaned = target.strip()
    if not cleaned:
        return None, "Enter a host IP or domain for this filter preset."
    if not is_safe_target_string(cleaned, max_length=253):
        return None, "Target host contains unsafe characters."
    target_type = get_target_type(cleaned)
    if target_type not in {"ipv4", "domain"}:
        if IPv4_PATTERN.match(cleaned):
            host = cleaned
        else:
            return None, "Target host must be an IPv4 address or domain name."
    else:
        host = cleaned.lower() if target_type == "domain" else cleaned
    return f"host {host}", None


def build_bpf_filter(
    preset: str,
    *,
    target_host: str = "",
    custom_filter: str = "",
) -> tuple[str, str | None]:
    if preset == "custom":
        bpf = custom_filter.strip()
        if not bpf:
            return "", None
        if _UNSAFE_BPF_RE.search(bpf):
            return "", "Custom filter contains disallowed characters."
        return bpf, None
    if preset not in FILTER_PRESETS:
        return "", f"Unknown filter preset: {preset}"
    if preset == "target_host":
        return build_host_filter(target_host)
    return FILTER_PRESETS[preset]["bpf"], None


def live_capture_dir(case_id: int) -> Path:
    dest = PROJECT_ROOT / "database" / "evidence_files" / f"case_{case_id}" / "live_captures"
    dest.mkdir(parents=True, exist_ok=True)
    return dest


def preview_output_filename(interface_id: str | None) -> str:
    stamp = datetime.now(tz=timezone.utc).strftime("%Y%m%d_%H%M%S")
    iface = (interface_id or "capture").strip() or "capture"
    safe_iface = re.sub(r"[^\w.\-]+", "_", iface)[:32]
    return f"lab_capture_{safe_iface}_{stamp}.pcap"


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _permission_issue(text: str) -> bool:
    lowered = text.lower()
    return any(marker in lowered for marker in _PERMISSION_MARKERS)


def _parse_packets_captured(text: str) -> int | None:
    match = _PACKETS_CAPTURED_RE.search(text)
    if match:
        return int(match.group(1))
    return None


def macos_capture_permission_status() -> dict[str, Any] | None:
    """Return macOS BPF capture readiness for the current process, or None on other OSes."""
    if platform.system() != "Darwin":
        return None

    access_bpf_exists = False
    in_access_bpf = False
    try:
        bpf_group = grp.getgrnam("access_bpf")
        access_bpf_exists = True
        in_access_bpf = bpf_group.gr_gid in os.getgroups()
    except KeyError:
        pass

    bpf_devices_group_accessible = False
    bpf0 = Path("/dev/bpf0")
    if bpf0.exists():
        bpf_devices_group_accessible = bool(bpf0.stat().st_mode & 0o066)

    can_open_bpf = False
    if bpf0.exists():
        try:
            fd = os.open(str(bpf0), os.O_RDONLY)
            os.close(fd)
            can_open_bpf = True
        except OSError:
            pass

    return {
        "access_bpf_group_exists": access_bpf_exists,
        "in_access_bpf_group": in_access_bpf,
        "bpf_devices_group_accessible": bpf_devices_group_accessible,
        "can_open_bpf": can_open_bpf,
        "ready": can_open_bpf,
    }


def macos_capture_permission_guidance() -> list[str]:
    """Step-by-step guidance when macOS blocks unprivileged packet capture."""
    return [
        "Install Wireshark (recommended) — it includes the ChmodBPF helper.",
        "Run ChmodBPF once with admin rights, e.g. "
        "`sudo \"/Library/Application Support/Wireshark/ChmodBPF/ChmodBPF\"` "
        "(Homebrew installs may use a different path under /opt/homebrew).",
        "Log out and back in (or restart) so your user picks up the `access_bpf` group.",
        "Verify with `id` — you should see `access_bpf` in the group list.",
        "Restart Streamlit from Terminal.app if you launched it from an IDE terminal "
        "before the group change took effect.",
        "Quick test: `tcpdump -i en0 -c 5 -w /tmp/test.pcap` should run without sudo.",
        "Workaround: run the suggested capture command in Terminal with `sudo`, then upload "
        "the PCAP via Uploaded evidence review.",
    ]


def build_tshark_command(
    *,
    interface_id: str,
    output_path: Path,
    duration_seconds: int,
    packet_cap: int,
    bpf_filter: str,
) -> list[str]:
    cmd = [
        "tshark",
        "-i",
        interface_id,
        "-a",
        f"duration:{duration_seconds}",
        "-c",
        str(packet_cap),
        "-w",
        str(output_path),
    ]
    if bpf_filter:
        cmd.extend(["-f", bpf_filter])
    return cmd


def build_tcpdump_command(
    *,
    interface_id: str,
    output_path: Path,
    packet_cap: int,
    bpf_filter: str,
) -> list[str]:
    cmd = ["tcpdump", "-i", interface_id, "-c", str(packet_cap), "-w", str(output_path)]
    if bpf_filter:
        cmd.append(bpf_filter)
    return cmd


def format_manual_command(cmd: list[str]) -> str:
    return " ".join(cmd)


def run_live_packet_capture(
    *,
    case_id: int,
    interface_id: str,
    interfaces: list[dict[str, str]],
    duration_seconds: int,
    packet_cap: int,
    bpf_filter: str,
    filter_preset: str,
    backend: str | None = None,
    output_filename: str | None = None,
) -> dict[str, Any]:
    """Run a bounded live capture to a controlled case folder."""
    status = capture_backend_status()
    selected = backend or status["selected_backend"]
    if not selected:
        return {
            "success": False,
            "status": "blocked",
            "errors": ["Capture backend unavailable — install tshark or tcpdump."],
            "warnings": [],
            "capture": {},
        }

    iface_error = validate_interface(interface_id, interfaces)
    if iface_error:
        return {
            "success": False,
            "status": "blocked",
            "errors": [iface_error],
            "warnings": [],
            "capture": {},
        }

    duration, duration_warning = validate_duration(duration_seconds)
    packet_cap, cap_warning = validate_packet_cap(packet_cap)
    warnings = [msg for msg in (duration_warning, cap_warning) if msg]

    filename = output_filename or preview_output_filename(interface_id)
    output_path = live_capture_dir(case_id) / filename
    output_path.parent.mkdir(parents=True, exist_ok=True)

    if selected == "tshark":
        cmd = build_tshark_command(
            interface_id=interface_id,
            output_path=output_path,
            duration_seconds=duration,
            packet_cap=packet_cap,
            bpf_filter=bpf_filter,
        )
        timeout = duration + 15
    else:
        cmd = build_tcpdump_command(
            interface_id=interface_id,
            output_path=output_path,
            packet_cap=packet_cap,
            bpf_filter=bpf_filter,
        )
        timeout = duration + 15

    try:
        completed = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        if output_path.is_file() and output_path.stat().st_size > 0:
            completed = None
        else:
            return {
                "success": False,
                "status": "error",
                "errors": ["Capture timed out without producing a usable file."],
                "warnings": warnings,
                "capture": {
                    "backend": selected,
                    "command": cmd,
                    "manual_command": format_manual_command(cmd),
                },
            }
    except OSError as exc:
        return {
            "success": False,
            "status": "error",
            "errors": [f"Capture failed to start: {exc}"],
            "warnings": warnings,
            "capture": {
                "backend": selected,
                "command": cmd,
                "manual_command": format_manual_command(cmd),
            },
        }

    stderr = ""
    stdout = ""
    return_code = 0
    if completed is not None:
        stderr = completed.stderr or ""
        stdout = completed.stdout or ""
        return_code = completed.returncode

    combined = f"{stdout}\n{stderr}".strip()
    if not output_path.is_file() or output_path.stat().st_size == 0:
        if _permission_issue(combined):
            return {
                "success": False,
                "status": "blocked",
                "errors": [
                    "Capture permission denied. On macOS, grant capture permissions to Terminal/"
                    "Python or run Wireshark/tshark with suitable local capture rights."
                ],
                "warnings": warnings,
                "capture": {
                    "backend": selected,
                    "interface": interface_id,
                    "duration_seconds": duration,
                    "packet_cap": packet_cap,
                    "filter_preset": filter_preset,
                    "bpf_filter": bpf_filter,
                    "command": cmd,
                    "manual_command": format_manual_command(cmd),
                    "permission_denied": True,
                    "stderr": redact_secrets_from_text(stderr[:2000]),
                },
            }
        return {
            "success": False,
            "status": "error",
            "errors": [
                redact_secrets_from_text(
                    (stderr or stdout or "Capture produced no output file.").strip()[:500]
                )
            ],
            "warnings": warnings,
            "capture": {
                "backend": selected,
                "interface": interface_id,
                "duration_seconds": duration,
                "packet_cap": packet_cap,
                "filter_preset": filter_preset,
                "bpf_filter": bpf_filter,
                "command": cmd,
                "manual_command": format_manual_command(cmd),
                "return_code": return_code,
            },
        }

    file_size = output_path.stat().st_size
    file_hash = sha256_file(output_path)
    capped_by_duration = duration_warning is not None or duration >= MAX_DURATION_SECONDS
    capped_by_packets = cap_warning is not None or packet_cap >= MAX_PACKET_CAP
    if return_code != 0 and file_size > 0:
        warnings.append("Capture tool reported a non-zero exit code but a PCAP file was saved.")

    packets_captured = _parse_packets_captured(combined)

    return {
        "success": True,
        "status": "completed_with_warnings" if warnings else "completed",
        "errors": [],
        "warnings": warnings,
        "capture": {
            "backend": selected,
            "interface": interface_id,
            "duration_seconds": duration,
            "packet_cap": packet_cap,
            "filter_preset": filter_preset,
            "bpf_filter": bpf_filter,
            "filename": filename,
            "file_size_bytes": file_size,
            "sha256": file_hash,
            "storage_path": str(output_path),
            "command": cmd,
            "manual_command": format_manual_command(cmd),
            "capped_by_duration": capped_by_duration,
            "capped_by_packet_count": capped_by_packets,
            "return_code": return_code,
            "packets_captured": packets_captured,
            "stderr": redact_secrets_from_text(stderr[:1000]) if stderr else "",
        },
    }

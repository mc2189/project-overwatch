"""Runtime privilege detection helpers."""

import os
from typing import Literal

PrivilegeIssue = Literal["os_detection", "traceroute"]


def has_root_privileges() -> bool:
    """Return True when the current process has elevated (root) privileges."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False


def detect_nmap_privilege_issue(output_text: str) -> PrivilegeIssue | None:
    """Detect privilege-related Nmap failures from stdout/stderr text."""
    if not output_text:
        return None

    lower = output_text.lower()

    if "traceroute" in lower and "root" in lower:
        return "traceroute"

    os_markers = (
        "requires root privileges",
        "tcp/ip fingerprinting",
        "os scan",
        "osscan",
        "fingerprinting",
    )
    if any(marker in lower for marker in os_markers) and "root" in lower:
        return "os_detection"

    return None


def privilege_option_fields() -> dict[str, bool]:
    """Return default privilege-tracking fields for normalized Nmap options."""
    return {
        "os_detection_requested": False,
        "os_detection_skipped": False,
        "os_detection_runtime_failed": False,
        "traceroute_requested": False,
        "traceroute_skipped": False,
        "traceroute_runtime_failed": False,
    }

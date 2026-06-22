"""Runtime privilege detection helpers."""

import os


def has_root_privileges() -> bool:
    """Return True when the current process has elevated (root) privileges."""
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

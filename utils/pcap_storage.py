"""Safe local storage helpers for uploaded PCAP evidence files."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent

_SAFE_NAME_RE = re.compile(r"[^\w.\-]+")


def _case_pcap_dir(case_id: int) -> Path:
    dest = PROJECT_ROOT / "database" / "evidence_files" / f"case_{case_id}" / "pcap_uploads"
    dest.mkdir(parents=True, exist_ok=True)
    return dest


def sanitise_upload_filename(filename: str) -> str:
    base = Path(filename).name.strip() or "capture.pcap"
    cleaned = _SAFE_NAME_RE.sub("_", base)
    return cleaned[:120]


def store_pcap_upload(
    case_id: int,
    filename: str,
    data: bytes,
    *,
    sha256: str | None = None,
) -> dict[str, Any]:
    """Persist uploaded capture bytes under the case evidence area."""
    digest = sha256 or hashlib.sha256(data).hexdigest()
    safe_name = sanitise_upload_filename(filename)
    dest_dir = _case_pcap_dir(case_id)
    dest = dest_dir / f"{digest[:16]}_{safe_name}"
    if not dest.is_file():
        dest.write_bytes(data)
    return {
        "filename": safe_name,
        "sha256": digest,
        "size_bytes": len(data),
        "storage_path": str(dest),
        "display_ref": f"{safe_name} ({digest[:12]}…)",
    }


def write_temporary_pcap_bytes(
    case_id: int,
    filename: str,
    data: bytes,
    *,
    sha256: str | None = None,
) -> dict[str, Any]:
    """Alias used when only in-memory bytes are available."""
    return store_pcap_upload(case_id, filename, data, sha256=sha256)

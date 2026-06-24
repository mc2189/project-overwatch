"""Local storage helpers for uploaded document/image metadata review files."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parent.parent

_SAFE_NAME_RE = re.compile(r"[^\w.\-]+")

SUPPORTED_METADATA_EXTENSIONS: frozenset[str] = frozenset(
    {
        "jpg",
        "jpeg",
        "png",
        "heic",
        "heif",
        "tif",
        "tiff",
        "pdf",
        "docx",
        "xlsx",
        "pptx",
        "txt",
        "csv",
    }
)


def sanitise_upload_filename(filename: str) -> str:
    base = Path(filename).name.strip() or "upload.bin"
    cleaned = _SAFE_NAME_RE.sub("_", base)
    return cleaned[:120]


def file_extension(filename: str) -> str:
    return Path(filename).suffix.lower().lstrip(".")


def is_supported_metadata_filename(filename: str) -> bool:
    return file_extension(filename) in SUPPORTED_METADATA_EXTENSIONS


def _case_upload_dir(case_id: int) -> Path:
    dest = PROJECT_ROOT / "database" / "evidence_files" / f"case_{case_id}" / "file_metadata_uploads"
    dest.mkdir(parents=True, exist_ok=True)
    return dest


def store_file_metadata_upload(
    case_id: int,
    filename: str,
    data: bytes,
    *,
    sha256: str | None = None,
) -> dict[str, Any]:
    """Persist uploaded file bytes under the case evidence area."""
    digest = sha256 or hashlib.sha256(data).hexdigest()
    safe_name = sanitise_upload_filename(filename)
    dest_dir = _case_upload_dir(case_id)
    dest = dest_dir / f"{digest[:16]}_{safe_name}"
    if not dest.is_file():
        dest.write_bytes(data)
    return {
        "filename": safe_name,
        "extension": file_extension(safe_name),
        "sha256": digest,
        "size_bytes": len(data),
        "storage_path": str(dest),
        "display_ref": f"{safe_name} ({digest[:12]}…)",
    }

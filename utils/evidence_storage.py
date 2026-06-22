"""File spill storage for large evidence locker artefacts."""

from __future__ import annotations

from pathlib import Path

from database.db_setup import PROJECT_ROOT

EVIDENCE_INLINE_MAX_BYTES = 32_768
EVIDENCE_FILES_DIR = PROJECT_ROOT / "database" / "evidence_files"
EVIDENCE_PREVIEW_CHARS = 2000


def evidence_file_suffix(content_type: str = "text/plain") -> str:
    lowered = (content_type or "text/plain").lower()
    if "json" in lowered:
        return ".json"
    if "xml" in lowered:
        return ".xml"
    if lowered.startswith("application/octet-stream") or "binary" in lowered:
        return ".bin"
    return ".txt"


def evidence_file_path(case_id: int, evidence_id: int, *, content_type: str = "text/plain") -> Path:
    suffix = evidence_file_suffix(content_type)
    return EVIDENCE_FILES_DIR / f"case_{case_id}" / f"evidence_{evidence_id}{suffix}"


def spill_evidence_content(case_id: int, evidence_id: int, content_text: str, *, content_type: str) -> str:
    """Write full text content to disk and return the relative storage path."""
    target = evidence_file_path(case_id, evidence_id, content_type=content_type)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content_text, encoding="utf-8")
    return str(target.relative_to(PROJECT_ROOT))


def spill_binary_content(
    case_id: int,
    evidence_id: int,
    content_bytes: bytes,
    *,
    content_type: str = "application/octet-stream",
) -> str:
    """Write binary content to disk and return the relative storage path."""
    target = evidence_file_path(case_id, evidence_id, content_type=content_type)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content_bytes)
    return str(target.relative_to(PROJECT_ROOT))


def inline_evidence_content(content_text: str, *, spilled: bool) -> str | None:
    """Return DB-stored content: full text, preview, or None when spilled-only."""
    if not content_text:
        return None
    if not spilled:
        return content_text
    preview = content_text[:EVIDENCE_PREVIEW_CHARS]
    if len(content_text) > EVIDENCE_PREVIEW_CHARS:
        preview += "\n... [truncated; full artefact stored on disk — see storage_path]"
    return preview


def inline_binary_preview(content_bytes: bytes, *, spilled: bool) -> str | None:
    """Return a short text preview for a binary artefact."""
    if not content_bytes:
        return None
    size = len(content_bytes)
    preview = f"[binary artefact: {size:,} bytes"
    if spilled:
        preview += "; full content stored on disk — see storage_path]"
    else:
        preview += "]"
    return preview


def should_spill_content(content_text: str | None) -> bool:
    if not content_text:
        return False
    return len(content_text.encode("utf-8")) > EVIDENCE_INLINE_MAX_BYTES


def should_spill_bytes(content_bytes: bytes | None) -> bool:
    if not content_bytes:
        return False
    return len(content_bytes) > EVIDENCE_INLINE_MAX_BYTES


def read_spilled_content(storage_path: str | None) -> str | None:
    if not storage_path:
        return None
    path = PROJECT_ROOT / storage_path
    if not path.exists():
        return None
    if path.suffix == ".bin":
        data = path.read_bytes()
        return f"[binary artefact: {len(data):,} bytes at {storage_path}]"
    return path.read_text(encoding="utf-8")


def read_spilled_bytes(storage_path: str | None) -> bytes | None:
    if not storage_path:
        return None
    path = PROJECT_ROOT / storage_path
    if not path.exists():
        return None
    return path.read_bytes()

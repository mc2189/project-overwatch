"""Extract metadata from local uploaded documents and images."""

from __future__ import annotations

import csv
import hashlib
import io
import zipfile
from pathlib import Path
from typing import Any
from xml.etree import ElementTree

from utils.file_metadata_storage import file_extension, is_supported_metadata_filename
from utils.security import redact_secrets_from_text
from utils.target_detection import file_target_type

MAX_TEXT_PREVIEW_LINES = 20
MAX_RAW_METADATA_ITEMS = 40

_OFFICE_NS = {
    "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
    "dc": "http://purl.org/dc/elements/1.1/",
    "dcterms": "http://purl.org/dc/terms/",
    "ep": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties",
}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _cap_dict(data: dict[str, Any], limit: int = MAX_RAW_METADATA_ITEMS) -> dict[str, Any]:
    items = list(data.items())[:limit]
    return {str(key): redact_secrets_from_text(str(value))[:500] for key, value in items if value not in (None, "")}


def _gps_from_exif(exif: Any) -> tuple[bool, dict[str, Any] | None]:
    if exif is None:
        return False, None
    try:
        gps_ifd = exif.get_ifd(0x8825)
    except Exception:
        return False, None
    if not gps_ifd:
        return False, None
    details: dict[str, Any] = {"gps_tags_present": True}
    try:
        from PIL.ExifTags import GPSTAGS

        for tag_id, value in gps_ifd.items():
            label = GPSTAGS.get(tag_id, str(tag_id))
            if label in {"GPSLatitude", "GPSLongitude", "GPSAltitude", "GPSLatitudeRef", "GPSLongitudeRef"}:
                details[label] = str(value)[:120]
    except Exception:
        details["note"] = "GPS metadata present but coordinates could not be decoded safely."
    return True, details


def _extract_image_metadata(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "extraction_status": "unavailable",
        "extraction_notes": [],
        "image": None,
        "privacy_flags": {"gps_present": False, "author_present": False, "company_present": False},
        "gps_details": None,
        "raw_metadata": {},
    }
    ext = path.suffix.lower().lstrip(".")
    if ext in {"heic", "heif"}:
        try:
            import pillow_heif  # type: ignore

            pillow_heif.register_heif_opener()
        except Exception:
            result["extraction_notes"].append("HEIC/HEIF support requires optional pillow-heif — metadata not extracted.")
            result["extraction_status"] = "partial"
            return result

    try:
        from PIL import Image
        from PIL.ExifTags import TAGS
    except Exception:
        result["extraction_notes"].append("Pillow is not installed — image metadata unavailable.")
        return result

    try:
        with Image.open(path) as img:
            width, height = img.size
            exif_data = img.getexif()
            exif_summary: dict[str, str] = {}
            camera_make = None
            camera_model = None
            software = None
            created = None
            modified = None
            orientation = None
            for tag_id, value in (exif_data or {}).items():
                label = TAGS.get(tag_id, str(tag_id))
                text = redact_secrets_from_text(str(value))
                if label in {"Make", "Model", "Software", "DateTime", "DateTimeOriginal", "DateTimeDigitized", "Orientation"}:
                    exif_summary[label] = text[:200]
                if label == "Make":
                    camera_make = text
                elif label == "Model":
                    camera_model = text
                elif label == "Software":
                    software = text
                elif label in {"DateTimeOriginal", "DateTime"}:
                    created = created or text
                elif label == "DateTimeDigitized":
                    modified = text
                elif label == "Orientation":
                    orientation = text

            gps_present, gps_details = _gps_from_exif(exif_data)
            result["privacy_flags"]["gps_present"] = gps_present
            if gps_present:
                result["gps_details"] = gps_details

            result["image"] = {
                "width": width,
                "height": height,
                "mode": img.mode,
                "format": img.format,
                "camera_make": camera_make,
                "camera_model": camera_model,
                "software": software,
                "created_date": created,
                "modified_date": modified,
                "orientation": orientation,
                "exif_summary": exif_summary,
                "xmp_iptc_summary": None,
            }
            result["raw_metadata"] = _cap_dict(exif_summary)
            result["extraction_status"] = "complete"
    except Exception as exc:
        result["extraction_notes"].append(f"Image metadata extraction failed: {exc}")
        result["extraction_status"] = "partial"
    return result


def _extract_pdf_metadata(path: Path) -> dict[str, Any]:
    result: dict[str, Any] = {
        "extraction_status": "unavailable",
        "extraction_notes": [],
        "document": None,
        "privacy_flags": {"gps_present": False, "author_present": False, "company_present": False},
        "raw_metadata": {},
    }
    try:
        from pypdf import PdfReader
    except Exception:
        result["extraction_notes"].append("pypdf is not installed — PDF metadata unavailable.")
        return result
    try:
        reader = PdfReader(str(path))
        meta = reader.metadata or {}
        fields = {
            "title": meta.get("/Title"),
            "author": meta.get("/Author"),
            "creator": meta.get("/Creator"),
            "producer": meta.get("/Producer"),
            "created_date": meta.get("/CreationDate"),
            "modified_date": meta.get("/ModDate"),
        }
        clean = {key: redact_secrets_from_text(str(value))[:300] for key, value in fields.items() if value}
        result["document"] = {
            **clean,
            "page_count": len(reader.pages),
            "application": clean.get("producer") or clean.get("creator"),
        }
        result["privacy_flags"]["author_present"] = bool(clean.get("author") or clean.get("creator"))
        result["raw_metadata"] = _cap_dict(clean)
        result["extraction_status"] = "complete"
    except Exception as exc:
        result["extraction_notes"].append(f"PDF metadata extraction failed: {exc}")
        result["extraction_status"] = "partial"
    return result


def _office_core_properties(path: Path) -> dict[str, str]:
    props: dict[str, str] = {}
    with zipfile.ZipFile(path) as archive:
        if "docProps/core.xml" not in archive.namelist():
            return props
        root = ElementTree.fromstring(archive.read("docProps/core.xml"))
        mapping = {
            "title": ".//dc:title",
            "author": ".//dc:creator",
            "last_modified_by": ".//cp:lastModifiedBy",
            "created_date": ".//dcterms:created",
            "modified_date": ".//dcterms:modified",
            "revision": ".//cp:revision",
            "category": ".//cp:category",
        }
        for key, xpath in mapping.items():
            node = root.find(xpath, _OFFICE_NS)
            if node is not None and (node.text or "").strip():
                props[key] = redact_secrets_from_text(node.text.strip())[:300]
        app_path = "docProps/app.xml"
        if app_path in archive.namelist():
            app_root = ElementTree.fromstring(archive.read(app_path))
            for key, xpath in (
                ("application", ".//ep:Application"),
                ("company", ".//ep:Company"),
                ("template", ".//ep:Template"),
            ):
                node = app_root.find(xpath, _OFFICE_NS)
                if node is not None and (node.text or "").strip():
                    props[key] = redact_secrets_from_text(node.text.strip())[:300]
    return props


def _count_office_parts(path: Path, *, kind: str) -> int | None:
    try:
        with zipfile.ZipFile(path) as archive:
            if kind == "xlsx":
                return len([name for name in archive.namelist() if name.startswith("xl/worksheets/")])
            if kind == "pptx":
                return len([name for name in archive.namelist() if name.startswith("ppt/slides/slide")])
    except Exception:
        return None
    return None


def _extract_office_metadata(path: Path, *, kind: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "extraction_status": "unavailable",
        "extraction_notes": [],
        "document": None,
        "privacy_flags": {"gps_present": False, "author_present": False, "company_present": False},
        "raw_metadata": {},
    }
    try:
        props = _office_core_properties(path)
        count = _count_office_parts(path, kind=kind)
        document: dict[str, Any] = dict(props)
        if kind == "xlsx" and count is not None:
            document["sheet_count"] = count
        if kind == "pptx" and count is not None:
            document["slide_count"] = count
        if kind == "docx":
            document["word_document"] = True
        result["document"] = document
        result["privacy_flags"]["author_present"] = bool(props.get("author") or props.get("last_modified_by"))
        result["privacy_flags"]["company_present"] = bool(props.get("company") or props.get("template"))
        result["raw_metadata"] = _cap_dict(props)
        result["extraction_status"] = "complete" if props else "partial"
        if not props:
            result["extraction_notes"].append("No core document properties were found.")
    except Exception as exc:
        result["extraction_notes"].append(f"Office metadata extraction failed: {exc}")
        result["extraction_status"] = "partial"
    return result


def _extract_text_metadata(path: Path, *, kind: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "extraction_status": "complete",
        "extraction_notes": [],
        "document": None,
        "privacy_flags": {"gps_present": False, "author_present": False, "company_present": False},
        "raw_metadata": {},
    }
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        lines = text.splitlines()
        preview_lines = lines[:MAX_TEXT_PREVIEW_LINES]
        document: dict[str, Any] = {
            "line_count": len(lines),
            "character_count": len(text),
            "preview_line_count": len(preview_lines),
        }
        if kind == "csv":
            reader = csv.reader(io.StringIO(text))
            rows = list(reader)
            document["row_count"] = len(rows)
            document["column_count"] = len(rows[0]) if rows else 0
        result["document"] = document
        result["raw_metadata"] = _cap_dict(document)
    except Exception as exc:
        result["extraction_notes"].append(f"Text metadata extraction failed: {exc}")
        result["extraction_status"] = "partial"
    return result


def extract_file_metadata(path: Path, *, filename: str | None = None) -> dict[str, Any]:
    """Extract metadata from a local file path."""
    name = filename or path.name
    ext = file_extension(name)
    target_type = file_target_type(name)
    size_bytes = path.stat().st_size if path.is_file() else 0
    base: dict[str, Any] = {
        "filename": name,
        "extension": ext,
        "target_type": target_type,
        "size_bytes": size_bytes,
        "sha256": sha256_file(path) if path.is_file() else None,
        "supported": is_supported_metadata_filename(name),
        "extraction_status": "unsupported",
        "extraction_notes": [],
        "image": None,
        "document": None,
        "privacy_flags": {"gps_present": False, "author_present": False, "company_present": False},
        "gps_details": None,
        "raw_metadata": {},
        "notable": False,
    }
    if not base["supported"]:
        base["extraction_notes"].append("Unsupported file type for metadata review.")
        return base

    if ext in {"jpg", "jpeg", "png", "heic", "heif", "tif", "tiff"}:
        extracted = _extract_image_metadata(path)
    elif ext == "pdf":
        extracted = _extract_pdf_metadata(path)
    elif ext == "docx":
        extracted = _extract_office_metadata(path, kind="docx")
    elif ext == "xlsx":
        extracted = _extract_office_metadata(path, kind="xlsx")
    elif ext == "pptx":
        extracted = _extract_office_metadata(path, kind="pptx")
    elif ext in {"txt", "csv"}:
        extracted = _extract_text_metadata(path, kind=ext)
    else:
        extracted = base
        return base

    base.update(
        {
            "extraction_status": extracted.get("extraction_status", "partial"),
            "extraction_notes": list(extracted.get("extraction_notes") or []),
            "image": extracted.get("image"),
            "document": extracted.get("document"),
            "privacy_flags": extracted.get("privacy_flags") or base["privacy_flags"],
            "gps_details": extracted.get("gps_details"),
            "raw_metadata": extracted.get("raw_metadata") or {},
        }
    )
    flags = base["privacy_flags"]
    base["notable"] = bool(
        flags.get("gps_present")
        or flags.get("author_present")
        or flags.get("company_present")
        or base.get("image")
        or base.get("document")
    )
    return base

"""Advisory interpretation of local file metadata review results."""

from __future__ import annotations

from typing import Any

from utils.finding_interpreter import FINDING_KIND_SOURCE_NOTICE, make_finding


def _files(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    return list(parsed_data.get("files") or [])


def interpret_file_metadata_results(parsed_data: dict[str, Any]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    files = _files(parsed_data)
    file_count = int(parsed_data.get("file_count") or len(files))

    if not files:
        findings.append(
            make_finding(
                "Metadata extraction partially unavailable",
                "info",
                88,
                "No files were available for metadata review.",
                ["Upload one or more supported files before running this module."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    partial = [row for row in files if row.get("extraction_status") in {"partial", "unavailable"}]
    unsupported = [row for row in files if row.get("extraction_status") == "unsupported"]
    notable = [row for row in files if row.get("notable")]
    gps_files = [row for row in files if (row.get("privacy_flags") or {}).get("gps_present")]
    author_files = [row for row in files if (row.get("privacy_flags") or {}).get("author_present")]
    company_files = [row for row in files if (row.get("privacy_flags") or {}).get("company_present")]
    image_files = [row for row in files if row.get("image")]
    doc_producer_files = [
        row
        for row in files
        if (row.get("document") or {}).get("producer") or (row.get("document") or {}).get("application")
    ]
    revision_files = [
        row for row in files if (row.get("document") or {}).get("revision") or (row.get("document") or {}).get("last_modified_by")
    ]

    findings.append(
        make_finding(
            "File metadata reviewed",
            "info",
            85,
            f"Metadata review completed for {file_count} local file(s). "
            f"{len(notable)} file(s) contain metadata that may warrant review before external sharing.",
            [
                "Metadata is extracted locally — files are not uploaded externally.",
                "Review whether present metadata is expected for the intended audience.",
            ],
            finding_kind=FINDING_KIND_SOURCE_NOTICE,
        )
    )

    if unsupported:
        names = ", ".join(row.get("filename", "file") for row in unsupported[:4])
        findings.append(
            make_finding(
                "Unsupported file type",
                "info",
                80,
                f"Unsupported file type(s) skipped: {names}.",
                ["Use supported image, PDF, Office, or basic text/CSV formats."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    if partial:
        findings.append(
            make_finding(
                "Metadata extraction partially unavailable",
                "info",
                78,
                "Some files could not be fully parsed — review extraction notes per file.",
                ["Install optional libraries where noted, or review files manually."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    if not notable and not partial and not unsupported:
        findings.append(
            make_finding(
                "No notable metadata observed",
                "info",
                75,
                "Files were reviewed, but no notable metadata fields were extracted.",
                ["This does not prove metadata is absent — extraction may be limited for the format."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )
        return findings

    if image_files:
        findings.append(
            make_finding(
                "Image EXIF metadata present",
                "info",
                80,
                f"Image EXIF metadata observed in {len(image_files)} file(s). Review before sharing externally.",
                ["Remove or strip EXIF metadata if publishing images outside trusted channels."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    if gps_files:
        findings.append(
            make_finding(
                "GPS/location metadata present",
                "medium",
                88,
                f"GPS/location metadata appears present in {len(gps_files)} image file(s). "
                "Review before sharing externally.",
                [
                    "Expand file details to review coordinates if needed.",
                    "Consider removing location metadata before external publication.",
                ],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    if author_files:
        findings.append(
            make_finding(
                "Author/creator metadata present",
                "info",
                82,
                f"Author or creator metadata observed in {len(author_files)} file(s). "
                "Personal names may be privacy-sensitive — review before sharing externally.",
                ["Treat author/creator fields as privacy advisory metadata, not confirmed identity proof."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    if doc_producer_files:
        findings.append(
            make_finding(
                "Document producer/application metadata present",
                "info",
                78,
                f"Producer or application metadata observed in {len(doc_producer_files)} document file(s).",
                ["Review whether application details should be removed before external sharing."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    if company_files:
        findings.append(
            make_finding(
                "Document producer/application metadata present",
                "low",
                76,
                f"Company or template metadata observed in {len(company_files)} file(s) — review internal exposure risk.",
                ["Review whether internal template or company fields should be removed before sharing."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    if revision_files:
        findings.append(
            make_finding(
                "Revision or editing metadata present",
                "info",
                74,
                f"Revision or last-modified metadata observed in {len(revision_files)} file(s).",
                ["Editing metadata can reveal workflow history — review before external sharing."],
                finding_kind=FINDING_KIND_SOURCE_NOTICE,
            )
        )

    return findings

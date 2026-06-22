"""HTML, JSON, batch export, and graph snapshot helpers for case reports."""

from __future__ import annotations

import base64
import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from database.db_setup import PROJECT_ROOT, get_case, get_db_conn
from utils.report_builder import ReportOptions, _load_case_data, _safe_filename_part, build_case_report
from utils.report_encryption import save_encrypted_export
from utils.report_settings import ReportBranding

ExportFormat = Literal["markdown", "html", "json", "pdf"]


def build_case_report_json(case_id: int, options: ReportOptions | None = None) -> str:
    """Build a structured JSON export for a case."""
    options = options or ReportOptions()
    conn = get_db_conn()
    try:
        data = _load_case_data(case_id, conn)
    finally:
        conn.close()

    findings = data["findings"]
    if options.include_closed_findings:
        export_findings = findings
    else:
        export_findings = [item for item in findings if item.get("status") == "open"]

    payload: dict[str, Any] = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "template": options.template,
        "case": data["case"],
        "entities": data["entities"],
        "relationships": data["relationships"],
        "observations": data["observations"],
        "operations": data["operations"],
        "findings": [
            {
                **finding,
                "suggested_actions": json.loads(finding.get("suggested_actions_json") or "[]")
                if finding.get("suggested_actions_json")
                else [],
            }
            for finding in export_findings
        ],
    }
    return json.dumps(payload, indent=2, default=str)


def markdown_to_html(
    markdown_text: str,
    title: str = "Project Overwatch Case Report",
    branding: ReportBranding | None = None,
) -> str:
    """Convert a subset of Markdown to simple HTML for browser viewing or printing."""
    lines = markdown_text.splitlines()
    body_parts: list[str] = []
    in_code = False
    in_list = False
    code_lines: list[str] = []

    def close_list() -> None:
        nonlocal in_list
        if in_list:
            body_parts.append("</ul>")
            in_list = False

    for line in lines:
        if line.strip().startswith("```"):
            if in_code:
                body_parts.append(
                    "<pre><code>"
                    + html.escape("\n".join(code_lines))
                    + "</code></pre>"
                )
                code_lines = []
                in_code = False
            else:
                close_list()
                in_code = True
            continue

        if in_code:
            code_lines.append(line)
            continue

        if line.startswith("# "):
            close_list()
            body_parts.append(f"<h1>{html.escape(line[2:].strip())}</h1>")
        elif line.startswith("## "):
            close_list()
            body_parts.append(f"<h2>{html.escape(line[3:].strip())}</h2>")
        elif line.startswith("### "):
            close_list()
            body_parts.append(f"<h3>{html.escape(line[4:].strip())}</h3>")
        elif line.startswith("#### "):
            close_list()
            body_parts.append(f"<h4>{html.escape(line[5:].strip())}</h4>")
        elif line.startswith("- "):
            if not in_list:
                body_parts.append("<ul>")
                in_list = True
            content = html.escape(line[2:].strip())
            content = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", content)
            content = re.sub(r"`(.+?)`", r"<code>\1</code>", content)
            body_parts.append(f"<li>{content}</li>")
        elif line.strip() == "":
            close_list()
            body_parts.append("<br>")
        else:
            close_list()
            content = html.escape(line.strip())
            content = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", content)
            content = re.sub(r"`(.+?)`", r"<code>\1</code>", content)
            content = re.sub(r"!\[(.+?)\]\((.+?)\)", r'<img alt="\1" src="\2" style="max-width:100%;">', content)
            if content.startswith("_") and content.endswith("_"):
                body_parts.append(f"<p><em>{html.escape(content.strip('_'))}</em></p>")
            else:
                body_parts.append(f"<p>{content}</p>")

    close_list()
    if in_code and code_lines:
        body_parts.append("<pre><code>" + html.escape("\n".join(code_lines)) + "</code></pre>")

    body = "\n".join(body_parts)
    header_html = ""
    footer_html = ""
    if branding:
        if branding.organisation_name:
            header_html += f'<p class="brand-org">{html.escape(branding.organisation_name)}</p>'
        meta_parts = []
        if branding.analyst_name:
            meta_parts.append(f"Analyst: {html.escape(branding.analyst_name)}")
        if branding.classification_label:
            meta_parts.append(f"Classification: {html.escape(branding.classification_label)}")
        if meta_parts:
            header_html += f'<p class="brand-meta">{" · ".join(meta_parts)}</p>'
        if branding.footer_text:
            footer_html = f'<footer><p>{html.escape(branding.footer_text)}</p></footer>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>{html.escape(title)}</title>
  <style>
    body {{ font-family: Georgia, serif; margin: 2rem auto; max-width: 900px; line-height: 1.5; color: #222; }}
    h1, h2, h3, h4 {{ font-family: Arial, sans-serif; }}
    pre {{ background: #f5f5f5; padding: 1rem; overflow-x: auto; }}
    code {{ background: #f0f0f0; padding: 0.1rem 0.25rem; }}
    img {{ border: 1px solid #ddd; margin: 1rem 0; }}
    .brand-org {{ font-size: 1.1rem; font-weight: bold; margin-bottom: 0.25rem; }}
    .brand-meta {{ color: #555; margin-top: 0; }}
    footer {{ margin-top: 2rem; padding-top: 1rem; border-top: 1px solid #ddd; color: #666; font-size: 0.9rem; }}
    @media print {{ body {{ margin: 1rem; }} }}
  </style>
</head>
<body>
{header_html}
{body}
{footer_html}
</body>
</html>"""


def export_graph_snapshot(
    entities: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    findings: list[dict[str, Any]],
    output_path: Path,
) -> Path | None:
    """Save the entity graph as a PNG if Plotly/kaleido is available."""
    from utils.graph_view import entity_graph_figure

    figure = entity_graph_figure(entities, relationships, findings)
    if figure is None:
        return None
    try:
        figure.write_image(str(output_path), width=1200, height=800, scale=2)
        return output_path
    except Exception:
        return None


def graph_snapshot_base64(
    entities: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    findings: list[dict[str, Any]],
) -> str | None:
    """Return a base64 PNG data URI for inline graph embedding, if available."""
    temp_path = PROJECT_ROOT / "reports" / ".graph_snapshot_temp.png"
    temp_path.parent.mkdir(parents=True, exist_ok=True)
    saved = export_graph_snapshot(entities, relationships, findings, temp_path)
    if saved is None or not saved.exists():
        return None
    try:
        encoded = base64.b64encode(saved.read_bytes()).decode("ascii")
        return f"data:image/png;base64,{encoded}"
    finally:
        try:
            saved.unlink(missing_ok=True)
        except OSError:
            pass


def _report_basename(case_id: int, case_name: str | None = None) -> str:
    conn = get_db_conn()
    try:
        case = get_case(case_id, conn=conn)
    finally:
        conn.close()
    name = case_name or (case.get("name") if case else None) or f"case_{case_id}"
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    return f"{_safe_filename_part(name)}_{case_id}_{timestamp}"


def is_pdf_export_available() -> bool:
    try:
        import weasyprint  # noqa: F401

        return True
    except ImportError:
        return False


def html_to_pdf_bytes(html_text: str) -> bytes:
    """Convert HTML to PDF bytes using WeasyPrint when available."""
    try:
        from weasyprint import HTML
    except ImportError as exc:
        raise RuntimeError(
            "PDF export requires WeasyPrint. Install with: pip install weasyprint"
        ) from exc
    return HTML(string=html_text).write_pdf()


def save_report_pdf(
    case_id: int,
    html_text: str | None = None,
    markdown_text: str | None = None,
    output_dir: str = "reports",
    branding: ReportBranding | None = None,
) -> Path:
    """Save a PDF report to disk."""
    if html_text is None:
        if markdown_text is None:
            markdown_text = build_case_report(case_id)
        conn = get_db_conn()
        try:
            case = get_case(case_id, conn=conn)
        finally:
            conn.close()
        title = f"Case Report — {case.get('name')}" if case else "Project Overwatch Case Report"
        html_text = markdown_to_html(markdown_text, title=title, branding=branding)

    reports_dir = Path(output_dir)
    if not reports_dir.is_absolute():
        reports_dir = PROJECT_ROOT / reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)

    output_path = reports_dir / f"{_report_basename(case_id)}.pdf"
    output_path.write_bytes(html_to_pdf_bytes(html_text))
    return output_path


def save_report_html(
    case_id: int,
    html_text: str | None = None,
    markdown_text: str | None = None,
    output_dir: str = "reports",
    branding: ReportBranding | None = None,
) -> Path:
    """Save an HTML report to disk."""
    if html_text is None:
        if markdown_text is None:
            markdown_text = build_case_report(case_id)
        conn = get_db_conn()
        try:
            case = get_case(case_id, conn=conn)
        finally:
            conn.close()
        title = f"Case Report — {case.get('name')}" if case else "Project Overwatch Case Report"
        html_text = markdown_to_html(markdown_text, title=title, branding=branding)

    reports_dir = Path(output_dir)
    if not reports_dir.is_absolute():
        reports_dir = PROJECT_ROOT / reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)

    output_path = reports_dir / f"{_report_basename(case_id)}.html"
    output_path.write_text(html_text, encoding="utf-8")
    return output_path


def save_encrypted_report(
    case_id: int,
    content: bytes,
    password: str,
    *,
    suffix: str = "enc",
    output_dir: str = "exports",
) -> Path:
    """Save password-encrypted report bytes."""
    exports_dir = Path(output_dir)
    if not exports_dir.is_absolute():
        exports_dir = PROJECT_ROOT / exports_dir
    output_path = exports_dir / f"{_report_basename(case_id)}.{suffix}"
    return save_encrypted_export(content, output_path, password)


def batch_export_reports(
    case_ids: list[int],
    *,
    output_dir: str = "reports",
    export_format: ExportFormat = "markdown",
    options: ReportOptions | None = None,
) -> list[Path]:
    """Export reports for multiple cases. Returns saved file paths."""
    options = options or ReportOptions()
    saved_paths: list[Path] = []

    reports_dir = Path(output_dir)
    if not reports_dir.is_absolute():
        reports_dir = PROJECT_ROOT / reports_dir
    reports_dir.mkdir(parents=True, exist_ok=True)

    for case_id in case_ids:
        try:
            if export_format == "json":
                content = build_case_report_json(case_id, options=options)
                path = reports_dir / f"{_report_basename(case_id)}.json"
                path.write_text(content, encoding="utf-8")
                saved_paths.append(path)
            elif export_format == "pdf":
                markdown = build_case_report(case_id, options=options)
                path = save_report_pdf(
                    case_id,
                    markdown_text=markdown,
                    output_dir=str(reports_dir),
                    branding=options.branding if options else None,
                )
                saved_paths.append(path)
            elif export_format == "html":
                markdown = build_case_report(case_id, options=options)
                path = save_report_html(
                    case_id,
                    markdown_text=markdown,
                    output_dir=str(reports_dir),
                    branding=options.branding if options else None,
                )
                saved_paths.append(path)
            else:
                from utils.report_builder import save_report_markdown

                markdown = build_case_report(case_id, options=options)
                path = save_report_markdown(case_id, markdown_text=markdown, output_dir=str(reports_dir))
                saved_paths.append(path)
        except OSError:
            continue

    return saved_paths

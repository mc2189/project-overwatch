"""Archive page renderers for Project Overwatch."""

from __future__ import annotations

import re

import pandas as pd
import streamlit as st

from database.db_setup import (
    FINDING_STATUSES,
    get_case,
    get_db_conn,
    entity_ids_with_evidence,
    list_cases,
    list_entities,
    list_evidence_items,
    list_findings,
    list_observations,
    list_operations,
    list_relationships,
    operation_run_mode_counts,
)
from ui.metrics import render_compact_metrics
from utils.evidence_model import evidence_type_label, reliability_label
from utils.case_backup import export_case_bundle_json, import_case_bundle, parse_case_bundle_json
from utils.graph_view import entity_graph_figure
from utils.report_builder import build_case_report, save_report_markdown
from utils.report_encryption import is_encryption_available
from utils.report_export import (
    batch_export_reports,
    build_case_report_json,
    html_to_pdf_bytes,
    is_pdf_export_available,
    markdown_to_html,
    save_encrypted_report,
    save_report_html,
    save_report_pdf,
)
from utils.report_presets import (
    REPORT_PRESETS,
    apply_preset_to_session,
    build_report_options_from_state,
    preset_select_options,
    suggest_preset_for_run_mode,
)
from utils.run_modes import get_run_mode_label
from utils.report_redaction import parse_custom_terms
from utils.report_scheduler import maybe_run_scheduled_exports
from utils.report_settings import (
    ReportBranding,
    ReportSchedule,
    load_report_branding,
    load_report_schedule,
    save_report_branding,
    save_report_schedule,
)


def enrich_relationships_for_display(
    relationships: list[dict],
    entities: list[dict],
) -> list[dict]:
    entity_map = {entity["id"]: entity for entity in entities}
    display_rows = []

    for relationship in relationships:
        source = entity_map.get(relationship["source_entity_id"], {})
        target = entity_map.get(relationship["target_entity_id"], {})
        display_rows.append(
            {
                **relationship,
                "source_entity": source.get("label") or source.get("value", relationship["source_entity_id"]),
                "target_entity": target.get("label") or target.get("value", relationship["target_entity_id"]),
                "evidence_type": evidence_type_label(relationship.get("evidence_type")),
                "reliability": reliability_label(relationship.get("reliability")),
            }
        )

    return display_rows


def render_entities_page(case_id: int, metrics: dict[str, int]) -> None:
    """Legacy alias — Entity Workspace replaced the basic entities list."""
    from ui.entity_workspace import render_entity_workspace_page

    render_entity_workspace_page(case_id, metrics)


def render_relationships_page(case_id: int, metrics: dict[str, int]) -> None:
    st.title("Relationships")
    render_compact_metrics(metrics)
    st.divider()

    conn = get_db_conn()
    entities = list_entities(case_id=case_id, conn=conn)
    relationships = list_relationships(case_id=case_id, conn=conn)
    conn.close()
    st.caption(f"Showing relationships for case #{case_id}.")
    if relationships:
        display_rows = enrich_relationships_for_display(relationships, entities)
        st.dataframe(pd.DataFrame(display_rows), width="stretch")
    else:
        st.info(
            "No relationships recorded for this case yet. "
            "Run Domain Intelligence or Nmap to populate relationships."
        )


def render_observations_page(case_id: int, metrics: dict[str, int]) -> None:
    st.title("Observations")
    render_compact_metrics(metrics)
    st.divider()

    conn = get_db_conn()
    observations = list_observations(case_id=case_id, conn=conn)
    evidence_items = list_evidence_items(case_id=case_id, conn=conn)
    conn.close()
    evidence_by_observation: dict[int, list[dict]] = {}
    for item in evidence_items:
        obs_id = item.get("observation_id")
        if obs_id is not None:
            evidence_by_observation.setdefault(int(obs_id), []).append(item)

    st.caption(f"Showing observations for case #{case_id}.")
    if observations:
        display_rows = []
        evidence_columns = (
            "evidence_type",
            "source_name",
            "reliability",
            "collection_method",
            "collected_at",
        )
        for observation in observations:
            row = observation.copy()
            if row.get("raw_output") and len(row["raw_output"]) > 200:
                row["raw_output"] = row["raw_output"][:200] + "..."
            if row.get("evidence_type"):
                row["evidence_type"] = evidence_type_label(row["evidence_type"])
            if row.get("reliability"):
                row["reliability"] = reliability_label(row["reliability"])
            linked = evidence_by_observation.get(int(observation["id"]), [])
            row["evidence_items"] = len(linked)
            display_rows.append(row)
        column_order = [
            "id",
            "module_id",
            "observation_type",
            "title",
            "evidence_items",
            *evidence_columns,
            "summary",
            "created_at",
        ]
        frame = pd.DataFrame(display_rows)
        visible = [column for column in column_order if column in frame.columns]
        remaining = [column for column in frame.columns if column not in visible]
        st.dataframe(frame[visible + remaining], width="stretch")

        st.subheader("Linked evidence")
        for observation in observations:
            linked = evidence_by_observation.get(int(observation["id"]), [])
            if not linked:
                continue
            label = observation.get("title") or f"Observation #{observation['id']}"
            with st.expander(f"{label} · {len(linked)} evidence item(s)", expanded=False):
                for item in linked:
                    st.markdown(
                        f"- **{item.get('title', 'Evidence')}** · "
                        f"`{item.get('source_name') or '-'}` · "
                        f"{evidence_type_label(item.get('evidence_type'))} · "
                        f"{reliability_label(item.get('reliability'))}"
                    )
                    if item.get("content_hash"):
                        st.caption(f"Hash: `{item['content_hash']}`")
                    preview = (item.get("content_text") or "")[:400]
                    if preview:
                        st.code(preview + ("..." if len(item.get("content_text") or "") > 400 else ""))
    else:
        st.info("No observations recorded for this case yet.")


def render_operations_page(case_id: int, metrics: dict[str, int]) -> None:
    st.title("Operations")
    render_compact_metrics(metrics)
    st.divider()

    conn = get_db_conn()
    operations = list_operations(case_id=case_id, conn=conn)
    mode_counts = operation_run_mode_counts(case_id, conn=conn)
    conn.close()
    st.caption(f"Showing operations for case #{case_id}.")
    if mode_counts:
        summary = ", ".join(f"{label}: {count}" for label, count in mode_counts.items())
        st.markdown(f"**Operations by run mode:** {summary}")

    run_mode_labels = sorted(
        {operation.get("run_mode_label") or "Unknown" for operation in operations}
    )
    if run_mode_labels:
        selected_modes = st.multiselect(
            "Filter by run mode",
            options=run_mode_labels,
            default=run_mode_labels,
            key="operations_run_mode_filter",
        )
        if selected_modes:
            operations = [
                operation
                for operation in operations
                if (operation.get("run_mode_label") or "Unknown") in selected_modes
            ]

    if operations:
        st.dataframe(pd.DataFrame(operations), width="stretch")
    else:
        st.info("No operations recorded for this case yet.")


def render_graph_page(case_id: int, metrics: dict[str, int]) -> None:
    from ui.entity_workspace import open_entity_in_workspace
    from utils.entity_pivot import get_entity_neighbour_ids

    st.title("Graph")
    render_compact_metrics(metrics)
    st.divider()

    conn = get_db_conn()
    entities = list_entities(case_id=case_id, conn=conn)
    relationships = list_relationships(case_id=case_id, conn=conn)
    findings = list_findings(case_id=case_id, conn=conn)
    evidence_items = list_evidence_items(case_id=case_id, conn=conn)
    conn.close()

    evidence_type_options = sorted({item.get("evidence_type") for item in evidence_items if item.get("evidence_type")})

    filter_col1, filter_col2, filter_col3 = st.columns(3)
    with filter_col1:
        status_filter = st.multiselect(
            "Finding statuses for node colour",
            options=list(FINDING_STATUSES),
            default=["open", "in_review", "action_required"],
            key="graph_finding_statuses",
        )
    with filter_col2:
        min_severity = st.selectbox(
            "Minimum severity",
            options=["All", "info", "low", "medium", "high", "critical"],
            key="graph_min_severity",
        )
    with filter_col3:
        hide_without_findings = st.checkbox(
            "Hide entities without matching findings",
            value=False,
            key="graph_hide_without_findings",
        )

    filter_col4, filter_col5, filter_col6 = st.columns(3)
    if evidence_type_options:
        with filter_col4:
            evidence_type_filter = st.multiselect(
                "Evidence types (entity highlight)",
                options=evidence_type_options,
                default=evidence_type_options,
                format_func=evidence_type_label,
                key="graph_evidence_types",
            )
        filtered_evidence_entity_ids = entity_ids_with_evidence(
            case_id,
            evidence_types=tuple(evidence_type_filter) if evidence_type_filter else None,
        )
    else:
        evidence_type_filter = []
        filtered_evidence_entity_ids = set()
        with filter_col4:
            st.caption("No evidence locker items yet.")
    with filter_col5:
        hide_without_evidence = st.checkbox(
            "Hide entities without evidence locker items",
            value=False,
            key="graph_hide_without_evidence",
        )
    with filter_col6:
        highlight_evidence = st.checkbox(
            "Highlight entities with evidence (green border)",
            value=True,
            key="graph_highlight_evidence",
        )

    statuses = tuple(status_filter) if status_filter else ("open", "in_review", "action_required")
    min_sev = None if min_severity == "All" else min_severity

    figure = entity_graph_figure(
        entities,
        relationships,
        findings,
        finding_statuses=statuses,
        min_severity=min_sev,
        hide_entities_without_findings=hide_without_findings,
        entities_with_evidence=filtered_evidence_entity_ids if highlight_evidence else None,
        hide_entities_without_evidence=hide_without_evidence,
    )

    st.caption(
        "Graph built from stored entities and relationships. "
        "Node colour reflects the highest finding severity matching the filters above. "
        "Green borders indicate entities with Evidence Locker artefacts."
    )
    if figure is None:
        st.info(
            "No graph data yet. Run Domain Intelligence or Nmap against a target to populate "
            "entities and relationships."
        )
    else:
        graph_event = st.plotly_chart(
            figure,
            width="stretch",
            on_select="rerun",
            selection_mode="points",
            key="entity_graph_chart",
        )
        if graph_event and graph_event.selection and graph_event.selection.points:
            point = graph_event.selection.points[0]
            custom = point.get("customdata")
            if custom is not None:
                st.session_state.graph_focus_entity = int(custom)

    st.divider()
    st.subheader("Entity neighbours")
    st.caption(
        "Select or click a graph node to list immediate neighbours, queue them, or open Entity Workspace."
    )
    if entities:
        entity_options = {entity["id"]: entity for entity in entities}
        focus_options = list(entity_options.keys())
        default_focus = st.session_state.get("graph_focus_entity")
        focus_index = focus_options.index(default_focus) if default_focus in focus_options else 0
        graph_entity_id = st.selectbox(
            "Focus entity",
            options=focus_options,
            index=focus_index,
            format_func=lambda eid: entity_options[eid].get("label")
            or entity_options[eid].get("value")
            or str(eid),
            key="graph_focus_entity_select",
        )
        st.session_state.graph_focus_entity = graph_entity_id
        neighbour_ids = get_entity_neighbour_ids(graph_entity_id, relationships)
        if neighbour_ids:
            st.markdown("**Immediate neighbours**")
            for neighbour_id in sorted(neighbour_ids):
                if neighbour_id not in entity_options:
                    continue
                neighbour = entity_options[neighbour_id]
                neighbour_label = neighbour.get("label") or neighbour.get("value") or str(neighbour_id)
                ncol1, ncol2, ncol3 = st.columns([3, 1, 1])
                with ncol1:
                    st.markdown(f"#{neighbour_id} · {neighbour_label}")
                with ncol2:
                    if st.button("Open", key=f"graph_neighbour_open_{neighbour_id}", width="stretch"):
                        open_entity_in_workspace(neighbour_id)
                        st.rerun()
                with ncol3:
                    if st.button("Queue", key=f"graph_neighbour_queue_{neighbour_id}", width="stretch"):
                        from ui.entity_workspace import queue_entity_for_case

                        if queue_entity_for_case(case_id, neighbour_id):
                            st.success(f"Queued {neighbour_label}.")
                        st.rerun()
        else:
            st.caption("No direct relationships for this entity.")
        focus_col1, focus_col2 = st.columns(2)
        with focus_col1:
            if st.button("Open in Entity Workspace", key="graph_open_entity_workspace", width="stretch"):
                open_entity_in_workspace(graph_entity_id)
                st.rerun()
        with focus_col2:
            if st.button("Add focus to pivot queue", key="graph_queue_focus_entity", width="stretch"):
                from ui.entity_workspace import queue_entity_for_case

                if queue_entity_for_case(case_id, graph_entity_id):
                    st.success("Added to pivot queue.")
                st.rerun()


def render_report_page(case_id: int, metrics: dict[str, int]) -> None:
    st.title("Report")
    render_compact_metrics(metrics)
    st.divider()

    st.caption(
        f"Generate a Markdown report for case #{case_id}. "
        "Review all content before sharing externally."
    )

    scheduled_paths, scheduled_message = maybe_run_scheduled_exports()
    if scheduled_message:
        if scheduled_paths:
            st.success(scheduled_message)
        else:
            st.info(scheduled_message)

    branding = load_report_branding()
    with st.expander("Organisation branding", expanded=False):
        brand_org = st.text_input("Organisation name", value=branding.organisation_name)
        brand_analyst = st.text_input("Analyst name", value=branding.analyst_name)
        brand_class = st.text_input("Classification label", value=branding.classification_label)
        brand_footer = st.text_area("Footer text", value=branding.footer_text, height=80)
        if st.button("Save branding settings", key="save_branding"):
            branding = ReportBranding(
                organisation_name=brand_org.strip(),
                analyst_name=brand_analyst.strip(),
                classification_label=brand_class.strip() or "INTERNAL USE ONLY",
                footer_text=brand_footer.strip(),
            )
            save_report_branding(branding)
            st.success("Branding settings saved locally.")

    with st.expander("Scheduled export", expanded=False):
        schedule = load_report_schedule()
        schedule_enabled = st.checkbox("Enable scheduled export", value=schedule.enabled)
        schedule_hours = st.number_input(
            "Export interval (hours)",
            min_value=1,
            max_value=168,
            value=schedule.interval_hours,
        )
        schedule_format = st.selectbox(
            "Scheduled format",
            options=["markdown", "html", "json", "pdf"],
            index=["markdown", "html", "json", "pdf"].index(schedule.export_format)
            if schedule.export_format in ("markdown", "html", "json", "pdf")
            else 0,
        )
        schedule_all_cases = st.checkbox(
            "Export all open cases (not just active)",
            value=schedule.export_all_open_cases,
        )
        if schedule.last_run_at:
            st.caption(f"Last scheduled run: {schedule.last_run_at}")
        if st.button("Save schedule settings", key="save_schedule"):
            save_report_schedule(
                ReportSchedule(
                    enabled=schedule_enabled,
                    interval_hours=int(schedule_hours),
                    export_format=schedule_format,
                    export_all_open_cases=schedule_all_cases,
                    last_run_at=schedule.last_run_at,
                )
            )
            st.success("Schedule settings saved. Exports run when the Report page is opened.")

    active_run_mode = st.session_state.get("operation_run_mode")
    case = get_case(case_id)
    if case and case.get("default_run_mode"):
        active_run_mode = case.get("default_run_mode")

    suggested_preset = suggest_preset_for_run_mode(active_run_mode)
    if suggested_preset:
        suggested = REPORT_PRESETS[suggested_preset]
        mode_label = get_run_mode_label(active_run_mode) if active_run_mode else "this investigation"
        st.info(
            f"Suggested export preset for **{mode_label}**: **{suggested.label}** — "
            f"{suggested.description}"
        )
        if st.button("Apply suggested preset", key="apply_suggested_report_preset"):
            apply_preset_to_session(suggested_preset)
            st.rerun()

    preset_col1, preset_col2 = st.columns([2, 1])
    with preset_col1:
        preset_options = preset_select_options(active_run_mode)
        preset_choice = st.selectbox(
            "Export preset",
            options=preset_options,
            format_func=lambda value: (
                "Custom settings"
                if value == "custom"
                else (
                    f"{REPORT_PRESETS[value].label} ★"
                    if REPORT_PRESETS[value].suggested_run_mode_id == active_run_mode
                    else REPORT_PRESETS[value].label
                )
            ),
            key="report_preset_choice",
        )
        if preset_choice != "custom":
            st.caption(REPORT_PRESETS[preset_choice].description)
    with preset_col2:
        st.write("")
        if st.button("Apply preset", width="stretch", disabled=preset_choice == "custom"):
            apply_preset_to_session(preset_choice)
            st.rerun()

    if "report_template" not in st.session_state:
        st.session_state.report_template = "full"
    if "include_closed_findings" not in st.session_state:
        st.session_state.include_closed_findings = False
    if "include_raw_appendix" not in st.session_state:
        st.session_state.include_raw_appendix = False
    if "include_graph_appendix" not in st.session_state:
        st.session_state.include_graph_appendix = False
    if "redact_ips" not in st.session_state:
        st.session_state.redact_ips = False
    if "redact_emails" not in st.session_state:
        st.session_state.redact_emails = False
    if "redact_domains" not in st.session_state:
        st.session_state.redact_domains = False

    report_col1, report_col2 = st.columns(2)
    with report_col1:
        report_template = st.selectbox(
            "Report template",
            options=["full", "executive"],
            format_func=lambda value: "Full technical" if value == "full" else "Executive summary",
            help="Executive omits detailed entities, relationships, and observations.",
            key="report_template",
        )
        include_closed_findings = st.checkbox(
            "Include closed / accepted / false positive findings",
            help="When unchecked, only active findings (open, in review, action required) are included.",
            key="include_closed_findings",
        )
        include_raw_appendix = st.checkbox(
            "Include raw output appendix",
            help="When enabled, observation raw output is appended in fenced code blocks.",
            key="include_raw_appendix",
        )
    with report_col2:
        include_graph_appendix = st.checkbox(
            "Include entity graph snapshot",
            help="Embeds a PNG graph in the appendix when kaleido is available.",
            key="include_graph_appendix",
        )
        redact_ips = st.checkbox("Redact IP addresses", key="redact_ips")
        redact_emails = st.checkbox("Redact email addresses", key="redact_emails")
        redact_domains = st.checkbox("Redact domain names", key="redact_domains")

    with st.expander("Advanced redaction", expanded=False):
        custom_terms_text = st.text_area(
            "Additional strings to redact (one per line)",
            height=100,
            placeholder="internal-hostname\nclient-secret-token",
        )
        custom_regex_text = st.text_area(
            "Custom regex patterns (one per line: pattern|||replacement)",
            height=100,
            placeholder=r"10\.\d+\.\d+\.\d+|||[REDACTED_SUBNET]",
        )
        st.caption("Lines starting with # are ignored. Custom redaction runs after built-in patterns.")

    report_options = build_report_options_from_state(
        branding,
        custom_terms_text=custom_terms_text,
        custom_regex_text=custom_regex_text,
    )

    if "case_report_markdown" not in st.session_state:
        st.session_state.case_report_markdown = ""

    generate_report = st.button("Generate / refresh report preview", type="primary")
    if generate_report:
        try:
            st.session_state.case_report_markdown = build_case_report(
                case_id,
                options=report_options,
            )
        except Exception as exc:
            st.session_state.case_report_markdown = ""
            st.error(f"Failed to generate report: {exc}")

    report_markdown = st.session_state.case_report_markdown
    if report_markdown:
        st.markdown("### Report preview")
        with st.container(height=480, border=True):
            st.markdown(report_markdown)

        conn = get_db_conn()
        case = get_case(case_id, conn=conn)
        conn.close()
        case_slug = (case or {}).get("name", f"case_{case_id}")
        safe_name = re.sub(r"[^\w\-]+", "_", case_slug.strip().lower()) or "case"
        report_json = build_case_report_json(case_id, options=report_options)
        report_html = markdown_to_html(
            report_markdown,
            title=f"Case Report — {case_slug}" if case else "Project Overwatch Case Report",
            branding=branding,
        )
        pdf_available = is_pdf_export_available()
        encryption_available = is_encryption_available()

        save_col1, save_col2, save_col3, save_col4 = st.columns(4)
        with save_col1:
            if st.button("Save Markdown", width="stretch"):
                try:
                    saved_path = save_report_markdown(
                        case_id,
                        markdown_text=report_markdown,
                    )
                    st.success(f"Saved to `{saved_path}`")
                except Exception as exc:
                    st.error(f"Failed to save Markdown: {exc}")
        with save_col2:
            if st.button("Save HTML", width="stretch"):
                try:
                    saved_path = save_report_html(
                        case_id,
                        html_text=report_html,
                    )
                    st.success(f"Saved to `{saved_path}`")
                except Exception as exc:
                    st.error(f"Failed to save HTML: {exc}")
        with save_col3:
            if st.button("Save PDF", width="stretch", disabled=not pdf_available):
                try:
                    saved_path = save_report_pdf(
                        case_id,
                        html_text=report_html,
                        branding=branding,
                    )
                    st.success(f"Saved to `{saved_path}`")
                except Exception as exc:
                    st.error(f"Failed to save PDF: {exc}")
            if not pdf_available:
                st.caption("Install WeasyPrint for native PDF export.")
        with save_col4:
            export_password = st.text_input(
                "Encryption password",
                type="password",
                key="report_encrypt_password",
                disabled=not encryption_available,
            )
            encrypt_format = st.selectbox(
                "Encrypt format",
                options=["markdown", "html", "json"],
                key="encrypt_format",
                disabled=not encryption_available,
            )
            if st.button("Save encrypted", width="stretch", disabled=not encryption_available):
                if not export_password:
                    st.warning("Enter a password for encrypted export.")
                else:
                    try:
                        payload = {
                            "markdown": report_markdown,
                            "html": report_html,
                            "json": report_json,
                        }[encrypt_format].encode("utf-8")
                        saved_path = save_encrypted_report(
                            case_id,
                            payload,
                            export_password,
                            suffix=f"{encrypt_format}.enc",
                        )
                        st.success(f"Encrypted export saved to `{saved_path}`")
                    except Exception as exc:
                        st.error(f"Encrypted export failed: {exc}")
            if not encryption_available:
                st.caption("Install cryptography for encrypted export.")

        download_col1, download_col2, download_col3, download_col4 = st.columns(4)
        with download_col1:
            st.download_button(
                "Download Markdown",
                data=report_markdown,
                file_name=f"{safe_name}_{case_id}_report.md",
                mime="text/markdown",
                width="stretch",
            )
        with download_col2:
            st.download_button(
                "Download HTML",
                data=report_html,
                file_name=f"{safe_name}_{case_id}_report.html",
                mime="text/html",
                width="stretch",
            )
        with download_col3:
            st.download_button(
                "Download JSON",
                data=report_json,
                file_name=f"{safe_name}_{case_id}_export.json",
                mime="application/json",
                width="stretch",
            )
        with download_col4:
            if pdf_available:
                try:
                    pdf_bytes = html_to_pdf_bytes(report_html)
                    st.download_button(
                        "Download PDF",
                        data=pdf_bytes,
                        file_name=f"{safe_name}_{case_id}_report.pdf",
                        mime="application/pdf",
                        width="stretch",
                    )
                except Exception:
                    st.caption("PDF generation failed for this report.")
            else:
                st.caption("PDF download requires WeasyPrint.")
    else:
        st.info("Generate a report preview to review, save, or download.")

    with st.expander("Batch export multiple cases"):
        all_cases = list_cases()
        case_options = {f"{case['name']} (#{case['id']})": case["id"] for case in all_cases}
        selected_labels = st.multiselect(
            "Cases to export",
            options=list(case_options.keys()),
            default=[label for label, cid in case_options.items() if cid == case_id],
        )
        batch_format = st.selectbox(
            "Export format",
            options=["markdown", "html", "json", "pdf"],
            format_func=lambda value: value.upper(),
        )
        if st.button("Batch export selected cases", width="stretch"):
            selected_ids = [case_options[label] for label in selected_labels]
            if not selected_ids:
                st.warning("Select at least one case.")
            else:
                try:
                    saved_paths = batch_export_reports(
                        selected_ids,
                        export_format=batch_format,
                        options=report_options,
                    )
                    if saved_paths:
                        st.success(f"Exported {len(saved_paths)} report(s) to `reports/`.")
                        for path in saved_paths[:10]:
                            st.caption(str(path))
                        if len(saved_paths) > 10:
                            st.caption(f"…and {len(saved_paths) - 10} more.")
                    else:
                        st.warning("No reports were saved.")
                except Exception as exc:
                    st.error(f"Batch export failed: {exc}")


def render_backup_page(case_id: int, metrics: dict[str, int]) -> None:
    st.title("Backup")
    render_compact_metrics(metrics)
    st.divider()

    conn = get_db_conn()
    st.dataframe(pd.read_sql_query("SELECT * FROM cases", conn), width="stretch")
    conn.close()
    st.caption("Case backup — export or import investigation data as JSON.")
    backup_col1, backup_col2 = st.columns(2)
    with backup_col1:
        bundle_json = export_case_bundle_json(case_id)
        st.download_button(
            "Download case backup (JSON)",
            data=bundle_json,
            file_name=f"case_{case_id}_backup.json",
            mime="application/json",
            width="stretch",
        )
    with backup_col2:
        uploaded = st.file_uploader("Import case backup", type=["json"], key="case_backup_upload")
        import_name = st.text_input("New case name (optional)", key="case_import_name")
        if uploaded and st.button("Import backup as new case", width="stretch"):
            try:
                bundle = parse_case_bundle_json(uploaded.getvalue().decode("utf-8"))
                imported = import_case_bundle(
                    bundle,
                    new_case_name=import_name.strip() or None,
                )
                st.session_state.case_id = imported["id"]
                st.success(f"Imported case '{imported['name']}' (#{imported['id']}).")
                st.rerun()
            except Exception as exc:
                st.error(f"Import failed: {exc}")

    with st.expander("Legacy (v0.1)"):
        st.caption(
            "Legacy v0.1 tables kept for backwards compatibility. "
            "Use **Entities** and **Observations** for current investigations."
        )
        conn = get_db_conn()
        st.markdown("**Targets (legacy manifest)**")
        st.dataframe(pd.read_sql_query("SELECT * FROM targets", conn), width="stretch")
        st.markdown("**Scan logs (legacy recon_data)**")
        st.dataframe(pd.read_sql_query("SELECT * FROM recon_data", conn), width="stretch")
        conn.close()

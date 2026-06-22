"""Evidence Locker page for Project Overwatch."""

from __future__ import annotations

from typing import Any

import streamlit as st

from database.db_setup import get_db_conn, list_entities, list_evidence_items, list_findings
from ui.metrics import render_compact_metrics
from utils.evidence_model import evidence_type_label, reliability_label
from utils.evidence_storage import read_spilled_content

CONTENT_PREVIEW_LIMIT = 500
CONTENT_EXPAND_LIMIT = 12000


def _linked_label(value: int | None, lookup: dict[int, str]) -> str:
    if value is None:
        return "-"
    return lookup.get(value, f"#{value}")


def render_evidence_item_detail(item: dict[str, Any]) -> None:
    st.markdown(f"**Summary:** {item.get('summary') or '_No summary._'}")
    if item.get("content_hash"):
        st.markdown(f"**Content hash (SHA-256):** `{item['content_hash']}`")
    if item.get("storage_path"):
        st.markdown(f"**Storage path:** `{item['storage_path']}`")
        st.caption("Full artefact stored on disk; preview below may be truncated.")
    content = item.get("content_text") or read_spilled_content(item.get("storage_path")) or ""
    if not content:
        st.caption("_No text content stored for this artefact._")
        return
    preview = content[:CONTENT_PREVIEW_LIMIT]
    with st.expander("Content preview", expanded=False):
        st.code(preview + ("..." if len(content) > CONTENT_PREVIEW_LIMIT else ""), language="text")
    if len(content) <= CONTENT_EXPAND_LIMIT:
        with st.expander("Full content", expanded=False):
            st.code(content, language="text")
    else:
        st.caption(
            f"Full content is {len(content):,} characters — open **Evidence Locker** export or "
            "database backup to review the complete artefact."
        )


def render_evidence_page(case_id: int, metrics: dict[str, int]) -> None:
    st.title("Evidence Locker")
    render_compact_metrics(metrics)
    st.divider()
    st.caption(
        f"Source artefacts and raw capture for case #{case_id}. "
        "Text artefacts are stored locally with SHA-256 hashes for change detection."
    )

    conn = get_db_conn()
    items = list_evidence_items(case_id=case_id, conn=conn)
    entities = list_entities(case_id=case_id, conn=conn)
    findings = list_findings(case_id=case_id, conn=conn)
    conn.close()

    entity_lookup = {
        entity["id"]: entity.get("label") or entity.get("value", entity["id"])
        for entity in entities
    }
    finding_lookup = {finding["id"]: finding.get("title", finding["id"]) for finding in findings}

    if not items:
        st.info(
            "No evidence items recorded for this case yet. "
            "Run a collection module to capture raw outputs and source summaries."
        )
        return

    module_options = sorted({item.get("module_id") for item in items if item.get("module_id")})
    filter_col1, filter_col2 = st.columns(2)
    with filter_col1:
        selected_modules = st.multiselect(
            "Filter by module",
            options=module_options,
            default=module_options,
            key="evidence_module_filter",
        )
    with filter_col2:
        evidence_types = sorted({item.get("evidence_type") for item in items if item.get("evidence_type")})
        selected_types = st.multiselect(
            "Filter by evidence type",
            options=evidence_types,
            default=evidence_types,
            key="evidence_type_filter",
        )

    filtered = [
        item
        for item in items
        if item.get("module_id") in selected_modules
        and (not item.get("evidence_type") or item.get("evidence_type") in selected_types)
    ]

    st.markdown(f"**Showing {len(filtered)} of {len(items)} evidence item(s).**")

    for item in filtered:
        header = item.get("title") or "Evidence item"
        module = item.get("module_id") or "unknown"
        captured = item.get("captured_at") or item.get("created_at") or "-"
        with st.expander(f"{header} · {module} · {captured}", expanded=False):
            st.markdown(f"**Module:** `{module}`")
            st.markdown(f"**Source:** `{item.get('source_name') or '-'}`")
            st.markdown(
                f"**Evidence type:** {evidence_type_label(item.get('evidence_type'))} · "
                f"**Reliability:** {reliability_label(item.get('reliability'))}"
            )
            if item.get("confidence") is not None:
                st.markdown(f"**Confidence:** {item.get('confidence')}")
            st.markdown(f"**Captured at:** {captured}")
            st.markdown(f"**Linked entity:** {_linked_label(item.get('entity_id'), entity_lookup)}")
            st.markdown(f"**Linked observation:** #{item.get('observation_id') or '-'}")
            st.markdown(f"**Linked finding:** {_linked_label(item.get('finding_id'), finding_lookup)}")
            if item.get("content_hash"):
                st.markdown(f"**Content hash:** `{item['content_hash']}`")
            render_evidence_item_detail(item)

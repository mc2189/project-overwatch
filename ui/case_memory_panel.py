"""Case memory, baseline, and change detection UI."""

from __future__ import annotations

from typing import Any

import streamlit as st

from database.db_setup import (
    create_case_baseline,
    get_db_conn,
    get_latest_case_baseline,
    list_case_baselines,
    mark_expected_item,
    update_case_baseline,
)
from ui.styles import section_heading
from utils.baseline_compare import compare_baseline_to_current, compare_case_to_latest_baseline
from utils.case_memory import build_baseline_snapshot, build_case_memory
from utils.baseline_ops import (
    baseline_snapshot_summary,
    is_baseline_snapshot_ready,
    snapshot_and_replace_baseline,
)
from utils.case_memory_refresh import (
    CASE_MEMORY_ANCHOR_ID,
    WORKSPACE_SCROLL_TO_CASE_MEMORY_KEY,
    get_case_memory_refresh,
    pop_case_memory_refresh,
    store_case_memory_refresh,
)
from utils.settings_manager import auto_suggest_baseline_creation


def _change_item_type(change: dict[str, Any]) -> tuple[str, str]:
    change_type = change.get("change_type") or ""
    mapping = {
        "new_device": ("device", change.get("target") or ""),
        "missing_device": ("device", change.get("target") or ""),
        "new_service": ("service", change.get("target") or change.get("title") or ""),
        "closed_service": ("service", change.get("target") or change.get("title") or ""),
        "changed_service": ("service", change.get("target") or ""),
        "new_remote_access_service": ("remote_access", change.get("target") or ""),
        "new_finding": ("finding", (change.get("current_state") or {}).get("fingerprint") or change.get("title") or ""),
        "new_web_path_response": ("web_path", change.get("target") or ""),
        "new_web_technology": ("technology", change.get("target") or ""),
        "new_sensitive_metadata": ("finding", change.get("target") or change.get("title") or ""),
    }
    item_type, item_key = mapping.get(change_type, ("device", change.get("target") or change.get("title") or "item"))
    return item_type, str(item_key).strip()


def _mark_changes_expected(case_id: int, changes: list[dict[str, Any]]) -> None:
    conn = get_db_conn()
    try:
        for change in changes:
            item_type, item_key = _change_item_type(change)
            if not item_key:
                continue
            mark_expected_item(
                case_id,
                item_type=item_type,
                item_key=item_key,
                notes=change.get("summary"),
                conn=conn,
            )
    finally:
        conn.close()


def render_case_memory_panel(
    case_id: int,
    *,
    conn: Any | None = None,
    quiet: bool = False,
) -> dict[str, Any]:
    """Render case memory card, change summary, and baseline controls.

    When ``quiet`` is True, hide the heavy baseline chrome until the case has a
    baseline, a post-run refresh, or session results — keeps empty Lab calm.
    """
    own_conn = conn is None
    if own_conn:
        conn = get_db_conn()
    try:
        memory = build_case_memory(case_id, conn=conn)
        comparison = compare_case_to_latest_baseline(case_id, conn=conn)
        baselines = list_case_baselines(case_id, limit=12, conn=conn)
    finally:
        if own_conn:
            conn.close()

    refresh = get_case_memory_refresh(st.session_state, case_id)
    has_session_results = bool(st.session_state.get("latest_run_results"))
    has_baseline = bool(comparison.get("has_baseline"))
    memory_counts = (
        len(memory.get("known_devices") or []),
        len(memory.get("known_services") or []),
        len(memory.get("open_findings") or []),
        len(memory.get("accepted_findings") or []),
    )
    show_full_controls = (
        not quiet
        or bool(refresh)
        or has_session_results
        or has_baseline
    )

    section_heading("Case memory")
    st.markdown(f'<div id="{CASE_MEMORY_ANCHOR_ID}"></div>', unsafe_allow_html=True)

    if quiet and not show_full_controls:
        if any(memory_counts):
            cols = st.columns(4)
            cols[0].metric("Devices", memory_counts[0])
            cols[1].metric("Services", memory_counts[1])
            cols[2].metric("Open findings", memory_counts[2])
            cols[3].metric("Accepted", memory_counts[3])
            st.caption("Run **Assess target** to update memory and enable baselines.")
        else:
            st.caption("Memory and baselines appear after your first assessment.")
        return {"memory": memory, "comparison": comparison, "quiet": True}
    if refresh:
        refresh_lines = [
            f"Updated after latest run — **{refresh.get('device_count', 0)}** devices, "
            f"**{refresh.get('service_count', 0)}** services, "
            f"**{refresh.get('open_findings', 0)}** open findings."
        ]
        if refresh.get("comparison_summary"):
            refresh_lines.append(str(refresh["comparison_summary"]))
        unexpected_count = int(refresh.get("unexpected_count") or 0)
        if unexpected_count:
            refresh_lines.append(f"**{unexpected_count}** unreviewed change(s) since baseline.")
        for change in refresh.get("notable_changes") or []:
            if change.get("title"):
                refresh_lines.append(f"- {change['title']}")
        st.info("\n\n".join(refresh_lines))
        if st.button("Dismiss memory update", key=f"dismiss_memory_refresh_{case_id}"):
            pop_case_memory_refresh(st.session_state, case_id)
            st.rerun()

    with st.container(border=True):
        cols = st.columns(4)
        cols[0].metric("Devices", len(memory.get("known_devices") or []))
        cols[1].metric("Services", len(memory.get("known_services") or []))
        cols[2].metric("Open findings", len(memory.get("open_findings") or []))
        cols[3].metric("Accepted", len(memory.get("accepted_findings") or []))

        baseline_meta = memory.get("latest_baseline") or {}
        if baseline_meta.get("baseline_id"):
            st.caption(
                f"Latest baseline: **{baseline_meta.get('name') or 'Baseline'}** · "
                f"updated {baseline_meta.get('updated_at') or '—'}"
            )
        elif auto_suggest_baseline_creation() and (memory.get("known_devices") or memory.get("known_services")):
            st.warning("No baseline yet — create one to track changes on your next run.")
        else:
            st.caption("No baseline yet — create one after a meaningful assessment run.")

        st.markdown(f"**Changes since baseline:** {comparison.get('summary_text')}")

        snapshot_ready = is_baseline_snapshot_ready(comparison)
        snapshot_summary = baseline_snapshot_summary(comparison)
        if snapshot_ready:
            st.success(snapshot_summary)
        else:
            st.warning(snapshot_summary)

        snap_col1, snap_col2 = st.columns([3, 2])
        with snap_col1:
            snapshot_clicked = st.button(
                "Snapshot & replace latest baseline",
                key=f"snapshot_replace_{case_id}",
                type="primary",
                help="Save current devices, services, and findings as the new comparison baseline.",
            )
        with snap_col2:
            force_snapshot_clicked = False
            if not snapshot_ready:
                force_snapshot_clicked = st.button(
                    "Snapshot anyway",
                    key=f"snapshot_force_{case_id}",
                    help="Replace baseline even with unreviewed changes — use after you accept current state.",
                )

        if snapshot_clicked or force_snapshot_clicked:
            conn = get_db_conn()
            try:
                baseline_name_value = st.session_state.get(f"baseline_name_input_{case_id}") or baseline_meta.get("name")
                result = snapshot_and_replace_baseline(
                    case_id,
                    name=str(baseline_name_value or "Lab baseline"),
                    notes=None,
                    source="assessment_workspace",
                    conn=conn,
                )
            finally:
                conn.close()
            verb = "created" if result.get("action") == "created" else "replaced"
            st.success(f"Baseline {verb}: **{result.get('name')}**. Next run will compare against this snapshot.")
            st.session_state.pop(f"case_memory_compare_{case_id}", None)
            st.rerun()

        compare_open = bool(st.session_state.get(f"case_memory_compare_{case_id}"))
        grouped = comparison.get("grouped") or {}
        top_changes = comparison.get("notable_changes") or (comparison.get("changes") or [])[:8]
        expand_changes = compare_open or bool(top_changes)
        with st.expander("Change summary", expanded=expand_changes):
            if not comparison.get("has_baseline"):
                st.caption("Create a baseline first, then re-run checks to see changes here.")
            else:
                for bucket, label in (
                    ("new", "New"),
                    ("changed", "Changed"),
                    ("resolved", "Resolved"),
                    ("expected", "Expected"),
                ):
                    rows = grouped.get(bucket) or []
                    if not rows:
                        continue
                    st.markdown(f"**{label}**")
                    for change in rows[:6]:
                        st.markdown(f"- {change.get('title')}")
                        st.caption(change.get("summary"))
                        if change.get("suggested_action"):
                            st.caption(f"Suggested: {change['suggested_action']}")

        if len(baselines) > 1:
            with st.expander("Baseline history", expanded=False):
                for row in baselines:
                    st.markdown(
                        f"- **{row.get('name') or 'Baseline'}** · "
                        f"{row.get('updated_at') or row.get('created_at') or '—'}"
                    )
                selected = st.selectbox(
                    "Compare against baseline",
                    options=[row["baseline_id"] for row in baselines],
                    format_func=lambda baseline_id: next(
                        (
                            f"{item.get('name') or 'Baseline'} · {item.get('updated_at') or item.get('created_at')}"
                            for item in baselines
                            if int(item["baseline_id"]) == int(baseline_id)
                        ),
                        str(baseline_id),
                    ),
                    key=f"baseline_history_select_{case_id}",
                )
                if st.button("Compare selected baseline", key=f"compare_selected_baseline_{case_id}"):
                    selected_row = next(
                        item for item in baselines if int(item["baseline_id"]) == int(selected)
                    )
                    conn = get_db_conn()
                    try:
                        selected_comparison = compare_baseline_to_current(
                            case_id,
                            baseline_summary=selected_row.get("summary") or {},
                            conn=conn,
                        )
                    finally:
                        conn.close()
                    st.session_state[f"case_memory_compare_{case_id}"] = selected_comparison
                    st.session_state[f"case_memory_comparison_{case_id}"] = selected_comparison
                    st.rerun()

        with st.form(key=f"create_baseline_form_{case_id}"):
            baseline_name = st.text_input(
                "Baseline name",
                value=baseline_meta.get("name") or "Lab baseline",
                key=f"baseline_name_input_{case_id}",
            )
            baseline_notes = st.text_input(
                "Notes (optional)",
                value="",
                key=f"baseline_notes_input_{case_id}",
            )
            create_col, update_col, compare_col = st.columns(3)
            create_clicked = create_col.form_submit_button("Create baseline")
            update_clicked = update_col.form_submit_button(
                "Update latest",
                disabled=baseline_meta.get("baseline_id") is None,
            )
            compare_clicked = compare_col.form_submit_button("Refresh compare")

        if create_clicked:
            conn = get_db_conn()
            try:
                snapshot = build_baseline_snapshot(
                    case_id,
                    conn=conn,
                    name=baseline_name.strip() or "Lab baseline",
                )
                create_case_baseline(
                    case_id,
                    name=baseline_name.strip() or "Lab baseline",
                    summary=snapshot,
                    source="assessment_workspace",
                    notes=baseline_notes.strip() or None,
                    conn=conn,
                )
            finally:
                conn.close()
            st.success("Baseline created from current case state.")
            st.rerun()

        if update_clicked and baseline_meta.get("baseline_id"):
            conn = get_db_conn()
            try:
                snapshot = build_baseline_snapshot(
                    case_id,
                    conn=conn,
                    name=baseline_name.strip() or baseline_meta.get("name"),
                )
                update_case_baseline(
                    int(baseline_meta["baseline_id"]),
                    summary=snapshot,
                    name=baseline_name.strip() or None,
                    notes=baseline_notes.strip() or None,
                    conn=conn,
                )
            finally:
                conn.close()
            st.success("Baseline updated.")
            st.rerun()

        if compare_clicked:
            st.session_state[f"case_memory_compare_{case_id}"] = True
            st.rerun()

        review_changes = [
            change
            for change in comparison.get("changes") or []
            if not change.get("expected") and change.get("category") in {"new", "changed"}
        ][:12]
        if review_changes:
            st.markdown("**Mark as expected**")
            selected_labels = st.multiselect(
                "Select changes to mark expected",
                options=list(range(len(review_changes))),
                format_func=lambda index: review_changes[index].get("title") or "Change",
                key=f"expected_changes_multi_{case_id}",
            )
            if st.button("Mark selected as expected", key=f"mark_expected_batch_{case_id}"):
                selected = [review_changes[index] for index in selected_labels]
                _mark_changes_expected(case_id, selected)
                st.success(f"Marked {len(selected)} item(s) as expected.")
                st.rerun()

    return {"memory": memory, "comparison": comparison}

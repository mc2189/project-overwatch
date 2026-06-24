"""Batch Queue page — controlled passive-first entity/module pivot runner."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from database.db_setup import (
    get_db_conn,
    list_entities,
    list_operations,
    list_pivot_queue,
    list_pivot_queue_entity_ids,
)
from ui.constants import MODULE_CARD_TITLES
from ui.metrics import render_compact_metrics
from utils.batch_queue import (
    PASSIVE_BATCH_MODULE_IDS,
    SESSION_RESULTS_KEY,
    add_passive_modules_for_entity,
    add_queue_item,
    clear_completed_items,
    clear_queue_items,
    execute_queue_items,
    module_recommendations_for_entity,
    passive_queued_items,
    remove_queue_item,
    selectable_queued_items,
    sort_queue_items,
)
from utils.batch_queue_store import (
    load_batch_queue,
    load_recent_batch_runs,
    migrate_session_batch_queue,
    move_queue_item,
    other_case_queue_summary,
    record_batch_queue_run,
    save_batch_queue,
)
from utils.settings_manager import rate_limit_seconds
from utils.operating_context import (
    CLIENT_ENGAGEMENT,
    PASSIVE_RESEARCH,
    PERSONAL_LAB,
    PERSONAL_LAB_CONFIRMATION_TEXT,
    operating_context_label,
)


def _save_queue(case_id: int, items: list[dict]) -> None:
    save_batch_queue(case_id, sort_queue_items(items))


def _load_queue(case_id: int) -> list[dict]:
    migrate_session_batch_queue(case_id, st.session_state)
    return sort_queue_items(load_batch_queue(case_id))


def navigate_to_batch_queue() -> None:
    st.session_state.nav_page = "Batch Queue"


def add_entity_passive_modules_to_batch_queue(case_id: int, entity: dict) -> tuple[int, list[str]]:
    """Add compatible passive modules for one entity. Returns (added_count, skip_messages)."""
    conn = get_db_conn()
    try:
        operations = list_operations(case_id=case_id, conn=conn)
    finally:
        conn.close()
    items = _load_queue(case_id)
    updated, added, skipped = add_passive_modules_for_entity(items, case_id, entity, operations)
    _save_queue(case_id, updated)
    return len(added), skipped


def import_pivot_queue_entities(case_id: int, entity_by_id: dict[int, dict]) -> tuple[int, list[str]]:
    """Import entities from the DB pivot queue and add passive modules to the batch queue."""
    conn = get_db_conn()
    try:
        entity_ids = list_pivot_queue_entity_ids(case_id, conn=conn)
        operations = list_operations(case_id=case_id, conn=conn)
    finally:
        conn.close()

    items = _load_queue(case_id)
    total_added = 0
    all_skipped: list[str] = []
    for entity_id in entity_ids:
        entity = entity_by_id.get(entity_id)
        if entity is None:
            continue
        items, added, skipped = add_passive_modules_for_entity(items, case_id, entity, operations)
        total_added += len(added)
        all_skipped.extend(skipped)
    _save_queue(case_id, items)
    return total_added, all_skipped


def _entity_label(entity: dict) -> str:
    return entity.get("label") or entity.get("value") or str(entity["id"])


def _render_entity_selector(
    case_id: int,
    entities: list[dict],
    operations: list[dict],
) -> None:
    st.subheader("Add to batch queue")
    entity_types = sorted({entity.get("entity_type", "unknown") for entity in entities})
    filter_col1, filter_col2 = st.columns(2)
    with filter_col1:
        type_filter = st.selectbox(
            "Filter by entity type",
            options=["All", *entity_types],
            key="batch_queue_type_filter",
        )
    with filter_col2:
        st.caption("Select entities, review compatible modules, then add passive pairs to the queue.")

    filtered = entities
    if type_filter != "All":
        filtered = [entity for entity in entities if entity.get("entity_type") == type_filter]

    if not filtered:
        st.info("No entities match this filter.")
        return

    selected_ids = st.multiselect(
        "Select entities",
        options=[entity["id"] for entity in filtered],
        format_func=lambda eid: next(
            f"#{eid} · {_entity_label(e)}" for e in filtered if e["id"] == eid
        ),
        key="batch_queue_entity_select",
    )

    if not selected_ids:
        return

    selected_entities = [entity for entity in filtered if entity["id"] in selected_ids]
    recommendation_rows: list[dict] = []
    for entity in selected_entities:
        for row in module_recommendations_for_entity(entity):
            recommendation_rows.append(
                {
                    "entity": _entity_label(entity),
                    "entity_id": entity["id"],
                    "module": row["display_name"],
                    "module_id": row["module_id"],
                    "mode": row["mode"],
                    "passive_default": "Yes" if row.get("is_passive_default") else "No",
                    "compatible": "Yes" if row.get("compatible") else "No",
                }
            )

    if recommendation_rows:
        st.markdown("**Compatible module suggestions**")
        st.dataframe(pd.DataFrame(recommendation_rows), width="stretch", hide_index=True)

    for entity in selected_entities:
        pivot = build_pivot_recommendations(entity)
        for suggestion in pivot.get("suggestions") or []:
            st.caption(f"{_entity_label(entity)}: {suggestion}")

    action_col1, action_col2, action_col3 = st.columns(3)
    items = _load_queue(case_id)

    with action_col1:
        if st.button("Add passive modules for selection", key="batch_add_passive_selection", width="stretch"):
            updated = items
            added_count = 0
            skipped: list[str] = []
            for entity in selected_entities:
                updated, added, skip = add_passive_modules_for_entity(
                    updated, case_id, entity, operations
                )
                added_count += len(added)
                skipped.extend(skip)
            _save_queue(case_id, updated)
            if added_count:
                st.success(f"Added {added_count} passive queue item(s).")
            if skipped:
                st.info("Skipped: " + "; ".join(skipped[:5]))
            st.rerun()

    with action_col2:
        passive_module_pick = st.selectbox(
            "Passive module",
            options=list(PASSIVE_BATCH_MODULE_IDS),
            format_func=lambda mid: MODULE_CARD_TITLES.get(mid, mid),
            key="batch_single_passive_module",
            label_visibility="collapsed",
        )
        if st.button("Add one passive module to selection", key="batch_add_one_passive", width="stretch"):
            updated = items
            added_count = 0
            for entity in selected_entities:
                updated, item, reason = add_queue_item(
                    updated, case_id, entity, passive_module_pick, operations=operations
                )
                if item:
                    added_count += 1
            _save_queue(case_id, updated)
            if added_count:
                st.success(f"Added {added_count} item(s).")
            else:
                st.warning("Nothing added — items may already be queued or incompatible.")
            st.rerun()

    with action_col3:
        st.caption("Active modules such as Nmap are not added by default.")
        if st.button("Show active module add (manual)", key="batch_show_active_add"):
            st.session_state.batch_queue_show_active_add = True

    if st.session_state.get("batch_queue_show_active_add"):
        st.warning(
            "Network Service Check is **active** and requires authorisation at run time. "
            "It is never included in passive batch runs."
        )
        if st.button("Add Nmap to selection (one per entity)", key="batch_add_nmap_selection"):
            updated = items
            added_count = 0
            for entity in selected_entities:
                updated, item, _ = add_queue_item(
                    updated, case_id, entity, "infra_nmap", operations=operations
                )
                if item:
                    added_count += 1
            _save_queue(case_id, updated)
            st.success(f"Added {added_count} Nmap queue item(s).")
            st.rerun()


def _render_queue_table(case_id: int, entity_by_id: dict[int, dict]) -> list[dict]:
    st.subheader("Current queue")
    items = _load_queue(case_id)
    if not items:
        st.info("Queue is empty. Select entities above or import from Entity Workspace pivot queue.")
        return items

    display_rows = []
    for item in items:
        display_rows.append(
            {
                "pos": item.get("position", 0) + 1,
                "queue_id": item["queue_id"],
                "entity": item.get("entity_value"),
                "type": item.get("entity_type"),
                "module": item.get("module_display_name"),
                "mode": item.get("mode"),
                "compatible": item.get("compatibility_status"),
                "status": item.get("status"),
                "summary": (item.get("summary") or "")[:120],
                "warning": item.get("recent_run_warning") or "",
            }
        )
    st.dataframe(pd.DataFrame(display_rows), width="stretch", hide_index=True)

    reorder_col1, reorder_col2, reorder_col3 = st.columns(3)
    with reorder_col1:
        reorder_id = st.selectbox(
            "Reorder item",
            options=[item["queue_id"] for item in items],
            format_func=lambda qid: next(
                f"{row.get('entity_value')} · {row.get('module_display_name')}"
                for row in items
                if row["queue_id"] == qid
            ),
            key="batch_queue_reorder_select",
        )
    with reorder_col2:
        if st.button("Move up", key="batch_queue_move_up"):
            _save_queue(case_id, move_queue_item(items, reorder_id, "up"))
            st.rerun()
    with reorder_col3:
        if st.button("Move down", key="batch_queue_move_down"):
            _save_queue(case_id, move_queue_item(items, reorder_id, "down"))
            st.rerun()

    for item in items:
        if item.get("recent_run_warning"):
            st.caption(f"⚠ {item['entity_value']} / {item['module_id']}: {item['recent_run_warning']}")

    manage_col1, manage_col2, manage_col3 = st.columns(3)
    with manage_col1:
        remove_id = st.selectbox(
            "Remove queue item",
            options=[item["queue_id"] for item in items],
            format_func=lambda qid: next(
                f"{row['entity_value']} · {row['module_display_name']}"
                for row in items
                if row["queue_id"] == qid
            ),
            key="batch_queue_remove_select",
        )
        if st.button("Remove selected item", key="batch_queue_remove_one"):
            _save_queue(case_id, remove_queue_item(items, remove_id))
            st.rerun()
    with manage_col2:
        if st.button("Clear entire queue", key="batch_queue_clear_all"):
            _save_queue(case_id, clear_queue_items(items))
            st.rerun()
    with manage_col3:
        if st.button("Clear completed items", key="batch_queue_clear_completed"):
            _save_queue(case_id, clear_completed_items(items))
            st.rerun()

    return items


def _render_run_controls(case_id: int, items: list[dict]) -> None:
    st.subheader("Run controls")
    delay_seconds = st.slider(
        "Courtesy delay between passive lookups (seconds)",
        min_value=0.0,
        max_value=5.0,
        value=float(st.session_state.get("batch_queue_delay", rate_limit_seconds())),
        step=0.5,
        key="batch_queue_delay_slider",
    )
    st.session_state.batch_queue_delay = delay_seconds

    queued_passive = passive_queued_items(items)
    queued_selectable = selectable_queued_items(items)
    active_queued = [item for item in queued_selectable if item.get("mode") == "active"]

    st.caption(
        f"Queued: {len(queued_selectable)} runnable · "
        f"Passive default batch: {len(queued_passive)} · "
        f"Active (manual only): {len(active_queued)}"
    )

    passive_ids = [item["queue_id"] for item in queued_passive]
    selectable_ids = [item["queue_id"] for item in queued_selectable]

    run_col1, run_col2 = st.columns(2)
    with run_col1:
        run_passive = st.button(
            "Run passive queue",
            type="primary",
            disabled=not passive_ids,
            width="stretch",
            key="batch_run_passive",
        )
    with run_col2:
        selected_run_ids = st.multiselect(
            "Queue items to run",
            options=selectable_ids,
            default=selectable_ids,
            format_func=lambda qid: next(
                f"{row['entity_value']} · {row['module_display_name']}"
                for row in items
                if row["queue_id"] == qid
            ),
            key="batch_run_selected_ids",
        )
        run_selected = st.button(
            "Run selected queue items",
            disabled=not selected_run_ids,
            width="stretch",
            key="batch_run_selected",
        )

    stop_after = st.checkbox(
        "Stop after current item",
        value=False,
        key="batch_queue_stop_after_checkbox",
    )

    active_in_selection = [
        item for item in queued_selectable if item.get("mode") == "active"
    ]
    if active_in_selection:
        st.markdown("**Active modules in queue (not included in passive batch run — manual confirmation required)**")
        for item in active_in_selection:
            st.caption(f"⚡ {item['entity_value']} · {item['module_display_name']}")

    authorisation_confirmed = False
    personal_lab_confirmed = False
    batch_operating_context = st.session_state.get("batch_operating_context", PASSIVE_RESEARCH)
    if active_in_selection:
        context_choices = [PASSIVE_RESEARCH, PERSONAL_LAB, CLIENT_ENGAGEMENT]
        batch_operating_context = st.radio(
            "Operating context for active queue items",
            options=context_choices,
            index=context_choices.index(batch_operating_context)
            if batch_operating_context in context_choices
            else 0,
            format_func=operating_context_label,
            key="batch_operating_context_radio",
            horizontal=True,
        )
        st.session_state.batch_operating_context = batch_operating_context
        if batch_operating_context == PERSONAL_LAB:
            personal_lab_confirmed = st.checkbox(
                PERSONAL_LAB_CONFIRMATION_TEXT,
                key="batch_queue_personal_lab_confirmed",
            )
            authorisation_confirmed = personal_lab_confirmed
        elif batch_operating_context == CLIENT_ENGAGEMENT:
            authorisation_confirmed = st.checkbox(
                "I confirm I am authorised to run active checks for queued active modules under client engagement.",
                key="batch_queue_auth",
            )
        else:
            st.warning("Passive Research cannot run active queue items — select Personal Lab or Client Engagement.")

    ids_to_run: list[str] = []
    if run_passive:
        ids_to_run = passive_ids
    elif run_selected:
        ids_to_run = selected_run_ids

    if ids_to_run:
        needs_auth = any(
            item.get("mode") == "active"
            for item in items
            if item.get("queue_id") in ids_to_run
        )
        if needs_auth and batch_operating_context == PASSIVE_RESEARCH:
            st.warning("Select Personal Lab or Client Engagement before running active queue items.")
            return
        if needs_auth and not authorisation_confirmed:
            st.warning("Confirm authorisation before running active queue items.")
            return

        with st.status("Running batch queue...", expanded=True) as status:
            progress = st.progress(0.0)
            conn = get_db_conn()
            started_at = None
            try:
                from datetime import datetime, timezone

                started_at = datetime.now(timezone.utc).isoformat()
                nmap_options = st.session_state.get("nmap_options") or {}
                updated, results = execute_queue_items(
                    case_id,
                    items,
                    ids_to_run,
                    db_conn=conn,
                    authorisation_confirmed=authorisation_confirmed,
                    operating_context=batch_operating_context,
                    personal_lab_confirmed=personal_lab_confirmed,
                    nmap_options=nmap_options,
                    delay_seconds=delay_seconds,
                    stop_after_first=stop_after,
                )
            finally:
                conn.close()
            progress.progress(1.0)
            status.update(label="Batch queue run finished", state="complete")

        _save_queue(case_id, updated)
        if results:
            record_batch_queue_run(case_id, results, started_at=started_at)
        st.session_state[SESSION_RESULTS_KEY] = results

        completed = sum(1 for row in results if row["queue_item"].get("status") == "completed")
        warnings = sum(
            1 for row in results if row["queue_item"].get("status") == "completed_with_warnings"
        )
        failed = sum(
            1
            for row in results
            if row["queue_item"].get("status") in {"blocked", "error"}
        )
        st.success(
            f"Processed {len(results)} item(s): {completed} completed, {warnings} with warnings, {failed} blocked/error."
        )
        st.rerun()


def _render_latest_results(case_id: int) -> None:
    from ui.concise_results import render_concise_result_card

    results = st.session_state.get(SESSION_RESULTS_KEY) or []
    if not results:
        return
    st.subheader("Latest queue results")
    for index, row in enumerate(results):
        item = row["queue_item"]
        result = row.get("result")
        if result:
            render_concise_result_card(
                result,
                target=item.get("entity_value") or "",
                case_id=case_id,
                card_index=index,
            )
        else:
            title = (
                f"{item.get('entity_value')} · {item.get('module_display_name')} · "
                f"{item.get('status')}"
            )
            with st.expander(title, expanded=False):
                st.markdown(f"**Summary:** {item.get('summary') or '-'}")


def render_batch_queue_page(case_id: int, metrics: dict) -> None:
    st.title("Batch Queue")
    render_compact_metrics(metrics)
    st.caption(
        "Select discovered entities and queue compatible **passive** follow-up modules. "
        "Queue items are persisted per case. Runs one item at a time through the normal executor."
    )

    other_queues = other_case_queue_summary(case_id)
    if other_queues:
        with st.expander("Batch queues in other cases", expanded=False):
            for line in other_queues:
                st.caption(line)

    st.divider()

    conn = get_db_conn()
    try:
        entities = list_entities(case_id=case_id, conn=conn)
        operations = list_operations(case_id=case_id, conn=conn)
        pivot_count = len(list_pivot_queue(case_id=case_id, conn=conn))
    finally:
        conn.close()

    if not entities:
        st.info("No entities in this case yet. Run modules or review Entity Workspace first.")
        return

    entity_by_id = {entity["id"]: entity for entity in entities}

    if pivot_count:
        import_col1, import_col2 = st.columns([2, 2])
        with import_col1:
            if st.button(
                f"Import {pivot_count} pivot-queue entit(y/ies) — add passive modules",
                key="batch_import_pivot_queue",
                width="stretch",
            ):
                added, skipped = import_pivot_queue_entities(case_id, entity_by_id)
                if added:
                    st.success(f"Added {added} passive module queue item(s) from pivot queue.")
                elif skipped:
                    st.info("No new items added. " + "; ".join(skipped[:3]))
                else:
                    st.info("No compatible passive modules to add from pivot queue.")
                st.rerun()

    _render_entity_selector(case_id, entities, operations)
    st.divider()
    items = _render_queue_table(case_id, entity_by_id)
    st.divider()
    _render_run_controls(case_id, items)
    st.divider()
    _render_latest_results(case_id)

    recent_runs = load_recent_batch_runs(case_id, limit=5)
    if recent_runs:
        st.subheader("Recent batch runs")
        for run in recent_runs:
            with st.expander(
                f"Run #{run['id']} · {run.get('completed_at', run.get('started_at', '-'))}",
                expanded=False,
            ):
                st.markdown(
                    f"Processed **{run.get('items_processed', 0)}** · "
                    f"Completed **{run.get('items_completed', 0)}** · "
                    f"Warnings **{run.get('items_warnings', 0)}** · "
                    f"Failed **{run.get('items_failed', 0)}**"
                )
                if run.get("run_summary"):
                    st.text(run["run_summary"])

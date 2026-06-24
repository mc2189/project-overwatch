"""Entity Workspace — inspect entities and launch compatible pivot modules."""

from __future__ import annotations

import json

import pandas as pd
import streamlit as st

from database.db_setup import (
    add_to_pivot_queue,
    create_or_get_entity,
    get_db_conn,
    infer_entity_type,
    list_entities,
    list_evidence_items,
    list_findings,
    list_observations,
    list_operations,
    list_pivot_queue,
    list_relationships,
    pivot_queue_contains,
    remove_from_pivot_queue,
    clear_pivot_queue,
    update_entity_confidence,
    update_entity_label,
    update_entity_notes,
)
from database.engagements import get_engagement_for_case
from modules.executor import execute_module
from modules.module_registry import get_module, is_executable
from ui.compact_preflight import render_compact_preflight
from ui.constants import MODULE_CARD_TITLES
from ui.findings_page import render_finding_detail
from ui.evidence_page import render_evidence_item_detail
from ui.metrics import render_compact_metrics
from ui.navigation import ENTITY_WORKSPACE_SELECTED_KEY, open_entity_in_workspace
from ui.workspace_cards import render_mode_explainer
from utils.entity_pivot import (
    build_pivot_recommendations,
    filter_operations_for_entity,
    parse_service_entity_details,
    split_relationships_for_entity,
)
from utils.module_compatibility import build_operation_plan, get_incompatible_reason
from utils.nmap_options import PROFILE_STANDARD, default_options_for_profile
from utils.operating_context import (
    CLIENT_ENGAGEMENT,
    PASSIVE_RESEARCH,
    PERSONAL_LAB,
    PERSONAL_LAB_CONFIRMATION_TEXT,
    enrich_operation_plan_with_preflight,
    list_operating_contexts,
    operating_context_label,
)

PIVOT_QUEUE_KEY = "pivot_queue"


def _migrate_session_pivot_queue(case_id: int) -> None:
    """One-time migration from session-state pivot queue to database storage."""
    legacy = st.session_state.pop(PIVOT_QUEUE_KEY, None)
    if not legacy:
        return
    conn = get_db_conn()
    try:
        for entity_id in legacy:
            add_to_pivot_queue(case_id, int(entity_id), conn=conn)
    finally:
        conn.close()


def queue_entity_for_case(case_id: int, entity_id: int) -> bool:
    """Add an entity to the persisted pivot queue. Returns True on success."""
    conn = get_db_conn()
    try:
        return add_to_pivot_queue(case_id, entity_id, conn=conn) is not None
    finally:
        conn.close()


def _entity_option_label(entity: dict) -> str:
    label = entity.get("label") or entity.get("value") or str(entity["id"])
    return f"#{entity['id']} · {entity.get('entity_type', '?')} · {label}"


def _entity_lookup(entities: list[dict]) -> dict[int, str]:
    return {
        entity["id"]: entity.get("label") or entity.get("value") or str(entity["id"])
        for entity in entities
    }


def _entities_by_value(entities: list[dict]) -> dict[str, dict]:
    return {(entity.get("value") or "").strip().lower(): entity for entity in entities}


def _render_entity_details(entity: dict) -> None:
    st.subheader("Entity details")
    detail_col1, detail_col2 = st.columns(2)
    with detail_col1:
        st.markdown(f"**Type:** `{entity.get('entity_type', '-')}`")
        st.markdown(f"**Value:** `{entity.get('value', '-')}`")
        st.markdown(f"**Label:** {entity.get('label') or '_None_'}")
        st.markdown(f"**Source:** {entity.get('source') or '_Unknown_'}")
    with detail_col2:
        st.markdown(f"**Confidence:** {entity.get('confidence', 50)}")
        st.markdown(f"**Created:** {entity.get('created_at') or '-'}")
        st.markdown(f"**Updated:** {entity.get('updated_at') or '-'}")
        if entity.get("notes"):
            st.markdown("**Notes (saved):**")
            st.write(entity.get("notes"))

    if (entity.get("entity_type") or "").lower() == "service":
        details = parse_service_entity_details(entity)
        if details:
            st.markdown("**Service details**")
            service_cols = st.columns(4)
            service_cols[0].metric("Host", details.get("host", "-"))
            service_cols[1].metric("Port", details.get("port", "-"))
            service_cols[2].metric("Protocol", details.get("protocol", "-"))
            if details.get("service"):
                service_cols[3].metric("Service", details["service"])
            if details.get("version"):
                st.caption(f"Version / banner: {details['version']}")


def _render_entity_edit_form(entity: dict) -> None:
    st.subheader("Analyst fields")
    with st.form(key=f"entity_edit_{entity['id']}"):
        new_label = st.text_input("Label", value=entity.get("label") or "")
        new_confidence = st.slider(
            "Confidence",
            min_value=0,
            max_value=100,
            value=int(entity.get("confidence") or 50),
        )
        new_notes = st.text_area("Analyst notes", value=entity.get("notes") or "")
        if st.form_submit_button("Save entity updates", width="stretch"):
            conn = get_db_conn()
            try:
                update_entity_label(entity["id"], new_label.strip() or None, conn=conn)
                update_entity_confidence(entity["id"], new_confidence, conn=conn)
                update_entity_notes(entity["id"], new_notes.strip() or None, conn=conn)
            finally:
                conn.close()
            st.success("Entity updated.")
            st.rerun()


def _render_relationship_rows(
    case_id: int,
    relationships: list[dict],
    entity_lookup: dict[int, str],
    *,
    direction: str,
) -> None:
    if not relationships:
        st.caption(f"No {direction} relationships.")
        return

    for relationship in relationships:
        rel_id = relationship.get("id", id(relationship))
        if direction == "from":
            other_id = relationship.get("target_entity_id")
            rel_type = relationship.get("relationship_type", "related")
            other_label = entity_lookup.get(other_id, other_id)
            summary = f"**{rel_type}** → {other_label}"
        else:
            other_id = relationship.get("source_entity_id")
            rel_type = relationship.get("relationship_type", "related")
            other_label = entity_lookup.get(other_id, other_id)
            summary = f"{other_label} → **{rel_type}**"

        with st.container(border=True):
            st.markdown(summary)
            st.caption(
                f"Module: `{relationship.get('source_module', '-')}` · "
                f"Confidence: {relationship.get('confidence', 50)}"
            )
            action_col1, action_col2 = st.columns(2)
            with action_col1:
                if st.button(
                    "Open in workspace",
                    key=f"rel_open_{direction}_{rel_id}",
                    width="stretch",
                ):
                    open_entity_in_workspace(other_id)
                    st.rerun()
            with action_col2:
                if st.button(
                    "Add to pivot queue",
                    key=f"rel_queue_{direction}_{rel_id}",
                    width="stretch",
                ):
                    if queue_entity_for_case(case_id, other_id):
                        st.success(f"Queued {other_label}.")
                    else:
                        st.warning("Could not add entity to pivot queue.")
                    st.rerun()


def _render_observations_section(observations: list[dict]) -> None:
    st.subheader("Observations")
    if not observations:
        st.info("No observations linked to this entity.")
        return
    for observation in observations:
        title = observation.get("title") or "Observation"
        with st.expander(f"{title} · `{observation.get('module_id', '-')}`", expanded=False):
            st.markdown(f"**Type:** {observation.get('observation_type', '-')}")
            st.markdown(f"**Created:** {observation.get('created_at', '-')}")
            if observation.get("summary"):
                st.write(observation.get("summary"))
            if observation.get("data_json"):
                with st.expander("Structured data", expanded=False):
                    try:
                        st.json(json.loads(observation["data_json"]))
                    except json.JSONDecodeError:
                        st.code(observation["data_json"])
            if observation.get("raw_output"):
                with st.expander("Raw output", expanded=False):
                    st.code(observation["raw_output"])


def _render_findings_section(
    case_id: int,
    findings: list[dict],
    entity: dict,
    *,
    entity_lookup: dict,
    entity_values: dict[int, str],
) -> None:
    st.subheader("Findings")
    if not findings:
        st.info("No findings linked to this entity.")
        return
    for finding in findings:
        title = finding.get("title") or "Finding"
        severity = finding.get("severity") or "info"
        with st.expander(f"[{severity}] {title}", expanded=False):
            render_finding_detail(
                finding,
                entity_lookup,
                evidence_items=None,
                entity_values=entity_values,
            )


def _render_evidence_section(case_id: int, entity_id: int) -> None:
    st.subheader("Evidence artefacts")
    conn = get_db_conn()
    try:
        items = list_evidence_items(case_id=case_id, entity_id=entity_id, conn=conn)
    finally:
        conn.close()
    if not items:
        st.info("No evidence artefacts linked to this entity.")
        return
    for item in items[:20]:
        header = item.get("title") or "Evidence item"
        module = item.get("module_id") or "unknown"
        with st.expander(f"{header} · {module}", expanded=False):
            render_evidence_item_detail(item)


def _render_network_section(
    case_id: int,
    entity: dict,
    outgoing: list[dict],
    incoming: list[dict],
    entity_lookup: dict,
) -> None:
    st.subheader("Network context")
    graph_col1, graph_col2 = st.columns([1, 2])
    with graph_col1:
        if st.button("Open in Graph", key=f"entity_open_graph_{entity['id']}", width="stretch"):
            st.session_state.graph_focus_entity = int(entity["id"])
            st.session_state.nav_page = "Graph"
            st.rerun()
    with graph_col2:
        st.caption("View neighbours and pivot from the case relationship graph.")
    st.divider()
    st.markdown("**Relationships from this entity**")
    _render_relationship_rows(case_id, outgoing, entity_lookup, direction="from")
    st.markdown("**Relationships to this entity**")
    _render_relationship_rows(case_id, incoming, entity_lookup, direction="to")


def _run_modules_for_entities(
    case_id: int,
    entities_to_run: list[dict],
    module_ids: list[str],
    *,
    operating_context: str,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
) -> None:
    if not module_ids:
        st.warning("Select at least one module.")
        return

    nmap_options = st.session_state.get("nmap_options") or default_options_for_profile(PROFILE_STANDARD)
    run_mode_label = "Entity Workspace pivot"
    run_results: list[dict] = []
    last_target = ""

    with st.status("Running modules from Entity Workspace...", expanded=True) as status:
        conn = get_db_conn()
        try:
            for entity in entities_to_run:
                pivot = build_pivot_recommendations(entity)
                target_value = pivot["execution_target"]
                if not target_value.strip():
                    continue
                target_type = pivot["target_type"]
                selected = []
                for module_id in module_ids:
                    module = get_module(module_id)
                    if module is None or not is_executable(module):
                        continue
                    if get_incompatible_reason(module, target_type):
                        continue
                    selected.append(module_id)
                if not selected:
                    continue

                entity_row = create_or_get_entity(
                    case_id,
                    infer_entity_type(target_value),
                    target_value,
                    label=entity.get("label") or target_value,
                    source="entity_workspace",
                    conn=conn,
                )
                for module_id in selected:
                    module = get_module(module_id)
                    if module is None:
                        continue
                    auth_ok = True
                    if module.requires_authorisation:
                        if operating_context == PASSIVE_RESEARCH:
                            auth_ok = False
                        elif operating_context == PERSONAL_LAB:
                            auth_ok = personal_lab_confirmed
                        elif operating_context == CLIENT_ENGAGEMENT:
                            auth_ok = authorisation_confirmed
                        else:
                            auth_ok = authorisation_confirmed
                    if not auth_ok:
                        continue
                    options: dict = {
                        "operating_context": operating_context,
                        "personal_lab_confirmed": personal_lab_confirmed,
                    }
                    if module_id == "infra_nmap":
                        options["nmap_options"] = nmap_options
                    result = execute_module(
                        module_id,
                        target_value,
                        options=options,
                        db_context=conn,
                        authorisation_confirmed=authorisation_confirmed or personal_lab_confirmed,
                        case_id=case_id,
                        entity_id=entity_row["id"],
                        run_mode_id="custom",
                        run_mode_label=run_mode_label,
                    )
                    run_results.append(result)
                    last_target = target_value
        finally:
            conn.close()
        status.update(label="Entity Workspace run complete", state="complete")

    if run_results:
        st.session_state.latest_run_results = run_results
        st.session_state.latest_run_target = last_target
        st.rerun()
    else:
        st.warning("No modules were run. Check compatibility and authorisation.")


def _render_pivot_queue(case_id: int, entity_by_id: dict[int, dict]) -> None:
    _migrate_session_pivot_queue(case_id)

    conn = get_db_conn()
    try:
        queue_rows = list_pivot_queue(case_id, conn=conn)
    finally:
        conn.close()

    st.subheader("Pivot queue")
    st.caption("Persisted per case in the local database.")

    if not queue_rows:
        st.info("Queue is empty. Add entities from Details, relationships, findings, or the Graph page.")
    else:
        for row in queue_rows:
            entity_id = row["entity_id"]
            queued = entity_by_id.get(entity_id)
            if queued is None:
                st.caption(f"Queued entity #{entity_id} is missing from this case.")
                continue
            row_col1, row_col2, row_col3 = st.columns([4, 1, 1])
            with row_col1:
                st.markdown(_entity_option_label(queued))
            with row_col2:
                if st.button("Open", key=f"pivot_open_{entity_id}", width="stretch"):
                    open_entity_in_workspace(entity_id)
                    st.rerun()
            with row_col3:
                if st.button("Remove", key=f"pivot_remove_{entity_id}", width="stretch"):
                    conn = get_db_conn()
                    try:
                        remove_from_pivot_queue(case_id, entity_id, conn=conn)
                    finally:
                        conn.close()
                    st.rerun()

        if st.button("Clear pivot queue", key="pivot_clear_all"):
            conn = get_db_conn()
            try:
                clear_pivot_queue(case_id, conn=conn)
            finally:
                conn.close()
            st.rerun()

        queued_entities = [entity_by_id[row["entity_id"]] for row in queue_rows if row["entity_id"] in entity_by_id]
        if queued_entities:
            st.markdown("**Send to Batch Queue**")
            batch_col1, batch_col2 = st.columns(2)
            with batch_col1:
                if st.button(
                    "Add passive modules for queued entities",
                    key="pivot_send_passive_batch_queue",
                    width="stretch",
                ):
                    from ui.batch_queue_page import import_pivot_queue_entities

                    added, skipped = import_pivot_queue_entities(case_id, entity_by_id)
                    if added:
                        st.success(f"Added {added} item(s) to Batch Queue.")
                    else:
                        st.info("No new passive items added.")
                    st.rerun()
            with batch_col2:
                if st.button("Open Batch Queue", key="pivot_open_batch_queue", width="stretch"):
                    from ui.batch_queue_page import navigate_to_batch_queue

                    navigate_to_batch_queue()
                    st.rerun()


def _render_pivot_actions(
    case_id: int,
    entity: dict,
    pivot: dict,
    *,
    case_name: str,
) -> None:
    st.subheader("Suggested next actions")
    for suggestion in pivot.get("suggestions") or []:
        st.info(suggestion)

    module_rows = pivot.get("module_rows") or []
    if not module_rows:
        return

    st.markdown("**Compatible modules**")
    compatible_ids = [row["module_id"] for row in module_rows if row.get("compatible")]
    selected_ids = st.multiselect(
        "Modules to run",
        options=compatible_ids,
        default=compatible_ids[:],
        format_func=lambda mid: MODULE_CARD_TITLES.get(mid, mid),
        key=f"entity_pivot_modules_{entity['id']}",
    )

    for row in module_rows:
        if not row.get("compatible"):
            st.caption(f"✗ {row['display_name']}: {row.get('incompatible_reason')}")

    auth_required = any(
        get_module(module_id).requires_authorisation
        for module_id in selected_ids
        if get_module(module_id) is not None
    )

    st.session_state.setdefault("operating_context", PASSIVE_RESEARCH)
    linked_engagement = get_engagement_for_case(case_id)
    context_choices = [mode_id for mode_id, _ in list_operating_contexts()]
    if not linked_engagement:
        context_choices = [mode for mode in context_choices if mode != CLIENT_ENGAGEMENT]
    operating_context = st.session_state.get("operating_context", PASSIVE_RESEARCH)
    if operating_context not in context_choices:
        operating_context = PASSIVE_RESEARCH

    with st.container(border=True):
        st.markdown("**Readiness**")
        operating_context = st.radio(
            "Operating context",
            options=context_choices,
            index=context_choices.index(operating_context),
            format_func=operating_context_label,
            key=f"entity_operating_context_{entity['id']}",
            horizontal=True,
        )
        st.session_state.operating_context = operating_context
        render_mode_explainer(operating_context)

        personal_lab_confirmed = st.session_state.get("personal_lab_confirmed", False)
        authorisation_confirmed = st.session_state.get("authorisation_confirmed", False)
        if auth_required and operating_context == PERSONAL_LAB:
            personal_lab_confirmed = st.checkbox(
                PERSONAL_LAB_CONFIRMATION_TEXT,
                value=personal_lab_confirmed,
                key=f"entity_personal_lab_{entity['id']}",
            )
            st.session_state.personal_lab_confirmed = personal_lab_confirmed
        elif auth_required and operating_context == CLIENT_ENGAGEMENT:
            authorisation_confirmed = st.checkbox(
                "I confirm authorisation under the linked client engagement.",
                value=authorisation_confirmed,
                key=f"entity_client_auth_{entity['id']}",
            )
            st.session_state.authorisation_confirmed = authorisation_confirmed

        passive_count = sum(
            1
            for module_id in selected_ids
            if (module := get_module(module_id)) and module.mode == "passive"
        )
        active_count = len(selected_ids) - passive_count

        plan_conn = get_db_conn()
        try:
            plan = enrich_operation_plan_with_preflight(
                build_operation_plan(
                    case_name=case_name,
                    case_id=case_id,
                    target=pivot["execution_target"],
                    selected_module_ids=selected_ids,
                    authorisation_confirmed=(
                        personal_lab_confirmed
                        if operating_context == PERSONAL_LAB
                        else authorisation_confirmed
                    )
                    if auth_required
                    else True,
                    run_mode_id="custom",
                    run_mode_label="Entity Workspace pivot",
                    recommendation_reason="Pivot from Entity Workspace",
                ),
                target=pivot["execution_target"],
                case_id=case_id,
                selected_module_ids=selected_ids,
                operating_context=operating_context,
                personal_lab_confirmed=personal_lab_confirmed,
                authorisation_confirmed=authorisation_confirmed,
                nmap_options=st.session_state.get("nmap_options", {}),
                conn=plan_conn,
            )
        finally:
            plan_conn.close()

        preflight_status = render_compact_preflight(
            operating_context=operating_context,
            module_preflights=plan.get("module_preflights") or [],
            selected_module_ids=selected_ids,
            passive_count=passive_count,
            active_count=active_count,
        )

    if plan.get("incompatible_modules"):
        for line in plan["incompatible_modules"]:
            st.warning(line)

    launch_blocked = None
    if not selected_ids:
        launch_blocked = "Select at least one compatible module."
    elif plan.get("incompatible_modules"):
        launch_blocked = "Remove incompatible modules from the selection."
    elif auth_required and operating_context == PASSIVE_RESEARCH:
        launch_blocked = "Select Personal Lab or Client Engagement for active checks."
    elif auth_required and operating_context == PERSONAL_LAB and not personal_lab_confirmed:
        launch_blocked = "Confirm Personal Lab authorisation."
    elif auth_required and operating_context == CLIENT_ENGAGEMENT and not authorisation_confirmed:
        launch_blocked = "Confirm client engagement authorisation."
    elif plan.get("engagement_blocked_modules") and operating_context != PERSONAL_LAB:
        launch_blocked = "Resolve preflight items before running."
    elif preflight_status.get("has_active") and not preflight_status.get("ready"):
        launch_blocked = "Complete active check preflight before running."

    if st.button(
        "Run compatible modules",
        type="primary",
        key=f"entity_pivot_run_{entity['id']}",
        disabled=launch_blocked is not None,
        width="stretch",
    ):
        _run_modules_for_entities(
            case_id,
            [entity],
            selected_ids,
            operating_context=operating_context,
            personal_lab_confirmed=personal_lab_confirmed,
            authorisation_confirmed=authorisation_confirmed,
        )
    if launch_blocked:
        st.caption(launch_blocked)

    st.divider()
    st.markdown("**Batch Queue**")
    batch_col1, batch_col2 = st.columns(2)
    with batch_col1:
        if st.button(
            "Add compatible passive modules to Batch Queue",
            key=f"entity_batch_queue_add_{entity['id']}",
            width="stretch",
        ):
            from ui.batch_queue_page import add_entity_passive_modules_to_batch_queue

            added, skipped = add_entity_passive_modules_to_batch_queue(case_id, entity)
            if added:
                st.success(f"Added {added} passive module(s) to Batch Queue.")
            elif skipped:
                st.info("Nothing new added. " + "; ".join(skipped[:3]))
            else:
                st.info("No compatible passive modules for this entity.")
            st.rerun()
    with batch_col2:
        if st.button(
            "Open Batch Queue",
            key=f"entity_open_batch_queue_{entity['id']}",
            width="stretch",
        ):
            from ui.batch_queue_page import navigate_to_batch_queue

            navigate_to_batch_queue()
            st.rerun()


def render_entity_workspace_page(case_id: int, metrics: dict, *, case_name: str = "") -> None:
    st.title("Entity Workspace")
    render_compact_metrics(metrics)
    st.caption(
        "Entity-centric investigation shell — review findings, evidence, and network context, "
        "then launch compatible follow-up modules."
    )
    st.divider()

    _migrate_session_pivot_queue(case_id)

    conn = get_db_conn()
    try:
        entities = list_entities(case_id=case_id, conn=conn)
        if not entities:
            st.info(
                "No entities in this case yet. Run modules from **Assessment Workspace** to populate entities."
            )
            return

        entity_by_id = {entity["id"]: entity for entity in entities}
        entity_lookup = _entity_lookup(entities)
        entities_by_value = _entities_by_value(entities)

        entity_values = {
            row["id"]: row.get("value") or row.get("label") or str(row["id"])
            for row in entities
        }

        if ENTITY_WORKSPACE_SELECTED_KEY in st.session_state:
            preselected = st.session_state.pop(ENTITY_WORKSPACE_SELECTED_KEY)
            if preselected in entity_by_id:
                st.session_state["entity_workspace_select"] = preselected

        entity_ids = [entity["id"] for entity in entities]
        default_index = 0
        if st.session_state.get("entity_workspace_select") in entity_ids:
            default_index = entity_ids.index(st.session_state["entity_workspace_select"])

        selected_id = st.selectbox(
            "Select entity",
            options=entity_ids,
            index=default_index,
            format_func=lambda eid: _entity_option_label(entity_by_id[eid]),
            key="entity_workspace_select",
        )
        entity = entity_by_id[selected_id]

        queue_col1, queue_col2, queue_col3 = st.columns([1, 1, 2])
        with queue_col1:
            already_queued = pivot_queue_contains(case_id, selected_id, conn=conn)
            if st.button(
                "Add to pivot queue",
                key="entity_add_pivot_queue",
                disabled=already_queued,
                width="stretch",
            ):
                if add_to_pivot_queue(case_id, selected_id, conn=conn):
                    st.success("Added to pivot queue.")
                    st.rerun()
        with queue_col2:
            if st.button(
                "Passive → Batch Queue",
                key="entity_passive_batch_queue",
                width="stretch",
            ):
                from ui.batch_queue_page import add_entity_passive_modules_to_batch_queue

                added, skipped = add_entity_passive_modules_to_batch_queue(case_id, entity)
                if added:
                    st.success(f"Added {added} passive module(s) to Batch Queue.")
                else:
                    st.info("No new passive items added.")
                st.rerun()
        with queue_col3:
            if already_queued:
                st.caption("This entity is in the pivot queue.")
            if st.button("Open Batch Queue", key="entity_header_batch_queue"):
                from ui.batch_queue_page import navigate_to_batch_queue

                navigate_to_batch_queue()
                st.rerun()

        pivot = build_pivot_recommendations(entity, entities_by_value=entities_by_value)
        findings = list_findings(case_id=case_id, entity_id=selected_id, conn=conn)
        observations = list_observations(case_id=case_id, entity_id=selected_id, conn=conn)
        relationships = list_relationships(case_id=case_id, conn=conn)
        operations = list_operations(case_id=case_id, conn=conn)
        outgoing, incoming = split_relationships_for_entity(selected_id, relationships)
        related_operations = filter_operations_for_entity(operations, entity)
    finally:
        conn.close()

    overview_tab, findings_tab, evidence_tab, network_tab, pivot_tab, queue_tab = st.tabs(
        ["Overview", "Findings", "Evidence", "Network", "Pivot", "Queue"]
    )

    with overview_tab:
        _render_entity_details(entity)
        _render_entity_edit_form(entity)
        st.divider()
        st.subheader("Observations")
        _render_observations_section(observations)
        st.divider()
        st.subheader("Operations")
        if related_operations:
            st.dataframe(pd.DataFrame(related_operations), width="stretch", hide_index=True)
        else:
            st.caption("No operations recorded for this entity value.")

    with findings_tab:
        _render_findings_section(
            case_id,
            findings,
            entity,
            entity_lookup=entity_lookup,
            entity_values=entity_values,
        )

    with evidence_tab:
        _render_evidence_section(case_id, selected_id)
        st.divider()
        st.subheader("Module observations")
        _render_observations_section(observations)

    with network_tab:
        _render_network_section(case_id, entity, outgoing, incoming, entity_lookup)

    with pivot_tab:
        st.markdown(
            f"**Execution target:** `{pivot['execution_target']}` · "
            f"**Detected type:** {pivot['target_type_label']}"
        )
        if pivot.get("normalized_target") and pivot["normalized_target"] != pivot["execution_target"]:
            st.caption(f"Normalised host: `{pivot['normalized_target']}`")
        _render_pivot_actions(case_id, entity, pivot, case_name=case_name)

    with queue_tab:
        _render_pivot_queue(case_id, entity_by_id)

    latest_results = st.session_state.get("latest_run_results") or []
    latest_target = st.session_state.get("latest_run_target", pivot["execution_target"])
    if latest_results:
        st.divider()
        from ui.concise_results import render_workspace_results

        render_workspace_results(latest_results, target=latest_target, case_id=case_id)

import sqlite3

import pandas as pd
import streamlit as st

from database.db_setup import (
    create_case,
    create_or_get_entity,
    get_or_create_default_case,
    get_db_conn,
    infer_entity_type,
    list_cases,
    list_entities,
    list_observations,
    list_operations,
    list_relationships,
)
from modules.executor import execute_module, get_runtime_error, is_runtime_ready
from modules.module_registry import (
    CATEGORIES,
    get_module,
    get_modules_by_category,
    is_executable,
    module_ui_label,
)
from utils.graph_view import entity_graph_figure
from utils.nmap_options import SCRIPT_VULN
from utils.nmap_ui import render_nmap_options

if "case_id" not in st.session_state:
    st.session_state.case_id = get_or_create_default_case()["id"]

modules_by_category = get_modules_by_category()
selected_modules: dict[str, bool] = {}
nmap_options: dict = {}
authorisation_confirmed = False

nmap_runtime_ready = is_runtime_ready("infra_nmap")
nmap_module_error = get_runtime_error("infra_nmap")


def module_selectable(module) -> bool:
    """A module can be selected in the UI only if it is executable and runtime-ready."""
    if not is_executable(module):
        return False
    if module.module_id == "infra_nmap":
        return nmap_runtime_ready
    return True


def selected_module_ids() -> list[str]:
    return [module_id for module_id, enabled in selected_modules.items() if enabled]


def selection_requires_authorisation(module_ids: list[str]) -> bool:
    return any(
        (module := get_module(module_id)) is not None and module.requires_authorisation
        for module_id in module_ids
    )


def get_current_case() -> dict:
    cases = list_cases()
    for case in cases:
        if case["id"] == st.session_state.case_id:
            return case
    default_case = get_or_create_default_case()
    st.session_state.case_id = default_case["id"]
    return default_case


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
            }
        )

    return display_rows


def render_execution_result(result: dict) -> None:
    """Display a structured executor result in the main panel."""
    module = get_module(result["module_id"])
    display_name = module.display_name if module else result["module_id"]

    if result["status"] == "blocked":
        st.warning(f"**{display_name}:** {result['summary']}")
        for error in result["errors"]:
            st.caption(error)
        return

    if result["status"] == "error" or not result["success"]:
        st.error(f"**{display_name}:** {result['summary']}")
        if result["raw_output"]:
            with st.expander("Raw Nmap output", expanded=False):
                st.code(result["raw_output"], language="bash")
        return

    st.write(f"🛰️ **{display_name}:** {result['summary']}")

    interpreter_findings = result.get("interpreter_findings") or []
    if interpreter_findings:
        st.write("### Analyst Interpretation")
        st.caption("Advisory defensive analysis only. This is not a definitive vulnerability assessment.")
        for finding in interpreter_findings:
            severity = finding.get("severity", "info").upper()
            st.markdown(f"**[{severity}] {finding.get('title', 'Finding')}** · confidence {finding.get('confidence', 0)}")
            st.write(finding.get("explanation", ""))
            actions = finding.get("suggested_actions") or []
            if actions:
                for action in actions:
                    st.markdown(f"- {action}")

    if result.get("findings"):
        st.error(f"🚨 {len(result['findings'])} keyword matches in raw output")
        for finding in result["findings"]:
            st.warning(f"**Match:** {finding}")

    if result.get("raw_output"):
        with st.expander("Raw Nmap output", expanded=False):
            st.code(result["raw_output"], language="bash")

    if result.get("parsed_data") or result.get("selected_options"):
        with st.expander("Structured scan data", expanded=False):
            st.json(
                {
                    "selected_options": result.get("selected_options"),
                    "parsed_data": result.get("parsed_data"),
                }
            )


current_case = get_current_case()

# --- Sidebar ---
with st.sidebar:
    st.title("🛡️ Arsenal Control")

    st.subheader("Case")
    cases = list_cases()
    case_labels = {f"{case['name']} (#{case['id']})": case["id"] for case in cases}
    selected_case_label = st.selectbox(
        "Active case",
        options=list(case_labels.keys()),
        index=list(case_labels.values()).index(st.session_state.case_id)
        if st.session_state.case_id in case_labels.values()
        else 0,
        label_visibility="collapsed",
    )
    st.session_state.case_id = case_labels[selected_case_label]

    with st.expander("Create new case", expanded=False):
        new_case_name = st.text_input("Case name", placeholder="e.g. Acme Corp assessment")
        new_case_description = st.text_area("Description", placeholder="Optional notes")
        if st.button("Create case", width="stretch"):
            if not new_case_name.strip():
                st.warning("Enter a case name.")
            else:
                created = create_case(new_case_name.strip(), new_case_description.strip() or None)
                st.session_state.case_id = created["id"]
                st.success(f"Case '{created['name']}' created.")
                st.rerun()

    nmap_entry = get_module("infra_nmap")
    if nmap_entry and is_executable(nmap_entry) and nmap_module_error:
        st.error("Nmap module unavailable")
        st.caption(nmap_module_error)

    target_ip = st.text_input("Target IP/Domain:", placeholder="e.g. 192.168.1.1")

    if st.button("Acquire Target", width="stretch"):
        if not target_ip.strip():
            st.warning("Enter a target value.")
        else:
            conn = get_db_conn()
            try:
                conn.execute("INSERT INTO targets (domain_or_ip) VALUES (?)", (target_ip.strip(),))
                conn.commit()
                entity = create_or_get_entity(
                    st.session_state.case_id,
                    infer_entity_type(target_ip),
                    target_ip.strip(),
                    label=target_ip.strip(),
                    source="manual_acquire",
                    conn=conn,
                )
                st.success(f"Target locked as {entity['entity_type']}: {entity['value']}")
            except sqlite3.IntegrityError:
                create_or_get_entity(
                    st.session_state.case_id,
                    infer_entity_type(target_ip),
                    target_ip.strip(),
                    label=target_ip.strip(),
                    source="manual_acquire",
                    conn=conn,
                )
                st.warning("Target exists in legacy archive; entity linked to current case.")
            finally:
                conn.close()

    st.divider()
    st.subheader("Select Modules")

    for category in CATEGORIES:
        category_key = str(category["key"])
        category_label = str(category["label"])
        default_expanded = bool(category.get("default_expanded", False))
        category_modules = modules_by_category.get(category_key, [])

        with st.expander(category_label, expanded=default_expanded):
            if not category_modules:
                st.caption("No modules registered.")
                continue

            for module in category_modules:
                selectable = module_selectable(module)
                default_checked = module.module_id == "infra_nmap" and selectable

                selected_modules[module.module_id] = st.checkbox(
                    module_ui_label(module),
                    value=default_checked,
                    disabled=not selectable,
                    help=module.description,
                )

                if not selectable and not is_executable(module):
                    st.caption(f"{module.mode.title()} · {module.risk_level.title()} risk · planned")

                if module.module_id == "infra_nmap" and selectable:
                    nmap_options = render_nmap_options(selectable)

    selected_ids = selected_module_ids()
    auth_required = selection_requires_authorisation(selected_ids)

    if auth_required:
        st.divider()
        st.subheader("Authorisation")
        authorisation_confirmed = st.checkbox(
            "I confirm I am authorised to run active checks against this target.",
            value=False,
        )
        st.caption(
            "Required for active modules such as Nmap. "
            "Use only on systems you own, lab environments, or targets with written permission."
        )

    if nmap_options.get("script_category") == SCRIPT_VULN and selected_modules.get("infra_nmap"):
        st.warning(
            "**High-risk option selected:** `--script=vuln` runs intrusive vulnerability checks. "
            "Use only on systems you own or have explicit written permission to test. "
            "This option will not run without the authorisation confirmation above."
        )

    st.divider()
    execute_btn = st.button("LAUNCH OPERATION", type="primary", width="stretch")

# --- Main Dashboard ---
st.title("Project Overwatch")
st.caption(
    f"Intelligence Command Centre · Case: **{current_case['name']}** (#{current_case['id']}) · "
    f"Status: {current_case['status']}"
)

conn = get_db_conn()
t_count = conn.execute("SELECT count(*) FROM targets").fetchone()[0]
s_count = conn.execute("SELECT count(*) FROM recon_data").fetchone()[0]
entity_count = conn.execute(
    "SELECT count(*) FROM entities WHERE case_id = ?",
    (st.session_state.case_id,),
).fetchone()[0]
observation_count = conn.execute(
    "SELECT count(*) FROM observations WHERE case_id = ?",
    (st.session_state.case_id,),
).fetchone()[0]
relationship_count = conn.execute(
    "SELECT count(*) FROM relationships WHERE case_id = ?",
    (st.session_state.case_id,),
).fetchone()[0]
conn.close()

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Legacy Targets", t_count)
m2.metric("Case Entities", entity_count)
m3.metric("Relationships", relationship_count)
m4.metric("Observations", observation_count)
m5.metric("Legacy Logs", s_count)

st.divider()

if execute_btn:
    if not target_ip:
        st.error("No target specified.")
    else:
        selected_ids = selected_module_ids()

        with st.status("Executing Active Intelligence Stack...", expanded=True) as status:
            if not selected_ids:
                st.warning("No executable modules selected.")
            elif auth_required and not authorisation_confirmed:
                st.error(
                    "Authorisation confirmation is required before running the selected active modules."
                )
            else:
                conn = get_db_conn()
                try:
                    target_value = target_ip.strip()
                    entity = create_or_get_entity(
                        st.session_state.case_id,
                        infer_entity_type(target_value),
                        target_value,
                        label=target_value,
                        source="operation",
                        conn=conn,
                    )

                    for module_id in selected_ids:
                        module = get_module(module_id)
                        if module is None or not is_executable(module):
                            if module:
                                st.warning(f"{module.display_name} is planned and cannot be run yet.")
                            continue

                        options = {}
                        if module_id == "infra_nmap":
                            options = {"nmap_options": nmap_options}

                        result = execute_module(
                            module_id,
                            target_value,
                            options=options,
                            db_context=conn,
                            authorisation_confirmed=authorisation_confirmed,
                            case_id=st.session_state.case_id,
                            entity_id=entity["id"],
                        )
                        render_execution_result(result)
                finally:
                    conn.close()

            status.update(label="Operation Complete", state="complete")

# --- Archive ---
st.header("📂 Archive")
(
    tab_manifest,
    tab_history,
    tab_cases,
    tab_entities,
    tab_relationships,
    tab_observations,
    tab_operations,
    tab_graph,
) = st.tabs(
    [
        "Manifest",
        "History",
        "Cases",
        "Entities",
        "Relationships",
        "Observations",
        "Operations",
        "Graph",
    ]
)

with tab_manifest:
    conn = get_db_conn()
    st.dataframe(pd.read_sql_query("SELECT * FROM targets", conn), width="stretch")
    conn.close()

with tab_history:
    conn = get_db_conn()
    st.dataframe(pd.read_sql_query("SELECT * FROM recon_data", conn), width="stretch")
    conn.close()

with tab_cases:
    conn = get_db_conn()
    st.dataframe(pd.read_sql_query("SELECT * FROM cases", conn), width="stretch")
    conn.close()

with tab_entities:
    conn = get_db_conn()
    entities = list_entities(case_id=st.session_state.case_id, conn=conn)
    conn.close()
    st.caption(f"Showing entities for case #{st.session_state.case_id}.")
    st.dataframe(pd.DataFrame(entities), width="stretch")

with tab_relationships:
    conn = get_db_conn()
    entities = list_entities(case_id=st.session_state.case_id, conn=conn)
    relationships = list_relationships(case_id=st.session_state.case_id, conn=conn)
    conn.close()
    st.caption(f"Showing relationships for case #{st.session_state.case_id}.")
    if relationships:
        display_rows = enrich_relationships_for_display(relationships, entities)
        st.dataframe(pd.DataFrame(display_rows), width="stretch")
    else:
        st.info("No relationships recorded for this case yet. Run Nmap against a target to discover services.")

with tab_observations:
    conn = get_db_conn()
    observations = list_observations(case_id=st.session_state.case_id, conn=conn)
    conn.close()
    st.caption(f"Showing observations for case #{st.session_state.case_id}.")
    if observations:
        display_rows = []
        for observation in observations:
            row = observation.copy()
            if row.get("raw_output") and len(row["raw_output"]) > 200:
                row["raw_output"] = row["raw_output"][:200] + "..."
            display_rows.append(row)
        st.dataframe(pd.DataFrame(display_rows), width="stretch")
    else:
        st.info("No observations recorded for this case yet.")

with tab_operations:
    conn = get_db_conn()
    operations = list_operations(case_id=st.session_state.case_id, conn=conn)
    conn.close()
    st.caption(f"Showing operations for case #{st.session_state.case_id}.")
    st.dataframe(pd.DataFrame(operations), width="stretch")

with tab_graph:
    conn = get_db_conn()
    entities = list_entities(case_id=st.session_state.case_id, conn=conn)
    relationships = list_relationships(case_id=st.session_state.case_id, conn=conn)
    conn.close()
    st.caption(
        "Graph built from stored entities and relationships for the active case. "
        "This view does not perform new scanning."
    )
    figure = entity_graph_figure(entities, relationships)
    if figure is None:
        st.info("No graph data yet. Run Nmap against an authorised target to populate entities and relationships.")
    else:
        st.plotly_chart(figure, width="stretch")

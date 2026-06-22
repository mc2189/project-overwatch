import json
import re
import sqlite3

import pandas as pd
import streamlit as st

from database.db_setup import (
    FINDING_STATUSES,
    TERMINAL_FINDING_STATUSES,
    create_case,
    create_or_get_entity,
    effective_finding_severity,
    finding_status_counts,
    get_case,
    get_or_create_default_case,
    get_db_conn,
    infer_entity_type,
    list_cases,
    list_entities,
    list_findings,
    list_observations,
    list_operations,
    list_relationships,
    normalize_finding_status,
    reopen_finding,
    update_finding,
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
from utils.report_builder import ReportOptions, build_case_report, save_report_markdown
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
from utils.nmap_options import SCRIPT_VULN
from utils.nmap_ui import render_nmap_options, render_privilege_status
from utils.case_backup import export_case_bundle_json, import_case_bundle, parse_case_bundle_json
from utils.local_auth import local_auth_enabled, render_local_auth_gate
from utils.module_compatibility import (
    build_operation_plan,
    get_module_disable_reason,
    module_detailed_help,
    module_is_selectable,
    module_short_help,
)
from utils.runtime_health import collect_health_checks
from utils.target_detection import get_target_type, target_type_label
from version import PROJECT_VERSION

if "case_id" not in st.session_state:
    st.session_state.case_id = get_or_create_default_case()["id"]

render_local_auth_gate()

if "startup_tasks_done" not in st.session_state:
    _scheduled_paths, scheduled_message = maybe_run_scheduled_exports()
    if scheduled_message:
        st.session_state.startup_notice = scheduled_message
    st.session_state.startup_tasks_done = True

modules_by_category = get_modules_by_category()
selected_modules: dict[str, bool] = {}
nmap_options: dict = {}
authorisation_confirmed = False

nmap_runtime_ready = is_runtime_ready("infra_nmap")
nmap_module_error = get_runtime_error("infra_nmap")
domain_intel_ready = is_runtime_ready("infra_domain_intel")
domain_intel_error = get_runtime_error("infra_domain_intel")
cert_subdomain_ready = is_runtime_ready("infra_cert_subdomain")
cert_subdomain_error = get_runtime_error("infra_cert_subdomain")


def module_runtime_ready(module_id: str) -> bool:
    if module_id == "infra_nmap":
        return nmap_runtime_ready
    if module_id == "infra_domain_intel":
        return domain_intel_ready
    if module_id == "infra_cert_subdomain":
        return cert_subdomain_ready
    return False


def module_runtime_error(module_id: str) -> str | None:
    if module_id == "infra_nmap":
        return nmap_module_error
    if module_id == "infra_domain_intel":
        return domain_intel_error
    if module_id == "infra_cert_subdomain":
        return cert_subdomain_error
    return None


def module_selectable(module, target: str) -> bool:
    """A module can be selected when executable, runtime-ready, and target-compatible."""
    return module_is_selectable(
        module,
        target,
        runtime_ready=module_runtime_ready(module.module_id),
    )


def default_module_checked(module, target: str) -> bool:
    """Default sidebar selection for compatible implemented modules."""
    if module.module_id == "infra_nmap":
        return module_selectable(module, target)
    return False


def selected_module_ids() -> list[str]:
    return [module_id for module_id, enabled in selected_modules.items() if enabled]


def selection_requires_authorisation(module_ids: list[str]) -> bool:
    return any(
        (module := get_module(module_id)) is not None and module.requires_authorisation
        for module_id in module_ids
    )

FINDING_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
FINDING_SEVERITY_OPTIONS = ("",) + FINDING_SEVERITY_ORDER
FINDING_STATUS_LABELS = {
    "open": "Open",
    "in_review": "In review",
    "action_required": "Action required",
    "accepted": "Accepted",
    "false_positive": "False positive",
    "closed": "Closed",
}


def finding_status_label(status: str | None) -> str:
    return FINDING_STATUS_LABELS.get(normalize_finding_status(status), "Open")


def save_finding_update(
    finding_id: int,
    *,
    status: str | None = None,
    analyst_notes: str | None = None,
    user_severity: str | None = None,
) -> None:
    conn = get_db_conn()
    try:
        update_finding(
            finding_id,
            status=status,
            analyst_notes=analyst_notes,
            user_severity=user_severity,
            conn=conn,
        )
    finally:
        conn.close()


def render_finding_review_controls(finding: dict) -> None:
    """Render triage controls for a single finding."""
    finding_id = finding["id"]
    current_status = normalize_finding_status(finding.get("status"))
    is_terminal = current_status in TERMINAL_FINDING_STATUSES

    st.markdown(f"**Status:** {finding_status_label(current_status)}")

    with st.form(key=f"finding_review_{finding_id}"):
        status_index = FINDING_STATUSES.index(current_status) if current_status in FINDING_STATUSES else 0
        new_status = st.selectbox(
            "Update status",
            FINDING_STATUSES,
            index=status_index,
            format_func=lambda value: FINDING_STATUS_LABELS.get(value, value),
        )
        analyst_notes = st.text_area(
            "Analyst notes",
            value=finding.get("analyst_notes") or "",
            help="Document review decisions, context, or follow-up.",
        )
        current_override = finding.get("user_severity") or ""
        override_index = (
            FINDING_SEVERITY_OPTIONS.index(current_override)
            if current_override in FINDING_SEVERITY_OPTIONS
            else 0
        )
        user_severity = st.selectbox(
            "Severity override",
            FINDING_SEVERITY_OPTIONS,
            index=override_index,
            format_func=lambda value: "(module default)" if not value else value,
            help="Optional analyst override. Leave as module default to use module severity.",
        )
        button_col1, button_col2 = st.columns(2)
        with button_col1:
            save_clicked = st.form_submit_button("Save update", width="stretch")
        with button_col2:
            close_clicked = (
                st.form_submit_button("Close finding", width="stretch") if not is_terminal else False
            )

    if save_clicked:
        save_finding_update(
            finding_id,
            status=new_status,
            analyst_notes=analyst_notes,
            user_severity=user_severity or None,
        )
        st.rerun()
    if close_clicked:
        save_finding_update(
            finding_id,
            status="closed",
            analyst_notes=analyst_notes,
            user_severity=user_severity or None,
        )
        st.rerun()

    if is_terminal:
        if st.button("Reopen finding", key=f"finding_reopen_{finding_id}", width="stretch"):
            conn = get_db_conn()
            try:
                reopen_finding(finding_id, conn=conn)
            finally:
                conn.close()
            st.rerun()


def render_finding_detail(finding: dict, entity_lookup: dict) -> None:
    """Render read-only finding detail inside an expander."""
    entity_label = entity_lookup.get(finding.get("entity_id"), finding.get("entity_id") or "-")
    module_severity = finding.get("severity", "info")
    effective_severity = effective_finding_severity(finding)

    st.markdown(f"**Title:** {finding.get('title', 'Finding')}")
    st.markdown(f"**Module:** `{finding.get('module_id', '-')}`")
    st.markdown(f"**Entity:** {entity_label}")
    st.markdown(f"**Module severity:** {module_severity}")
    if finding.get("user_severity"):
        st.markdown(f"**Analyst severity override:** {finding.get('user_severity')}")
    st.markdown(f"**Effective severity:** {effective_severity}")
    st.markdown(f"**Confidence:** {finding.get('confidence', 50)}")
    st.markdown(f"**Status:** {finding_status_label(finding.get('status'))}")

    st.markdown("**Explanation**")
    st.write(finding.get("explanation") or "_No explanation provided._")

    try:
        suggested_actions = json.loads(finding.get("suggested_actions_json") or "[]")
    except json.JSONDecodeError:
        suggested_actions = []
    if suggested_actions:
        st.markdown("**Suggested actions**")
        for action in suggested_actions:
            st.markdown(f"- {action}")

    if finding.get("analyst_notes"):
        st.markdown("**Analyst notes**")
        st.write(finding.get("analyst_notes"))

    timestamp_parts = []
    if finding.get("created_at"):
        timestamp_parts.append(f"Created: {finding.get('created_at')}")
    if finding.get("updated_at"):
        timestamp_parts.append(f"Updated: {finding.get('updated_at')}")
    if finding.get("reviewed_at"):
        timestamp_parts.append(f"Reviewed: {finding.get('reviewed_at')}")
    if finding.get("closed_at"):
        timestamp_parts.append(f"Closed: {finding.get('closed_at')}")
    if timestamp_parts:
        st.caption(" · ".join(timestamp_parts))

    render_finding_review_controls(finding)


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
            with st.expander("Raw output", expanded=False):
                st.code(result["raw_output"], language="text")
        return

    st.write(f"**{display_name}:** {result['summary']}")

    parsed_data = result.get("parsed_data") or {}
    if result["module_id"] == "infra_cert_subdomain" and parsed_data:
        st.write("### Certificate & Subdomain Intelligence Summary")
        subdomains = parsed_data.get("subdomains") or []
        st.write(f"**Subdomains discovered:** {len(subdomains)}")
        if subdomains:
            st.dataframe(
                pd.DataFrame({"subdomain": subdomains}),
                width="stretch",
                hide_index=True,
            )
        else:
            st.caption("No related public names were returned for this domain.")

        certificates = parsed_data.get("certificates") or []
        if certificates:
            st.markdown("**Certificate references (sample)**")
            cert_rows = []
            for cert in certificates[:15]:
                cert_rows.append(
                    {
                        "id": cert.get("id"),
                        "common_name": cert.get("common_name"),
                        "issuer": cert.get("issuer"),
                        "not_before": cert.get("not_before"),
                        "not_after": cert.get("not_after"),
                    }
                )
            st.dataframe(pd.DataFrame(cert_rows), width="stretch", hide_index=True)

        if parsed_data.get("source"):
            st.caption(f"Source: {parsed_data.get('source')}")
        if parsed_data.get("warning"):
            st.warning(parsed_data["warning"])
        if parsed_data.get("wildcard_observed"):
            st.caption("Wildcard certificate names were observed in the source data.")
        if parsed_data.get("truncated"):
            st.caption("Subdomain list was truncated for usability.")

    if result["module_id"] == "infra_domain_intel" and parsed_data:
        st.write("### Domain Intelligence Summary")
        dns_records = parsed_data.get("dns", {})
        if dns_records:
            st.markdown("**DNS records**")
            for record_type, values in dns_records.items():
                st.write(f"- {record_type}: {', '.join(values) if values else '(none)'}")

        security_headers = parsed_data.get("security_headers", {}).get("https", {})
        if security_headers:
            present = [name for name, meta in security_headers.items() if meta.get("present")]
            missing = [name for name, meta in security_headers.items() if not meta.get("present")]
            st.markdown("**HTTPS security headers**")
            st.write(f"Present: {', '.join(present) if present else '(none)'}")
            st.write(f"Missing: {', '.join(missing) if missing else '(none)'}")

        tls = parsed_data.get("tls", {})
        if tls:
            st.markdown("**TLS certificate**")
            if tls.get("available"):
                st.write(
                    f"Issuer: {tls.get('issuer')} · Subject: {tls.get('subject')} · "
                    f"Valid: {tls.get('not_before')} -> {tls.get('not_after')}"
                )
            else:
                st.write(f"TLS unavailable: {tls.get('error') or 'unknown error'}")

        wayback = parsed_data.get("wayback", {})
        if wayback:
            st.markdown("**Wayback Machine**")
            if wayback.get("available"):
                st.write(
                    f"Snapshots available · first={wayback.get('first_snapshot')} · "
                    f"last={wayback.get('last_snapshot')}"
                )
            else:
                st.write("No snapshots found.")

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
        st.info(f"{len(result['findings'])} note(s) from module output")
        for finding in result["findings"]:
            st.write(f"- {finding}")

    if result.get("raw_output"):
        label = "Raw Nmap output" if result["module_id"] == "infra_nmap" else "Raw output"
        with st.expander(label, expanded=False):
            language = "bash" if result["module_id"] == "infra_nmap" else "text"
            st.code(result["raw_output"], language=language)

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
    st.title("Project Overwatch")
    st.caption(f"v{PROJECT_VERSION} · Local intelligence dashboard")
    if local_auth_enabled():
        st.caption("Local password protection enabled")
    render_privilege_status()

    with st.expander("System status", expanded=False):
        for check in collect_health_checks():
            icon = "✅" if check.ok else ("⚠️" if not check.required else "❌")
            st.write(f"{icon} **{check.name}** — {check.detail}")

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

    domain_intel_entry = get_module("infra_domain_intel")
    if domain_intel_entry and is_executable(domain_intel_entry) and domain_intel_error:
        st.error("Domain Intelligence module unavailable")
        st.caption(domain_intel_error)

    cert_subdomain_entry = get_module("infra_cert_subdomain")
    if cert_subdomain_entry and is_executable(cert_subdomain_entry) and cert_subdomain_error:
        st.error("Certificate & Subdomain Intelligence module unavailable")
        st.caption(cert_subdomain_error)

    target_ip = st.text_input(
        "Target",
        placeholder="e.g. 192.168.1.1, example.com, or https://example.com",
        help="IPv4 address, domain, URL, email, or username-like value.",
    )
    detected_target_type = get_target_type(target_ip or "")
    if target_ip.strip():
        st.caption(f"Detected target type: **{target_type_label(detected_target_type)}**")

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
    st.subheader("Modules")
    st.caption("**Active** modules send probes (authorisation required). **Passive** modules use public lookups only.")

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
                runtime_ready = module_runtime_ready(module.module_id)
                selectable = module_selectable(module, target_ip)
                enabled = is_executable(module) and selectable
                disable_reason = get_module_disable_reason(
                    module,
                    target_ip,
                    runtime_ready=runtime_ready,
                    runtime_error=module_runtime_error(module.module_id),
                )
                default_checked = default_module_checked(module, target_ip) and enabled

                selected_modules[module.module_id] = st.checkbox(
                    module_ui_label(module),
                    value=default_checked,
                    disabled=not enabled,
                    help=module_short_help(module),
                )

                if is_executable(module):
                    with st.expander(f"About {module.display_name}", expanded=False):
                        st.write(module_detailed_help(module))
                        if module.example_inputs:
                            st.markdown("**Example inputs:** " + ", ".join(f"`{item}`" for item in module.example_inputs))
                        if module.output_summary:
                            st.markdown(f"**Outputs:** {module.output_summary}")
                        if module.caution_notes:
                            st.markdown("**Notes:**")
                            for note in module.caution_notes:
                                st.markdown(f"- {note}")
                    if disable_reason and not selectable:
                        st.caption(disable_reason)
                elif not is_executable(module):
                    st.caption(
                        f"Planned · {module.mode.title()} · {module.risk_level.title()} risk — "
                        f"{module_short_help(module)}"
                    )

                if module.module_id == "infra_nmap" and enabled:
                    nmap_options = render_nmap_options(enabled)

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
    execute_btn = st.button("Run selected modules", type="primary", width="stretch")

# --- Main Dashboard ---
st.title("Investigation dashboard")
st.caption(
    f"Case: **{current_case['name']}** (#{current_case['id']}) · Status: {current_case['status']} · "
    f"v{PROJECT_VERSION}"
)

if st.session_state.get("startup_notice") and not st.session_state.get("startup_notice_dismissed"):
    st.info(st.session_state.startup_notice)
    if st.button("Dismiss", key="dismiss_startup_notice"):
        st.session_state.startup_notice_dismissed = True
        st.rerun()

conn = get_db_conn()
operation_count = conn.execute(
    "SELECT count(*) FROM operations WHERE case_id = ?",
    (st.session_state.case_id,),
).fetchone()[0]
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
finding_counts = finding_status_counts(st.session_state.case_id, conn=conn)
open_findings_count = finding_counts.get("open", 0)
in_review_count = finding_counts.get("in_review", 0)
action_required_count = finding_counts.get("action_required", 0)
closed_findings_count = finding_counts.get("closed", 0)
resolved_findings_count = (
    finding_counts.get("accepted", 0) + finding_counts.get("false_positive", 0)
)
conn.close()

m1, m2, m3, m4, m5 = st.columns(5)
m1.metric("Entities", entity_count)
m2.metric("Relationships", relationship_count)
m3.metric("Observations", observation_count)
m4.metric("Open findings", open_findings_count)
m5.metric("Operations", operation_count)

f1, f2, f3, f4, f5 = st.columns(5)
f1.metric("In review", in_review_count)
f2.metric("Action required", action_required_count)
f3.metric("Closed", closed_findings_count)
f4.metric("Accepted / false positive", resolved_findings_count)
f5.metric("Total findings", sum(finding_counts.values()))

st.divider()

operation_plan = build_operation_plan(
    case_name=current_case["name"],
    case_id=current_case["id"],
    target=target_ip or "",
    selected_module_ids=selected_module_ids(),
    authorisation_confirmed=authorisation_confirmed,
)

with st.expander("Operation Plan", expanded=True):
    if not operation_plan["target"]:
        st.info("Enter a target in the sidebar to see module compatibility and expected outputs.")
    elif not operation_plan["selected_modules"]:
        st.info("Select one or more modules in the sidebar to build an operation plan.")
    else:
        st.markdown(f"**Case:** {operation_plan['case_name']} (#{operation_plan['case_id']})")
        st.markdown(f"**Target:** `{operation_plan['target']}`")
        st.markdown(f"**Detected type:** {operation_plan['target_type_label']}")
        st.markdown("**Selected modules:** " + ", ".join(operation_plan["selected_modules"]))
        if operation_plan["active_modules"]:
            st.markdown("**Active modules:** " + ", ".join(operation_plan["active_modules"]))
        if operation_plan["passive_modules"]:
            st.markdown("**Passive modules:** " + ", ".join(operation_plan["passive_modules"]))
        if operation_plan["analysis_modules"]:
            st.markdown("**Analysis modules:** " + ", ".join(operation_plan["analysis_modules"]))
        st.markdown(
            "**Authorisation required:** "
            + ("Yes — confirm in the sidebar before launch." if operation_plan["authorisation_required"] else "No")
        )
        if operation_plan["expected_outputs"]:
            st.markdown("**Expected outputs:**")
            for line in operation_plan["expected_outputs"]:
                st.markdown(f"- {line}")
        if operation_plan["incompatible_modules"]:
            st.warning("Some selected modules are incompatible with this target:")
            for line in operation_plan["incompatible_modules"]:
                st.markdown(f"- {line}")
        elif operation_plan["authorisation_required"] and not operation_plan["authorisation_confirmed"]:
            st.warning("Authorisation confirmation is required before active modules can run.")
        elif operation_plan["ready_to_run"]:
            st.success("Ready to run. Use **Run selected modules** in the sidebar when you are ready.")

st.divider()

if execute_btn:
    if not target_ip:
        st.error("No target specified.")
    else:
        selected_ids = selected_module_ids()

        with st.status("Running selected modules...", expanded=True) as status:
            if not selected_ids:
                st.warning("No modules selected. Enable Nmap or Domain Intelligence in the sidebar.")
            elif auth_required and not authorisation_confirmed:
                st.error(
                    "Authorisation is required before running active modules such as Nmap."
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

            status.update(label="Module run complete", state="complete")

# --- Archive ---
st.header("📂 Archive")
(
    tab_cases,
    tab_entities,
    tab_relationships,
    tab_observations,
    tab_operations,
    tab_findings,
    tab_report,
    tab_graph,
    tab_legacy,
) = st.tabs(
    [
        "Cases",
        "Entities",
        "Relationships",
        "Observations",
        "Operations",
        "Findings",
        "Report",
        "Graph",
        "Legacy (v0.1)",
    ]
)

with tab_cases:
    conn = get_db_conn()
    st.dataframe(pd.read_sql_query("SELECT * FROM cases", conn), width="stretch")
    conn.close()
    st.caption("Case backup — export or import investigation data as JSON.")
    backup_col1, backup_col2 = st.columns(2)
    with backup_col1:
        bundle_json = export_case_bundle_json(st.session_state.case_id)
        st.download_button(
            "Download case backup (JSON)",
            data=bundle_json,
            file_name=f"case_{st.session_state.case_id}_backup.json",
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
        st.info("No relationships recorded for this case yet. Run Domain Intelligence or Nmap to populate relationships.")

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

with tab_findings:
    conn = get_db_conn()
    entities = list_entities(case_id=st.session_state.case_id, conn=conn)
    entity_lookup = {
        entity["id"]: entity.get("label") or entity.get("value", entity["id"])
        for entity in entities
    }
    findings = list_findings(case_id=st.session_state.case_id, conn=conn)
    conn.close()

    st.caption(
        f"Showing findings for case #{st.session_state.case_id}. "
        "Findings are analyst aids, not final proof of risk."
    )

    module_options = sorted({finding.get("module_id") for finding in findings if finding.get("module_id")})
    filter_col1, filter_col2, filter_col3 = st.columns(3)
    with filter_col1:
        severity_filter = st.selectbox(
            "Filter by severity",
            ["All", *FINDING_SEVERITY_ORDER],
            key="findings_severity_filter",
        )
    with filter_col2:
        status_filter = st.selectbox(
            "Filter by status",
            ["All", *FINDING_STATUSES],
            format_func=lambda value: "All" if value == "All" else FINDING_STATUS_LABELS.get(value, value),
            key="findings_status_filter",
        )
    with filter_col3:
        module_filter = st.selectbox(
            "Filter by module",
            ["All", *module_options],
            key="findings_module_filter",
        )

    filtered_findings = findings
    if severity_filter != "All":
        filtered_findings = [
            finding
            for finding in filtered_findings
            if effective_finding_severity(finding) == severity_filter
        ]
    if status_filter != "All":
        filtered_findings = [
            finding
            for finding in filtered_findings
            if normalize_finding_status(finding.get("status")) == status_filter
        ]
    if module_filter != "All":
        filtered_findings = [
            finding for finding in filtered_findings if finding.get("module_id") == module_filter
        ]

    if not filtered_findings:
        st.info("No findings match the current filters.")
    else:
        summary_rows = []
        for finding in filtered_findings:
            summary_rows.append(
                {
                    "id": finding["id"],
                    "severity": effective_finding_severity(finding),
                    "confidence": finding.get("confidence"),
                    "module": finding.get("module_id"),
                    "entity": entity_lookup.get(finding.get("entity_id"), finding.get("entity_id") or "-"),
                    "title": finding.get("title"),
                    "status": finding_status_label(finding.get("status")),
                    "created_at": finding.get("created_at"),
                }
            )
        st.dataframe(pd.DataFrame(summary_rows), width="stretch")

        findings_by_severity: dict[str, list[dict]] = {severity: [] for severity in FINDING_SEVERITY_ORDER}
        for finding in filtered_findings:
            severity = effective_finding_severity(finding).lower()
            if severity not in findings_by_severity:
                severity = "info"
            findings_by_severity[severity].append(finding)

        for severity in FINDING_SEVERITY_ORDER:
            severity_findings = findings_by_severity.get(severity, [])
            if not severity_findings:
                continue
            st.subheader(f"{severity.upper()} ({len(severity_findings)})")
            for finding in severity_findings:
                entity_label = entity_lookup.get(finding.get("entity_id"), finding.get("entity_id") or "-")
                status_text = finding_status_label(finding.get("status"))
                expander_label = (
                    f"[{effective_finding_severity(finding).upper()}] {finding.get('title', 'Finding')} · "
                    f"{finding.get('module_id')} · {entity_label} · {status_text}"
                )
                with st.expander(expander_label, expanded=False):
                    render_finding_detail(finding, entity_lookup)

with tab_report:
    st.caption(
        f"Generate a Markdown report for case #{st.session_state.case_id}. "
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
            st.success("Schedule settings saved. Exports run when this tab is opened.")

    report_col1, report_col2 = st.columns(2)
    with report_col1:
        report_template = st.selectbox(
            "Report template",
            options=["full", "executive"],
            format_func=lambda value: "Full technical" if value == "full" else "Executive summary",
            help="Executive omits detailed entities, relationships, and observations.",
        )
        include_closed_findings = st.checkbox(
            "Include closed / accepted / false positive findings",
            value=False,
            help="When unchecked, only active findings (open, in review, action required) are included.",
        )
        include_raw_appendix = st.checkbox(
            "Include raw output appendix",
            value=False,
            help="When enabled, observation raw output is appended in fenced code blocks.",
        )
    with report_col2:
        include_graph_appendix = st.checkbox(
            "Include entity graph snapshot",
            value=False,
            help="Embeds a PNG graph in the appendix when kaleido is available.",
        )
        redact_ips = st.checkbox("Redact IP addresses", value=False)
        redact_emails = st.checkbox("Redact email addresses", value=False)
        redact_domains = st.checkbox("Redact domain names", value=False)

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

    report_options = ReportOptions(
        include_closed_findings=include_closed_findings,
        include_raw_appendix=include_raw_appendix,
        include_graph_appendix=include_graph_appendix,
        template=report_template,
        redactions={
            option
            for option, enabled in (
                ("ipv4", redact_ips),
                ("email", redact_emails),
                ("domain", redact_domains),
            )
            if enabled
        },
        branding=branding,
        custom_redaction_terms=parse_custom_terms(custom_terms_text),
        custom_redaction_regex=custom_regex_text,
    )

    if "case_report_markdown" not in st.session_state:
        st.session_state.case_report_markdown = ""

    generate_report = st.button("Generate / refresh report preview", type="primary")
    if generate_report:
        try:
            st.session_state.case_report_markdown = build_case_report(
                st.session_state.case_id,
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
        case = get_case(st.session_state.case_id, conn=conn)
        conn.close()
        case_slug = (case or {}).get("name", f"case_{st.session_state.case_id}")
        safe_name = re.sub(r"[^\w\-]+", "_", case_slug.strip().lower()) or "case"
        report_json = build_case_report_json(st.session_state.case_id, options=report_options)
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
                        st.session_state.case_id,
                        markdown_text=report_markdown,
                    )
                    st.success(f"Saved to `{saved_path}`")
                except Exception as exc:
                    st.error(f"Failed to save Markdown: {exc}")
        with save_col2:
            if st.button("Save HTML", width="stretch"):
                try:
                    saved_path = save_report_html(
                        st.session_state.case_id,
                        html_text=report_html,
                    )
                    st.success(f"Saved to `{saved_path}`")
                except Exception as exc:
                    st.error(f"Failed to save HTML: {exc}")
        with save_col3:
            if st.button("Save PDF", width="stretch", disabled=not pdf_available):
                try:
                    saved_path = save_report_pdf(
                        st.session_state.case_id,
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
                            st.session_state.case_id,
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
                file_name=f"{safe_name}_{st.session_state.case_id}_report.md",
                mime="text/markdown",
                width="stretch",
            )
        with download_col2:
            st.download_button(
                "Download HTML",
                data=report_html,
                file_name=f"{safe_name}_{st.session_state.case_id}_report.html",
                mime="text/html",
                width="stretch",
            )
        with download_col3:
            st.download_button(
                "Download JSON",
                data=report_json,
                file_name=f"{safe_name}_{st.session_state.case_id}_export.json",
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
                        file_name=f"{safe_name}_{st.session_state.case_id}_report.pdf",
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
            default=[label for label, cid in case_options.items() if cid == st.session_state.case_id],
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

with tab_graph:
    conn = get_db_conn()
    entities = list_entities(case_id=st.session_state.case_id, conn=conn)
    relationships = list_relationships(case_id=st.session_state.case_id, conn=conn)
    findings = list_findings(case_id=st.session_state.case_id, conn=conn)
    conn.close()
    st.caption(
        "Graph built from stored entities and relationships for the active case. "
        "Node colour reflects the highest active finding severity (open, in review, action required). "
        "This view does not perform new scanning."
    )
    figure = entity_graph_figure(entities, relationships, findings)
    if figure is None:
        st.info("No graph data yet. Run Domain Intelligence or Nmap against a target to populate entities and relationships.")
    else:
        st.plotly_chart(figure, width="stretch")

with tab_legacy:
    st.caption(
        "Legacy v0.1 tables kept for backwards compatibility. "
        "Use **Cases**, **Entities**, and **Observations** for current investigations."
    )
    conn = get_db_conn()
    st.markdown("**Targets (legacy manifest)**")
    st.dataframe(pd.read_sql_query("SELECT * FROM targets", conn), width="stretch")
    st.markdown("**Scan logs (legacy recon_data)**")
    st.dataframe(pd.read_sql_query("SELECT * FROM recon_data", conn), width="stretch")
    conn.close()

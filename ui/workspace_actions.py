"""Apply workspace next-action clicks (session state, queue, navigation)."""

from __future__ import annotations

from typing import Any

import streamlit as st

from database.db_setup import create_or_get_entity, get_db_conn, infer_entity_type, list_operations
from database.personal_lab import add_personal_lab_scope_item, list_personal_lab_scope
from ui.constants import IMPLEMENTED_MODULE_IDS
from ui.navigation import open_entity_in_workspace
from utils.batch_queue import add_queue_item, sort_queue_items
from utils.batch_queue_store import load_batch_queue, save_batch_queue
from utils.engagement_guardrails import resolve_scope_match

ASSESSMENT_GOAL_SESSION_KEY = "assessment_goal"


def apply_workspace_action(action: dict[str, Any], case_id: int) -> str:
    """Execute a workspace action. Returns a user-visible status message."""
    if not action.get("enabled"):
        return action.get("blocked_reason") or "This action is not available."

    action_type = action.get("action_type")
    st.session_state.last_workspace_action = action.get("id")

    if action_type == "run_module":
        module_id = action.get("module_id")
        if not module_id:
            return "No module specified for this action."
        provenance = st.session_state.get("capture_provenance")
        if provenance and action.get("target"):
            st.session_state.capture_followup_pending = {
                "sha256": provenance.get("sha256"),
                "target": action.get("target"),
                "module_id": module_id,
            }
        for mid in IMPLEMENTED_MODULE_IDS:
            st.session_state[f"module_sel_{mid}"] = mid == module_id
        action_target = (action.get("target") or "").strip()
        if action_target:
            st.session_state.operation_target = action_target
            if module_id == "infra_http_security" and action_target.startswith(("http://", "https://")):
                st.session_state.http_requested_url = action_target
                st.session_state.http_target_source = "discovered_service"
            if module_id == "infra_tls_review":
                import re

                port_match = re.search(r"port\s+(\d+)", action.get("title", ""), re.IGNORECASE)
                if port_match:
                    st.session_state.tls_review_port_override = int(port_match.group(1))
                    st.session_state.tls_target_source = "discovered_service"
            if module_id == "infra_ssh_review":
                import re

                port_match = re.search(r"port\s+(\d+)", action.get("title", ""), re.IGNORECASE)
                if port_match:
                    st.session_state.ssh_review_port_override = int(port_match.group(1))
        if action.get("goal_id"):
            st.session_state[ASSESSMENT_GOAL_SESSION_KEY] = action["goal_id"]
        st.session_state.workspace_focus_run_panel = True
        module = action.get("module_display_name") or module_id
        return f"Selected **{module}** — confirm authorisation in the run panel (active modules are not auto-run)."

    if action_type == "add_to_queue":
        module_id = action.get("module_id")
        target = (action.get("target") or "").strip()
        if not module_id or not target:
            return "Queue action requires a target and module."
        conn = get_db_conn()
        try:
            entity = create_or_get_entity(
                case_id,
                infer_entity_type(target),
                target,
                label=target,
                source="workspace_action",
                conn=conn,
            )
            items = load_batch_queue(case_id)
            operations = list_operations(case_id, conn=conn)
            updated, item, reason = add_queue_item(
                items,
                case_id,
                entity,
                module_id,
                operations=operations,
            )
            if item:
                save_batch_queue(case_id, sort_queue_items(updated))
                label = action.get("module_display_name") or module_id
                return f"Added **{label}** for `{target}` to Batch Queue."
            return reason or "Could not add to Batch Queue."
        finally:
            conn.close()

    if action_type == "open_entity":
        entity_id = action.get("entity_id")
        target = (action.get("target") or "").strip()
        conn = get_db_conn()
        try:
            if entity_id is None and target:
                entity = create_or_get_entity(
                    case_id,
                    infer_entity_type(target),
                    target,
                    label=target,
                    source="workspace_action",
                    conn=conn,
                )
                entity_id = entity["id"]
        finally:
            conn.close()
        if entity_id is None:
            return "No entity available to open."
        open_entity_in_workspace(int(entity_id))
        st.rerun()

    if action_type == "open_finding":
        if action.get("finding_id"):
            st.session_state.findings_focus_id = int(action["finding_id"])
        st.session_state.nav_page = "Findings"
        st.rerun()

    if action_type == "review_evidence":
        st.session_state.nav_page = "Evidence Locker"
        st.rerun()

    if action_type == "open_graph":
        entity_id = action.get("entity_id")
        if entity_id:
            st.session_state.graph_focus_entity = int(entity_id)
        st.session_state.nav_page = "Graph"
        st.rerun()

    if action_type == "create_report":
        st.session_state.nav_page = "Report"
        st.rerun()

    if action_type == "update_scope":
        st.session_state.nav_page = "Client Engagements"
        st.rerun()

    if action_type == "add_lab_scope":
        target = (action.get("target") or "").strip()
        if not target:
            return "No target specified for lab scope."
        if (
            st.session_state.get("operating_context") == "personal_lab"
            and not st.session_state.get("personal_lab_confirmed")
        ):
            return "Tick Personal Lab confirmation before adding lab scope."
        conn = get_db_conn()
        try:
            items = list_personal_lab_scope(case_id, conn=conn)
            if resolve_scope_match(target, items) is not None:
                return "Target is already in Personal Lab scope."
            add_personal_lab_scope_item(case_id, target, conn=conn)
            return f"Added `{target}` to Personal Lab scope."
        finally:
            conn.close()

    if action_type == "add_note":
        existing = st.session_state.get("workspace_analyst_notes", "")
        note = f"[{action.get('title', 'Note')}] {action.get('reason', '')}"
        st.session_state.workspace_analyst_notes = (existing + "\n" + note).strip()
        return "Added note to workspace analyst notes."

    if action_type == "try_common_web_ports":
        target = (action.get("target") or "").strip()
        if not target:
            return "No target specified for web port probe."
        if (
            st.session_state.get("operating_context") == "personal_lab"
            and not st.session_state.get("personal_lab_confirmed")
        ):
            return "Tick Personal Lab confirmation before probing web ports."
        if (
            st.session_state.get("operating_context") == "client_engagement"
            and not st.session_state.get("authorisation_confirmed")
        ):
            return "Confirm authorisation before probing web ports."
        from utils.web_port_planner import DEFAULT_COMMON_WEB_PORTS, probe_web_ports_sequential, reachable_probe_ports

        results = probe_web_ports_sequential(target, DEFAULT_COMMON_WEB_PORTS)
        reachable = reachable_probe_ports(results)
        st.session_state[f"web_port_probe_{target}"] = results
        if reachable:
            ports = ", ".join(str(row["port"]) for row in reachable)
            st.session_state.pending_web_port_target = target
            st.session_state.pending_web_ports = [row["port"] for row in reachable]
            return f"Reachable web ports on `{target}`: {ports}. Use advanced HTTP/TLS settings or next actions."
        attempted = ", ".join(str(row["port"]) for row in results)
        return (
            f"No common web ports responded on `{target}` (tried {attempted}). "
            "Run Network Service Check or confirm the host is online."
        )

    return "Action applied."

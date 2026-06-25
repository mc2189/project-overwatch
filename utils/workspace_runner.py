"""Execute assessment workspace module runs (shared by UI and lab orchestration)."""

from __future__ import annotations

from typing import Any

from database.db_setup import create_or_get_entity, get_db_conn, infer_entity_type
from modules.executor import execute_module
from modules.module_registry import get_module, is_executable
from utils.run_modes import get_run_mode_label, persist_run_mode_for_case
from utils.target_detection import file_target_type, get_target_type


def execute_workspace_modules(
    *,
    current_case: dict,
    target: str,
    selected_ids: list[str],
    operating_context: str,
    personal_lab_confirmed: bool,
    authorisation_confirmed: bool,
    run_mode_id: str,
    session_state: dict[str, Any],
    pcap_session_key: str = "pcap_upload",
    file_metadata_session_key: str = "file_metadata_uploads",
) -> list[dict[str, Any]]:
    """Run selected modules for the workspace target and return result rows."""
    nmap_options = session_state.get("nmap_options", {})
    run_mode_label = get_run_mode_label(run_mode_id)
    persist_run_mode_for_case(current_case["id"], run_mode_id)
    run_results: list[dict[str, Any]] = []
    conn = get_db_conn()
    try:
        target_value = target.strip()
        entity = create_or_get_entity(
            current_case["id"],
            infer_entity_type(target_value),
            target_value,
            label=target_value,
            source="operation",
            conn=conn,
        )
        for module_id in selected_ids:
            module = get_module(module_id)
            if module is None or not is_executable(module):
                continue
            options: dict[str, Any] = {}
            if module_id == "infra_nmap":
                options = {"nmap_options": nmap_options}
            elif module_id == "infra_tls_review":
                tls_opts = session_state.get("tls_review_options", {})
                options = {
                    "port_override": tls_opts.get("port_override"),
                    "protocol_probes": tls_opts.get("protocol_probes", True),
                    "target_source": tls_opts.get("target_source", "default_assumption"),
                }
            elif module_id == "infra_http_security":
                http_opts = session_state.get("http_security_options", {})
                options = {
                    "request_method": http_opts.get("request_method", "GET"),
                    "port_override": http_opts.get("port_override"),
                    "scheme_override": http_opts.get("scheme_override"),
                    "requested_url": http_opts.get("requested_url"),
                    "target_source": http_opts.get("target_source", "default_assumption"),
                }
            elif module_id in {"infra_web_stack_identifier", "infra_web_path_review"}:
                http_opts = session_state.get("http_security_options", {})
                options = {
                    "request_method": http_opts.get("request_method", "GET"),
                    "port_override": http_opts.get("port_override"),
                    "scheme_override": http_opts.get("scheme_override"),
                    "requested_url": http_opts.get("requested_url"),
                    "target_source": http_opts.get("target_source", "default_assumption"),
                }
            elif module_id == "infra_remote_access_review":
                latest = session_state.get("latest_run_results") or run_results
                nmap_ports: list[dict] = []
                for prior in latest:
                    if prior.get("module_id") == "infra_nmap" and prior.get("success"):
                        nmap_ports = (prior.get("parsed_data") or {}).get("parsed_ports") or []
                        break
                options = {"parsed_ports": nmap_ports, "latest_results": latest}
            elif module_id == "infra_ssh_review":
                latest = session_state.get("latest_run_results") or run_results
                nmap_ports = []
                for prior in latest:
                    if prior.get("module_id") == "infra_nmap" and prior.get("success"):
                        nmap_ports = (prior.get("parsed_data") or {}).get("parsed_ports") or []
                        break
                ssh_opts = session_state.get("ssh_review_options", {})
                options = {
                    "parsed_ports": nmap_ports,
                    "latest_results": latest,
                    "port_override": ssh_opts.get("port_override"),
                    "explicit_review": True,
                }
            elif module_id == "net_pcap_review":
                pcap_upload = session_state.get(pcap_session_key) or {}
                options = {
                    "pcap_file_path": pcap_upload.get("storage_path"),
                    "pcap_filename": pcap_upload.get("filename") or target_value,
                    "pcap_sha256": pcap_upload.get("sha256"),
                    "pcap_size": pcap_upload.get("size_bytes"),
                    "case_id": current_case["id"],
                }
            elif module_id == "evidence_file_metadata":
                uploads = list(session_state.get(file_metadata_session_key) or [])
                options = {
                    "uploaded_files": uploads,
                    "case_id": current_case["id"],
                    "target_type": file_target_type(uploads[0]["filename"]) if uploads else get_target_type(target_value),
                }
            options["operating_context"] = operating_context
            options["personal_lab_confirmed"] = personal_lab_confirmed
            result = execute_module(
                module_id,
                target_value,
                options=options,
                db_context=conn,
                authorisation_confirmed=(
                    personal_lab_confirmed if operating_context == "personal_lab" else authorisation_confirmed
                ),
                case_id=current_case["id"],
                entity_id=entity["id"],
                run_mode_id=run_mode_id,
                run_mode_label=run_mode_label,
            )
            run_results.append(result)
    finally:
        conn.close()
    return run_results

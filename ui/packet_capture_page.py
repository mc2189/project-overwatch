"""Personal Lab Packet Capture page."""

from __future__ import annotations

import streamlit as st

from database.db_setup import create_or_get_entity, get_db_conn, get_or_create_default_case, infer_entity_type, list_operations
from modules.executor import execute_module
from ui.concise_results import render_result_detail_expanders
from ui.styles import render_status_chip, section_heading
from utils.live_capture import (
    DEFAULT_DURATION_SECONDS,
    DEFAULT_PACKET_CAP,
    FILTER_PRESETS,
    MAX_DURATION_SECONDS,
    MAX_PACKET_CAP,
    PERSONAL_LAB_CAPTURE_CONFIRMATION,
    capture_backend_status,
    default_interface,
    list_capture_interfaces,
    macos_capture_permission_guidance,
    macos_capture_permission_status,
    preview_output_filename,
)
from utils.pcap_analysis import pyshark_available
from ui.workspace_actions import apply_workspace_action
from utils.pcap_next_actions import (
    suggest_pcap_investigation_actions,
    suggest_pcap_primary_action,
)
from utils.pcap_followup_runner import (
    build_recon_progress_summary,
    queue_passive_for_entity,
    queue_passive_for_ranked_entities,
    run_modules_for_ranked_entities,
    run_suggested_for_entity,
    runnable_modules_for_entity,
)
from utils.pcap_synthesis import build_capture_followup_synthesis
from utils.pcap_recon_artifact import build_capture_recon_artifact
from utils.pcap_triage import dedupe_table_rows, rank_investigation_entities
from utils.web_port_planner import is_private_ipv4_target

CAPTURE_IN_PROGRESS_KEY = "live_capture_in_progress"
CAPTURE_LAST_RESULT_KEY = "live_capture_last_result"
CAPTURE_CONFIRM_KEY = "personal_lab_capture_confirmed"
CAPTURE_FOLLOWUP_RESULTS_KEY = "capture_followup_results"
CAPTURE_RECON_SUMMARY_KEY = "capture_recon_summary"
CAPTURE_RECON_ARTIFACT_KEY = "capture_recon_artifact"


def _render_readiness() -> dict:
    backend = capture_backend_status()
    interfaces, iface_error = list_capture_interfaces()

    c1, c2, c3 = st.columns(3)
    c1.metric("tshark", "Yes" if backend["tshark_available"] else "No")
    c2.metric("tcpdump", "Yes" if backend["tcpdump_available"] else "No")
    c3.metric("pyshark", "Yes" if pyshark_available() else "No")

    st.metric("Backend", backend["selected_backend"] or "None")

    if backend["selected_backend"]:
        st.success(f"Usable backend: **{backend['selected_backend']}**")
    else:
        st.warning(
            "Install **Wireshark/tshark** or **tcpdump** to capture packets. "
            "Uploaded PCAP review remains available without live capture."
        )

    if backend["tshark_available"] and not pyshark_available():
        st.info(
            "Install **pyshark** (`pip install pyshark`) for full DNS, HTTP, and TLS analysis "
            "after capture. Basic packet counts still work via capinfos/tshark."
        )

    if interfaces:
        st.caption(f"{len(interfaces)} interface(s) discovered.")
    elif iface_error:
        st.caption(iface_error)

    perm = macos_capture_permission_status()
    if perm is not None:
        if perm["ready"]:
            st.success("macOS capture permissions look OK for this process.")
        else:
            st.error(
                "macOS capture permissions are not ready for this process. "
                "Live capture will fail until BPF access is configured."
            )
            detail_bits = []
            if not perm["access_bpf_group_exists"]:
                detail_bits.append("`access_bpf` group not found (run Wireshark ChmodBPF)")
            elif not perm["in_access_bpf_group"]:
                detail_bits.append("your user is not in `access_bpf` yet (log out/in after ChmodBPF)")
            if not perm["bpf_devices_group_accessible"]:
                detail_bits.append("`/dev/bpf*` is not group-writable (ChmodBPF not applied)")
            if detail_bits:
                st.caption(" · ".join(detail_bits))
            with st.expander("Fix macOS capture permissions", expanded=True):
                for index, step in enumerate(macos_capture_permission_guidance(), start=1):
                    st.markdown(f"{index}. {step}")

    return {"backend": backend, "interfaces": interfaces, "iface_error": iface_error, "perm": perm}


def _followup_lab_confirmed() -> bool:
    return bool(
        st.session_state.get(CAPTURE_CONFIRM_KEY)
        or st.session_state.get("personal_lab_confirmed")
    )


def _append_followup_results(capture_result: dict, new_results: list[dict], *, case_id: int) -> str:
    if not new_results:
        return "No modules ran — check Personal Lab confirmation, API keys, or compatibility."
    existing = st.session_state.get(CAPTURE_FOLLOWUP_RESULTS_KEY) or []
    merged = existing + new_results
    st.session_state[CAPTURE_FOLLOWUP_RESULTS_KEY] = merged
    st.session_state.latest_run_results = (st.session_state.get("latest_run_results") or []) + new_results
    st.session_state[CAPTURE_RECON_SUMMARY_KEY] = build_recon_progress_summary(capture_result, merged)
    parsed = capture_result.get("parsed_data") or {}
    pcap_parsed = (parsed.get("pcap_review") or {}).get("parsed_data") or {}
    triage = parsed.get("triage") or pcap_parsed.get("triage") or {}
    st.session_state[CAPTURE_RECON_ARTIFACT_KEY] = build_capture_recon_artifact(
        capture_result,
        followup_results=merged,
        pcap_parsed=pcap_parsed,
        triage=triage,
        case_id=case_id,
    )
    completed = sum(1 for row in new_results if row.get("success"))
    failed = len(new_results) - completed
    if failed:
        return f"Ran {len(new_results)} check(s): {completed} completed, {failed} blocked or failed."
    return f"Ran {len(new_results)} check(s): {completed} completed."


def _render_lan_devices(case_id: int, pcap_parsed: dict) -> None:
    devices = list(pcap_parsed.get("lan_devices") or [])
    followup_results = st.session_state.get(CAPTURE_FOLLOWUP_RESULTS_KEY) or []
    if followup_results:
        from utils.nmap_lan_enrichment import enrich_lan_devices_from_nmap

        devices = enrich_lan_devices_from_nmap(devices, followup_results)
    if not devices:
        if pcap_parsed.get("dhcp_activity") or pcap_parsed.get("arp_activity") or pcap_parsed.get("mdns_activity"):
            st.caption("LAN discovery traffic was seen, but no stable device rows could be inferred yet.")
        return

    section_heading("LAN devices")
    st.caption(lan_device_summary(devices))
    st.dataframe(
        [
            {
                "IP": row.get("ip") or "—",
                "MAC": row.get("mac") or "—",
                "Hostname": row.get("hostname") or "—",
                "Role": row.get("role_label") or "—",
                "Nmap": row.get("nmap_services_summary") or "—",
                "Sources": ", ".join(row.get("sources") or []),
                "Confidence": row.get("confidence") or "—",
            }
            for row in devices[:20]
        ],
        width="stretch",
        hide_index=True,
    )

    lab_ok = _followup_lab_confirmed()
    for index, device in enumerate(devices[:8]):
        ip = str(device.get("ip") or "").strip()
        if not ip:
            continue
        label = device.get("hostname") or ip
        if st.button(
            f"Run Network Service Check on {label}",
            key=f"capture_lan_nmap_{index}_{ip}",
            disabled=not lab_ok,
            width="stretch",
        ):
            from utils.nmap_profiles import options_for_profile, PROFILE_LOCAL_DEVICE

            conn = get_db_conn()
            try:
                entity = create_or_get_entity(
                    case_id,
                    infer_entity_type(ip),
                    ip,
                    label=label,
                    source="capture_lan_device",
                    conn=conn,
                )
                result = execute_module(
                    "infra_nmap",
                    ip,
                    options={
                        "operating_context": PERSONAL_LAB,
                        "personal_lab_confirmed": lab_ok,
                        "nmap_options": options_for_profile(PROFILE_LOCAL_DEVICE),
                    },
                    db_context=conn,
                    authorisation_confirmed=lab_ok,
                    case_id=case_id,
                    entity_id=entity["id"],
                    run_mode_id="capture_lan_nmap",
                    run_mode_label="LAN device Nmap",
                )
                result["target"] = ip
            finally:
                conn.close()
            capture_result = st.session_state.get(CAPTURE_LAST_RESULT_KEY) or {}
            st.session_state.capture_action_message = _append_followup_results(
                capture_result, [result], case_id=case_id
            )
            st.rerun()


def _render_recon_artifact(
    case_id: int,
    *,
    capture_result: dict,
    pcap_parsed: dict,
    triage: dict,
) -> None:
    followup_results = st.session_state.get(CAPTURE_FOLLOWUP_RESULTS_KEY) or []
    artifact = st.session_state.get(CAPTURE_RECON_ARTIFACT_KEY)
    if not artifact and followup_results:
        artifact = build_capture_recon_artifact(
            capture_result,
            followup_results=followup_results,
            pcap_parsed=pcap_parsed,
            triage=triage,
            case_id=case_id,
        )
    if not artifact:
        return

    progress = artifact.get("progress") or {}
    if not progress.get("modules_run") and not artifact.get("lan_devices") and not artifact.get("synthesis_lines"):
        return

    section_heading("Capture recon result")
    if artifact.get("network_picture"):
        st.caption(artifact["network_picture"])
    if artifact.get("lan_device_summary"):
        st.caption(artifact["lan_device_summary"])

    r1, r2, r3, r4 = st.columns(4)
    r1.metric("Follow-up checks", progress.get("modules_run", 0))
    r2.metric("Completed", progress.get("modules_completed", 0))
    r3.metric("Failed/blocked", progress.get("modules_failed", 0))
    r4.metric("New findings", progress.get("total_findings", 0))

    if artifact.get("device_lines"):
        st.markdown("**LAN device roles**")
        for line in artifact["device_lines"][:8]:
            st.markdown(f"- {line}")

    if artifact.get("synthesis_lines"):
        st.markdown("**Capture → module synthesis**")
        for line in artifact["synthesis_lines"][:8]:
            st.markdown(f"- {line}")

    lab_ok = _followup_lab_confirmed()
    next_steps = artifact.get("suggested_next_steps") or []
    if next_steps:
        st.markdown("**Suggested next tests**")
        active_modules = {"infra_nmap", "infra_tls_review", "infra_http_security", "infra_web_stack_identifier", "infra_web_path_review", "infra_remote_access_review"}
        for pindex, action in enumerate(next_steps[:6]):
            module_id = action.get("module_id")
            needs_lab = module_id in active_modules
            if st.button(
                action.get("button_label") or action.get("title"),
                key=f"capture_artifact_action_{pindex}_{action.get('module_id')}",
                disabled=not action.get("enabled") or (needs_lab and not lab_ok),
                width="stretch",
            ):
                if not action.get("module_id") or not action.get("target"):
                    continue
                if needs_lab and not lab_ok:
                    st.session_state.capture_action_message = (
                        "Confirm Personal Lab capture to run active follow-up scans."
                    )
                    st.rerun()
                target = str(action["target"]).strip()
                module_id = str(action["module_id"])
                conn = get_db_conn()
                try:
                    entity = create_or_get_entity(
                        case_id,
                        infer_entity_type(target),
                        target,
                        label=target,
                        source="capture_followup",
                        conn=conn,
                    )
                    result = execute_module(
                        module_id,
                        target,
                        options={
                            "operating_context": PERSONAL_LAB,
                            "personal_lab_confirmed": lab_ok or module_id not in active_modules,
                        },
                        db_context=conn,
                        authorisation_confirmed=lab_ok or module_id not in active_modules,
                        case_id=case_id,
                        entity_id=entity["id"],
                        run_mode_id="capture_followup",
                        run_mode_label="Capture recon follow-up",
                    )
                    result["target"] = target
                finally:
                    conn.close()
                st.session_state.capture_action_message = _append_followup_results(
                    capture_result, [result], case_id=case_id
                )
                st.rerun()


def _render_interactive_followups(
    case_id: int,
    *,
    ranked: list[dict],
    capture_result: dict,
) -> None:
    """Clickable priority follow-ups with bulk run/queue actions."""
    candidates = [item for item in ranked if item.get("tier") in {"investigate", "review"}][:12]
    if not candidates:
        return

    section_heading("Priority follow-ups")
    st.caption(
        "Run the suggested test series from capture triage in one click. "
        "Passive intel uses API modules; LAN scans use Nmap (Personal Lab)."
    )

    lab_ok = _followup_lab_confirmed()
    if not lab_ok:
        st.warning("Confirm **Personal Lab packet capture** above to run active follow-up scans from this page.")

    bulk_run, bulk_queue, bulk_lan = st.columns(3)
    with bulk_run:
        if st.button(
            "Run all suggested",
            key="capture_bulk_run_investigate",
            disabled=not lab_ok,
            width="stretch",
        ):
            with st.spinner("Running suggested tests for investigate-tier entities…"):
                new_results = run_modules_for_ranked_entities(
                    case_id,
                    candidates,
                    tiers=("investigate", "review"),
                    personal_lab_confirmed=lab_ok,
                )
                st.session_state.capture_action_message = _append_followup_results(
                    capture_result, new_results, case_id=case_id
                )
            st.rerun()
    with bulk_queue:
        if st.button("Queue all passive checks", key="capture_bulk_queue_passive", width="stretch"):
            added, _skipped = queue_passive_for_ranked_entities(
                case_id,
                candidates,
                tiers=("investigate", "review"),
            )
            st.session_state.capture_action_message = (
                f"Added {added} passive queue item(s)." if added else "No new passive items queued."
            )
            st.rerun()
    with bulk_lan:
        lan_items = [
            item
            for item in candidates
            if item.get("entity_type") == "ip" and is_private_ipv4_target(str(item.get("value") or ""))
        ]
        if st.button(
            f"Scan all LAN IPs (Nmap) · {len(lan_items)}",
            key="capture_bulk_lan_nmap",
            disabled=not lab_ok or not lan_items,
            width="stretch",
        ):
            with st.spinner("Running Nmap on LAN IPs from capture…"):
                new_results = run_modules_for_ranked_entities(
                    case_id,
                    lan_items,
                    active_only=True,
                    personal_lab_confirmed=lab_ok,
                    ignore_tier=True,
                    limit_modules_per_entity=1,
                )
                st.session_state.capture_action_message = _append_followup_results(
                    capture_result, new_results, case_id=case_id
                )
            st.rerun()

    for index, item in enumerate(candidates):
        value = str(item.get("value") or "")
        suggested = runnable_modules_for_entity(item)
        suggested_text = ", ".join(suggested) if suggested else "—"
        device_hint = item.get("device_hint") or {}
        hint_bits = []
        if device_hint.get("hostname"):
            hint_bits.append(device_hint["hostname"])
        if device_hint.get("role_label"):
            hint_bits.append(device_hint["role_label"])
        hint_text = f" · {' / '.join(hint_bits)}" if hint_bits else ""
        label = (
            f"**{value}** · {item.get('tier')} · {item.get('org_bucket')} · "
            f"{item.get('packets', 0)} pkts{hint_text} · tests: {suggested_text}"
        )
        with st.container(border=True):
            st.markdown(label)
            row1, row2, row3, row4 = st.columns(4)
            with row1:
                if st.button(
                    "Run suggested",
                    key=f"capture_run_suggested_{index}_{value}",
                    disabled=not lab_ok or not suggested,
                    width="stretch",
                ):
                    with st.spinner(f"Running tests for {value}…"):
                        new_results = run_suggested_for_entity(
                            case_id,
                            item,
                            personal_lab_confirmed=lab_ok,
                        )
                        st.session_state.capture_action_message = _append_followup_results(
                            capture_result, new_results, case_id=case_id
                        )
                    st.rerun()
            with row2:
                if st.button(
                    "Queue passive",
                    key=f"capture_queue_passive_{index}_{value}",
                    width="stretch",
                ):
                    added, _ = queue_passive_for_entity(case_id, item)
                    st.session_state.capture_action_message = (
                        f"Queued {added} passive item(s) for {value}."
                        if added
                        else f"No new passive items for {value}."
                    )
                    st.rerun()
            with row3:
                if st.button(
                    "Open entity",
                    key=f"capture_open_entity_{index}_{value}",
                    width="stretch",
                ):
                    conn = get_db_conn()
                    try:
                        entity = create_or_get_entity(
                            case_id,
                            infer_entity_type(value),
                            value,
                            label=value,
                            source="capture_followup",
                            conn=conn,
                        )
                    finally:
                        conn.close()
                    from ui.navigation import open_entity_in_workspace

                    open_entity_in_workspace(entity["id"])
                    st.rerun()
            with row4:
                if st.button(
                    "Open Batch Queue",
                    key=f"capture_open_batch_{index}",
                    width="stretch",
                ):
                    from ui.batch_queue_page import navigate_to_batch_queue

                    navigate_to_batch_queue()
                    st.rerun()


def _render_capture_form(case_id: int, readiness: dict) -> None:
    backend = readiness["backend"]
    interfaces = readiness["interfaces"]
    iface_error = readiness.get("iface_error")
    if not backend["any_available"]:
        return

    if not interfaces:
        st.warning(
            iface_error
            or "No network interfaces were discovered. Click **Refresh interfaces** or install/configure tshark/tcpdump."
        )
        if st.button("Refresh interfaces", key="refresh_interfaces_empty", width="stretch"):
            st.rerun()
        return

    interface_ids = [iface["id"] for iface in interfaces]
    default_iface = default_interface(interfaces) or (interface_ids[0] if interface_ids else "")
    if default_iface and default_iface in interface_ids:
        default_index = interface_ids.index(default_iface)
    else:
        default_index = 0

    col_a, col_b = st.columns([3, 1])
    with col_a:
        interface_id = st.selectbox(
            "Network interface",
            options=interface_ids,
            index=default_index,
            format_func=lambda value: next(
                (item["label"] for item in interfaces if item["id"] == value),
                value,
            ),
        )
    with col_b:
        if st.button("Refresh interfaces", width="stretch"):
            st.rerun()

    duration = st.slider(
        "Capture duration (seconds)",
        min_value=5,
        max_value=MAX_DURATION_SECONDS,
        value=DEFAULT_DURATION_SECONDS,
        step=5,
    )
    packet_cap = st.number_input(
        "Packet cap",
        min_value=100,
        max_value=MAX_PACKET_CAP,
        value=DEFAULT_PACKET_CAP,
        step=100,
    )

    preset_labels = {key: value["label"] for key, value in FILTER_PRESETS.items()}
    preset_labels["custom"] = "Custom (advanced)"
    filter_preset = st.selectbox(
        "Filter preset",
        options=list(preset_labels.keys()),
        format_func=lambda key: preset_labels[key],
    )
    filter_target_host = ""
    custom_bpf = ""
    if filter_preset == "target_host":
        filter_target_host = st.text_input(
            "Target host (IPv4 or domain)",
            placeholder="192.168.1.10 or example.local",
        )
    if filter_preset == "custom":
        with st.expander("Advanced custom BPF filter", expanded=False):
            custom_bpf = st.text_input(
                "BPF capture filter",
                placeholder="tcp port 443",
                help="Optional Berkeley Packet Filter expression. Invalid filters fail safely.",
            )

    filename_preview = preview_output_filename(interface_id)
    st.caption(f"Output file preview: `{filename_preview}`")

    workspace_confirmed = bool(st.session_state.get("personal_lab_confirmed", False))
    if CAPTURE_CONFIRM_KEY not in st.session_state and workspace_confirmed:
        st.session_state[CAPTURE_CONFIRM_KEY] = True

    confirmed = st.checkbox(PERSONAL_LAB_CAPTURE_CONFIRMATION, key=CAPTURE_CONFIRM_KEY)
    if confirmed:
        st.session_state.personal_lab_confirmed = True
    elif workspace_confirmed:
        confirmed = True

    if workspace_confirmed and not st.session_state.get(CAPTURE_CONFIRM_KEY, False):
        st.caption("Personal Lab confirmation carried over from Assessment Workspace.")

    in_progress = st.session_state.get(CAPTURE_IN_PROGRESS_KEY, False)
    start_disabled = not confirmed or in_progress or not interfaces

    if st.button(
        "Start capture",
        type="primary",
        disabled=start_disabled or not interface_id,
        width="stretch",
    ):
        if not interface_id:
            st.error("Select a network interface before starting capture.")
            return
        target = f"live-capture:{interface_id}"
        conn = get_db_conn()
        try:
            entity = create_or_get_entity(
                case_id,
                "artefact",
                filename_preview,
                label=filename_preview,
                source="net_live_capture",
                conn=conn,
            )
            with st.spinner(f"Capturing up to {duration}s / {packet_cap:,} packets…"):
                result = execute_module(
                    "net_live_capture",
                    target,
                    options={
                        "case_id": case_id,
                        "interface_id": interface_id,
                        "interfaces": interfaces,
                        "duration_seconds": duration,
                        "packet_cap": packet_cap,
                        "filter_preset": filter_preset,
                        "filter_target_host": filter_target_host,
                        "custom_bpf_filter": custom_bpf,
                        "output_filename": filename_preview,
                        "operating_context": PERSONAL_LAB,
                        "personal_lab_confirmed": confirmed,
                        "standalone_authorised_testing": True,
                        "workspace_target": str(st.session_state.get("operation_target") or ""),
                    },
                    db_context=conn,
                    authorisation_confirmed=True,
                    case_id=case_id,
                    entity_id=entity["id"],
                )
        finally:
            conn.close()
        st.session_state[CAPTURE_LAST_RESULT_KEY] = result
        st.session_state[CAPTURE_FOLLOWUP_RESULTS_KEY] = []
        st.session_state.pop(CAPTURE_RECON_SUMMARY_KEY, None)
        st.session_state.pop(CAPTURE_RECON_ARTIFACT_KEY, None)
        st.session_state.live_capture_entity_id = entity["id"]
        capture_meta = (result.get("parsed_data") or {}).get("capture") or {}
        st.session_state.capture_provenance = {
            "sha256": capture_meta.get("sha256"),
            "filename": capture_meta.get("filename"),
            "case_id": case_id,
        }
        st.rerun()


def _render_capture_result(case_id: int) -> None:
    result = st.session_state.get(CAPTURE_LAST_RESULT_KEY)
    if not result:
        return

    section_heading("Capture result")
    status_key = "complete" if result.get("success") else "failed"
    if result.get("status") == "blocked":
        status_key = "blocked"
    head = st.columns([4, 1])
    with head[0]:
        st.markdown(f"**{result.get('summary', 'Capture result')}**")
    with head[1]:
        render_status_chip(status_key)

    parsed = result.get("parsed_data") or {}
    capture = parsed.get("capture") or {}
    pcap_parsed = (parsed.get("pcap_review") or {}).get("parsed_data") or {}

    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Backend", capture.get("backend") or "—")
    m2.metric("Interface", capture.get("interface") or "—")
    m3.metric(
        "Packets",
        pcap_parsed.get("packets_analysed")
        or pcap_parsed.get("packet_count")
        or capture.get("packets_captured")
        or "—",
    )
    m4.metric("Findings", len(result.get("interpreter_findings") or []))

    triage = parsed.get("triage") or pcap_parsed.get("triage") or {}
    network_picture = triage.get("network_picture") or {}
    if network_picture.get("one_liner"):
        st.info(f"**Network picture:** {network_picture['one_liner']}")

    if triage.get("narrative"):
        section_heading("Investigation triage")
        for line in triage["narrative"]:
            st.markdown(line)

    buckets = triage.get("talker_buckets") or network_picture.get("talker_buckets") or []
    if buckets:
        st.markdown("**Traffic by platform** (condensed talkers)")
        st.dataframe(
            [
                {
                    "Platform": row.get("bucket"),
                    "Packets": row.get("packets"),
                    "IPs": row.get("ip_count"),
                    "Examples": ", ".join(row.get("sample_ips") or []),
                }
                for row in buckets[:8]
            ],
            width="stretch",
            hide_index=True,
        )

    resilience_notes = triage.get("resilience_notes") or []
    if resilience_notes:
        section_heading("What this means (resilience)")
        for note in resilience_notes:
            st.markdown(f"**{note.get('title', 'Note')}** — {note.get('note', '')}")

    if triage.get("narrative"):
        diff = triage.get("fingerprint_diff") or {}
        if diff.get("has_changes"):
            delta_bits = []
            if diff.get("new_domains"):
                delta_bits.append(f"new domains: {', '.join(diff['new_domains'][:5])}")
            if diff.get("new_public_ips"):
                delta_bits.append(f"new public IPs: {', '.join(diff['new_public_ips'][:5])}")
            if diff.get("new_tls_sni"):
                delta_bits.append(f"new TLS names: {', '.join(diff['new_tls_sni'][:5])}")
            if delta_bits:
                st.info("Changes vs previous capture — " + "; ".join(delta_bits))

    ranked = triage.get("ranked_entities") or []
    if not ranked and pcap_parsed:
        ranked = rank_investigation_entities(pcap_parsed)
    _render_lan_devices(case_id, pcap_parsed)
    _render_interactive_followups(case_id, ranked=ranked, capture_result=result)
    _render_recon_artifact(
        case_id,
        capture_result=result,
        pcap_parsed=pcap_parsed,
        triage=triage,
    )

    focus = triage.get("focus") or {}
    if focus.get("external_to_target"):
        st.caption(
            "External talkers vs workspace target: "
            + ", ".join(
                f"{row.get('ip')} ({row.get('packets')})" for row in focus["external_to_target"][:5]
            )
        )

    if capture.get("filename"):
        st.caption(
            f"File: **{capture['filename']}** · "
            f"{capture.get('file_size_bytes', 0):,} bytes · "
            f"SHA-256 `{str(capture.get('sha256', ''))[:16]}…`"
        )

    if capture.get("permission_denied") and capture.get("manual_command"):
        st.warning(
            "Permission denied. macOS is blocking unprivileged access to `/dev/bpf*`. "
            "Configure capture permissions (see **Capture readiness** above), or run this "
            "command manually in Terminal:"
        )
        st.code(capture["manual_command"], language="bash")
        st.caption(
            "If permissions are not fixed yet, prefix with `sudo` for a one-off lab capture, "
            "then use **Uploaded evidence review** to analyse the saved file."
        )
        with st.expander("Fix macOS capture permissions", expanded=False):
            for index, step in enumerate(macos_capture_permission_guidance(), start=1):
                st.markdown(f"{index}. {step}")

    for warning in result.get("warnings") or []:
        st.warning(warning)
    for error in result.get("errors") or []:
        st.error(error)

    if pcap_parsed.get("protocols"):
        proto_text = ", ".join(
            str(item.get("protocol", "")).upper()
            for item in pcap_parsed["protocols"][:8]
            if item.get("protocol")
        )
        st.caption(f"Top protocols: {proto_text or '—'}")

    if pcap_parsed.get("top_source_ips"):
        talkers = ", ".join(
            item.get("ip", "") for item in pcap_parsed["top_source_ips"][:5] if item.get("ip")
        )
        if talkers:
            st.caption(f"Top talkers: {talkers}")

    workspace_target = str(st.session_state.get("operation_target") or "")
    entity_id = st.session_state.get("live_capture_entity_id")
    provenance = st.session_state.get("capture_provenance") or {}
    conn = get_db_conn()
    try:
        followup_synthesis = build_capture_followup_synthesis(
            pcap_parsed,
            list_operations(case_id, conn=conn),
            capture_sha256=capture.get("sha256") or provenance.get("sha256"),
        )
    finally:
        conn.close()
    if followup_synthesis:
        section_heading("Capture → module synthesis")
        st.caption("Links follow-up checks you ran on entities seen in this capture.")
        for row in followup_synthesis:
            st.markdown(f"- {row.get('summary_line')}")
            if row.get("resilience_note"):
                st.caption(row["resilience_note"])

    investigation_actions = suggest_pcap_investigation_actions(
        result,
        case_id=case_id,
        workspace_target=workspace_target,
        entity_id=int(entity_id) if entity_id else None,
        triage=triage or None,
    )
    primary = suggest_pcap_primary_action(
        result,
        case_id=case_id,
        workspace_target=workspace_target,
        triage=triage or None,
    )
    if primary.get("title"):
        st.caption(f"Next: **{primary.get('title')}**")

    if investigation_actions:
        section_heading("Investigation actions")
        for index, action in enumerate(investigation_actions[:10]):
            label = action.get("button_label") or action.get("title")
            disabled = not action.get("enabled")
            if st.button(
                label,
                key=f"capture_action_{action.get('id', index)}",
                disabled=disabled,
                width="stretch",
            ):
                message = apply_workspace_action(action, case_id)
                if message:
                    st.session_state.capture_action_message = message
                st.rerun()
        blocked = [action for action in investigation_actions if not action.get("enabled")]
        for action in blocked[:3]:
            if action.get("blocked_reason"):
                st.caption(f"{action.get('title')}: {action['blocked_reason']}")

    if st.session_state.get("capture_action_message"):
        st.success(st.session_state.capture_action_message)
        st.session_state.capture_action_message = None

    with st.expander("Capture command details", expanded=False):
        if capture.get("manual_command"):
            st.code(capture["manual_command"], language="bash")
        else:
            st.caption("No command recorded.")

    with st.expander("PCAP analysis details", expanded=False):
        if pcap_parsed:
            if pcap_parsed.get("dns_queries"):
                st.markdown("**DNS (unique sample)**")
                st.dataframe(
                    dedupe_table_rows(pcap_parsed["dns_queries"], "query"),
                    width="stretch",
                    hide_index=True,
                )
            if pcap_parsed.get("http_entries"):
                st.markdown("**HTTP (unique sample)**")
                st.dataframe(
                    dedupe_table_rows(pcap_parsed["http_entries"], "host"),
                    width="stretch",
                    hide_index=True,
                )
            if pcap_parsed.get("tls_sni"):
                st.markdown("**TLS / SNI (unique sample)**")
                st.dataframe(
                    dedupe_table_rows(pcap_parsed["tls_sni"], "server_name"),
                    width="stretch",
                    hide_index=True,
                )
            for finding in result.get("interpreter_findings") or []:
                if finding.get("resilience_note"):
                    st.caption(f"_{finding.get('title')}: {finding['resilience_note']}_")
        else:
            st.caption("No PCAP analysis metadata available.")

    with st.expander("Full module result", expanded=False):
        render_result_detail_expanders(result)


def render_packet_capture_page(current_case: dict | None) -> None:
    """Render the Personal Lab Packet Capture workflow."""
    st.title("Packet Capture")
    st.caption(
        "Bounded Personal Lab capture for your own system, home network, or lab environment. "
        "No client engagement required. Captures are saved and analysed automatically."
    )

    if current_case is None:
        current_case = get_or_create_default_case()
        st.session_state.case_id = current_case["id"]

    st.caption(f"Case: **{current_case.get('name')}** (#{current_case['id']})")

    section_heading("Capture readiness")
    readiness = _render_readiness()

    section_heading("Capture settings")
    _render_capture_form(current_case["id"], readiness)

    _render_capture_result(current_case["id"])

    st.divider()
    if st.button("Return to Assessment Workspace", key="capture_return_workspace", width="stretch"):
        st.session_state.nav_page = "Assessment Workspace"
        st.rerun()

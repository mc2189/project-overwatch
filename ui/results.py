"""Execution result rendering for Project Overwatch."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from modules.module_registry import get_module
from ui.constants import SEVERITY_RANK
from utils.display_format import display_or_unavailable, format_wayback_timestamp
from utils.finding_interpreter import risk_findings, source_notice_findings
from utils.result_status import status_label
from utils.result_summary import summarize_run_results


def _highest_severity(findings: list[dict]) -> str | None:
    best = None
    best_rank = -1
    for finding in findings:
        severity = (finding.get("severity") or "info").lower()
        rank = SEVERITY_RANK.get(severity, 0)
        if rank > best_rank:
            best_rank = rank
            best = severity
    return best


def _render_warnings_block(result: dict) -> None:
    warnings = list(result.get("warnings") or [])
    module_notes = [note for note in (result.get("findings") or []) if note not in warnings]
    if warnings:
        st.markdown("**Warnings**")
        for warning in warnings:
            st.warning(warning)
    if module_notes and not warnings:
        st.markdown("**Module notes**")
        for note in module_notes:
            st.caption(note)


def render_result_summary_tab(result: dict) -> None:
    module = get_module(result["module_id"])
    display_name = module.display_name if module else result["module_id"]
    st.markdown(f"**Module:** {display_name}")
    st.markdown(f"**Status:** {status_label(result.get('status'))}")
    st.write(result.get("summary", ""))
    _render_warnings_block(result)

    parsed_data = result.get("parsed_data") or {}
    if result["module_id"] == "infra_cert_subdomain" and parsed_data:
        subdomains = parsed_data.get("subdomains") or []
        st.write(f"**Certificate names returned:** {len(subdomains)}")
        if parsed_data.get("source"):
            st.caption(f"Source: {parsed_data.get('source')}")
        if parsed_data.get("warning"):
            st.warning(parsed_data["warning"])

    if result["module_id"] == "infra_domain_intel" and parsed_data:
        dns_records = parsed_data.get("dns", {})
        if dns_records:
            st.markdown("**DNS records**")
            for record_type, values in dns_records.items():
                cleaned = [str(value).strip() for value in (values or []) if str(value).strip()]
                if cleaned:
                    st.write(f"- {record_type}: {', '.join(cleaned)}")
                else:
                    st.write(f"- {record_type}: none observed")

        tls = parsed_data.get("tls", {})
        if tls and tls.get("available"):
            st.markdown("**TLS certificate**")
            st.write(
                f"Issuer: {tls.get('issuer')} · Subject: {tls.get('subject')} · "
                f"Valid: {tls.get('not_before')} -> {tls.get('not_after')}"
            )

        wayback = parsed_data.get("wayback", {})
        if wayback:
            first = display_or_unavailable(
                wayback.get("first_snapshot_display")
                or format_wayback_timestamp(wayback.get("first_snapshot"))
            )
            last = display_or_unavailable(
                wayback.get("last_snapshot_display")
                or format_wayback_timestamp(wayback.get("last_snapshot"))
            )
            has_first = bool((wayback.get("first_snapshot") or "").strip()) or bool(
                (wayback.get("first_snapshot_display") or "").strip()
            )
            has_last = bool((wayback.get("last_snapshot") or "").strip()) or bool(
                (wayback.get("last_snapshot_display") or "").strip()
            )
            if wayback.get("available") and has_first and has_last:
                st.markdown("**Wayback Machine**")
                st.write(f"Snapshots available · first observed: {first} · latest snapshot: {last}")
            elif wayback.get("available") and has_first and not has_last:
                st.markdown("**Wayback Machine**")
                st.write(
                    f"Wayback partially available · first observed: {first} · "
                    "latest snapshot unavailable during this run."
                )
            elif wayback.get("available") and not has_first and has_last:
                st.markdown("**Wayback Machine**")
                st.write(
                    f"Wayback partially available · latest snapshot: {last} · "
                    "earliest snapshot unavailable during this run."
                )
            elif wayback.get("available"):
                st.markdown("**Wayback Machine**")
                st.write("Wayback partially available · snapshot details were incomplete during this run.")
            elif wayback.get("error"):
                st.caption(f"Wayback lookup: {wayback['error']}")

    if result["module_id"] == "infra_whois_rdap" and parsed_data:
        if parsed_data.get("private_local_ip"):
            st.info("Private/local IP — public RDAP allocation lookup is not applicable.")
        rdap = parsed_data.get("rdap_summary") or {}
        registrar = rdap.get("registrar") or parsed_data.get("registrar")
        if registrar and (registrar.get("name") or registrar.get("handle")):
            st.markdown(
                f"**Registrar/registry:** {registrar.get('name') or registrar.get('handle')}"
            )
        if rdap.get("status"):
            st.markdown(f"**Status:** {', '.join(rdap['status'])}")
        events = rdap.get("events") or {}
        date_bits = []
        for label, key in (
            ("Created", "registration"),
            ("Updated", "last_changed"),
            ("Expires", "expiration"),
        ):
            if events.get(key):
                date_bits.append(f"{label}: {events[key]}")
        if date_bits:
            st.markdown("**Dates:** " + " · ".join(date_bits))
        if rdap.get("nameservers"):
            st.markdown(f"**Nameservers:** {', '.join(rdap['nameservers'])}")
        if rdap.get("network_name"):
            st.markdown(f"**Network:** {rdap['network_name']}")
        if rdap.get("country"):
            st.markdown(f"**Country:** {rdap['country']}")
        abuse = rdap.get("abuse_contact") or parsed_data.get("abuse_contact")
        if abuse and (abuse.get("email") or abuse.get("name")):
            st.markdown(f"**Abuse/contact:** {abuse.get('email') or abuse.get('name')}")
        if parsed_data.get("warning"):
            st.warning(parsed_data["warning"])

    if result["module_id"] == "infra_website_metadata" and parsed_data:
        homepage = parsed_data.get("homepage") or {}
        if homepage.get("page_title"):
            st.markdown(f"**Page title:** {homepage['page_title']}")
        if homepage.get("meta_description"):
            st.markdown(f"**Meta description:** {homepage['meta_description']}")
        if homepage.get("canonical_url"):
            st.markdown(f"**Canonical URL:** {homepage['canonical_url']}")
        st.write(
            f"**Links / forms:** {homepage.get('link_count', 0)} / {homepage.get('form_count', 0)}"
        )
        robots = parsed_data.get("robots_txt") or {}
        if robots.get("summary"):
            st.markdown(f"**robots.txt:** {robots['summary']}")
        sitemaps = parsed_data.get("sitemap_hints") or {}
        if sitemaps.get("summary"):
            st.markdown(f"**Sitemap hints:** {sitemaps['summary']}")
        if parsed_data.get("warning"):
            st.warning(parsed_data["warning"])


def render_result_interpretation_tab(result: dict) -> None:
    interpreter_findings = result.get("interpreter_findings") or []
    risk = risk_findings(interpreter_findings)
    notices = source_notice_findings(interpreter_findings)
    if not risk and not notices:
        st.caption("No analyst interpretation findings for this module run.")
        return
    st.caption("Advisory defensive analysis only. This is not a definitive vulnerability assessment.")
    if risk:
        st.markdown("**Review findings**")
        for finding in risk:
            severity = finding.get("severity", "info").upper()
            st.markdown(
                f"**[{severity}] {finding.get('title', 'Finding')}** · "
                f"confidence {finding.get('confidence', 0)}"
            )
            st.write(finding.get("explanation", ""))
            for action in finding.get("suggested_actions") or []:
                st.markdown(f"- {action}")
    if notices:
        st.markdown("**Source and lookup notices**")
        st.caption("External lookup limits — informational only, not target risk findings.")
        for finding in notices:
            st.markdown(f"**{finding.get('title', 'Notice')}**")
            st.write(finding.get("explanation", ""))


def render_result_module_output_tab(result: dict) -> None:
    warnings = result.get("warnings") or []
    module_notes = [note for note in (result.get("findings") or []) if note not in warnings]
    if module_notes:
        st.markdown("**Module notes**")
        for note in module_notes:
            st.write(f"- {note}")
    elif not warnings:
        st.caption("No additional module notes.")

    parsed_data = result.get("parsed_data") or {}
    if result["module_id"] == "infra_cert_subdomain":
        subdomains = parsed_data.get("subdomains") or []
        if subdomains:
            st.dataframe(pd.DataFrame({"subdomain": subdomains}), width="stretch", hide_index=True)
        else:
            st.caption("No certificate names were returned in this run.")
        certificates = parsed_data.get("certificates") or []
        if certificates:
            st.markdown("**Certificate references (sample)**")
            cert_rows = [
                {
                    "id": cert.get("id"),
                    "common_name": cert.get("common_name"),
                    "issuer": cert.get("issuer"),
                    "not_before": cert.get("not_before"),
                    "not_after": cert.get("not_after"),
                }
                for cert in certificates[:15]
            ]
            st.dataframe(pd.DataFrame(cert_rows), width="stretch", hide_index=True)

    if result["module_id"] == "infra_whois_rdap" and parsed_data:
        rdap = parsed_data.get("rdap_summary") or {}
        rows: list[dict[str, str]] = []
        for label, key in (
            ("Object class", "object_class"),
            ("Handle", "handle"),
            ("LDH name", "ldh_name"),
            ("Network", "network_name"),
            ("Country", "country"),
        ):
            value = rdap.get(key)
            if value:
                rows.append({"field": label, "value": str(value)})
        events = rdap.get("events") or {}
        for label, key in (
            ("Registration", "registration"),
            ("Last changed", "last_changed"),
            ("Expiration", "expiration"),
        ):
            if events.get(key):
                rows.append({"field": label, "value": events[key]})
        if rdap.get("status"):
            rows.append({"field": "Status", "value": ", ".join(rdap["status"])})
        if rows:
            st.markdown("**RDAP summary**")
            st.dataframe(pd.DataFrame(rows), width="stretch", hide_index=True)
        if rdap.get("nameservers"):
            st.markdown("**Nameservers**")
            st.dataframe(
                pd.DataFrame({"nameserver": rdap["nameservers"]}),
                width="stretch",
                hide_index=True,
            )
        entities = rdap.get("entities") or []
        if entities:
            st.markdown("**RDAP entities (sample)**")
            entity_rows = [
                {
                    "roles": ", ".join(entity.get("roles") or []),
                    "name": entity.get("name"),
                    "email": entity.get("email"),
                    "handle": entity.get("handle"),
                }
                for entity in entities[:10]
            ]
            st.dataframe(pd.DataFrame(entity_rows), width="stretch", hide_index=True)

    if result["module_id"] == "infra_domain_intel" and parsed_data:
        security_headers = parsed_data.get("security_headers", {}).get("https", {})
        if security_headers:
            present = [name for name, meta in security_headers.items() if meta.get("present")]
            missing = [name for name, meta in security_headers.items() if not meta.get("present")]
            st.markdown("**HTTPS security headers**")
            st.write(f"Present: {', '.join(present) if present else '(none)'}")
            st.write(f"Missing: {', '.join(missing) if missing else '(none)'}")

    if result["module_id"] == "infra_website_metadata" and parsed_data:
        homepage = parsed_data.get("homepage") or {}
        headers = homepage.get("basic_headers") or {}
        if headers:
            st.markdown("**Basic response headers**")
            st.dataframe(
                pd.DataFrame([{"header": key, "value": value} for key, value in headers.items()]),
                width="stretch",
                hide_index=True,
            )
        robots = parsed_data.get("robots_txt") or {}
        if robots.get("disallow_rules"):
            st.markdown("**robots.txt disallow rules (sample)**")
            st.dataframe(
                pd.DataFrame({"rule": robots["disallow_rules"][:20]}),
                width="stretch",
                hide_index=True,
            )
        sitemaps = parsed_data.get("sitemap_hints") or {}
        entries = sitemaps.get("entries") or []
        if entries:
            st.markdown("**Sitemap hints**")
            st.dataframe(pd.DataFrame(entries), width="stretch", hide_index=True)


def render_result_raw_tab(result: dict) -> None:
    raw_output = result.get("raw_output")
    if not raw_output:
        st.caption("No raw output captured.")
        return
    language = "bash" if result["module_id"] == "infra_nmap" else "text"
    st.code(raw_output, language=language)


def render_result_structured_tab(result: dict) -> None:
    payload = {
        "selected_options": result.get("selected_options"),
        "parsed_data": result.get("parsed_data"),
        "warnings": result.get("warnings"),
        "errors": result.get("errors"),
    }
    if any(payload.values()):
        st.json(payload)
    else:
        st.caption("No structured data captured.")


def render_result_detail_tabs(result: dict) -> None:
    tab_summary, tab_interp, tab_output, tab_raw, tab_data = st.tabs(
        ["Summary", "Analyst Interpretation", "Module Output", "Raw Output", "Structured Data"]
    )
    with tab_summary:
        render_result_summary_tab(result)
    with tab_interp:
        render_result_interpretation_tab(result)
    with tab_output:
        render_result_module_output_tab(result)
    with tab_raw:
        render_result_raw_tab(result)
    with tab_data:
        render_result_structured_tab(result)


def _render_combined_summary(results: list[dict]) -> None:
    summary = summarize_run_results(results)
    st.markdown("**Combined run summary**")
    cols = st.columns(4)
    cols[0].metric("Modules run", summary["modules_run"])
    cols[1].metric("Completed", summary["completed"])
    cols[2].metric("With warnings", summary["completed_with_warnings"] + summary["partial"])
    cols[3].metric("Failed", summary["failed"])
    st.caption(
        f"Warnings: {summary['warnings_count']} · "
        f"Review findings: {summary['total_findings']} · "
        f"Highest severity: {summary['highest_severity'] or 'none'}"
    )
    if summary["partial"]:
        st.caption(f"Partial results: {summary['partial']}")


def render_latest_results(results: list[dict], *, target: str) -> None:
    if not results:
        return

    st.subheader("Latest Results")
    st.caption(f"Target: `{target}`")
    _render_combined_summary(results)

    for index, result in enumerate(results):
        module = get_module(result["module_id"])
        display_name = module.display_name if module else result["module_id"]
        interpreter_findings = result.get("interpreter_findings") or []
        risk = risk_findings(interpreter_findings)
        highest = _highest_severity(risk)
        run_status = result.get("status", "unknown")

        if run_status == "blocked":
            st.warning(f"**{display_name}** — blocked · {result.get('summary', '')}")
            continue
        if run_status == "error" or not result.get("success"):
            st.error(f"**{display_name}** — error · {result.get('summary', '')}")
            with st.expander(f"{display_name} details", expanded=False):
                render_result_detail_tabs(result)
            continue

        summary_bits = [
            f"**{display_name}**",
            f"status: {status_label(run_status)}",
            f"findings: {len(risk)}",
        ]
        warning_count = len(result.get("warnings") or [])
        if warning_count:
            summary_bits.append(f"warnings: {warning_count}")
        if highest:
            summary_bits.append(f"highest severity: {highest}")
        st.markdown(" · ".join(summary_bits))
        st.write(result.get("summary", ""))

        with st.expander(f"View {display_name} result details", expanded=index == 0):
            render_result_detail_tabs(result)

    st.divider()

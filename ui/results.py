"""Execution result rendering for Project Overwatch."""

from __future__ import annotations

import pandas as pd
import streamlit as st

from modules.module_registry import get_module
from ui.constants import SEVERITY_RANK


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


def render_result_summary_tab(result: dict) -> None:
    module = get_module(result["module_id"])
    display_name = module.display_name if module else result["module_id"]
    st.markdown(f"**Module:** {display_name}")
    st.markdown(f"**Status:** {result.get('status', 'unknown')}")
    st.write(result.get("summary", ""))

    parsed_data = result.get("parsed_data") or {}
    if result["module_id"] == "infra_cert_subdomain" and parsed_data:
        subdomains = parsed_data.get("subdomains") or []
        st.write(f"**Subdomains discovered:** {len(subdomains)}")
        if parsed_data.get("source"):
            st.caption(f"Source: {parsed_data.get('source')}")
        if parsed_data.get("warning"):
            st.warning(parsed_data["warning"])

    if result["module_id"] == "infra_domain_intel" and parsed_data:
        dns_records = parsed_data.get("dns", {})
        if dns_records:
            st.markdown("**DNS records**")
            for record_type, values in dns_records.items():
                if values:
                    st.write(f"- {record_type}: {', '.join(values)}")

        tls = parsed_data.get("tls", {})
        if tls and tls.get("available"):
            st.markdown("**TLS certificate**")
            st.write(
                f"Issuer: {tls.get('issuer')} · Subject: {tls.get('subject')} · "
                f"Valid: {tls.get('not_before')} -> {tls.get('not_after')}"
            )

        wayback = parsed_data.get("wayback", {})
        if wayback and wayback.get("available"):
            st.markdown("**Wayback Machine**")
            st.write(
                f"Snapshots available · first={wayback.get('first_snapshot')} · "
                f"last={wayback.get('last_snapshot')}"
            )

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
    if not interpreter_findings:
        st.caption("No analyst interpretation findings for this module run.")
        return
    st.caption("Advisory defensive analysis only. This is not a definitive vulnerability assessment.")
    for finding in interpreter_findings:
        severity = finding.get("severity", "info").upper()
        st.markdown(f"**[{severity}] {finding.get('title', 'Finding')}** · confidence {finding.get('confidence', 0)}")
        st.write(finding.get("explanation", ""))
        for action in finding.get("suggested_actions") or []:
            st.markdown(f"- {action}")


def render_result_module_output_tab(result: dict) -> None:
    module_notes = result.get("findings") or []
    if not module_notes:
        st.caption("No additional module notes.")
        return
    for note in module_notes:
        st.write(f"- {note}")

    parsed_data = result.get("parsed_data") or {}
    if result["module_id"] == "infra_cert_subdomain":
        subdomains = parsed_data.get("subdomains") or []
        if subdomains:
            st.dataframe(pd.DataFrame({"subdomain": subdomains}), width="stretch", hide_index=True)
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


def render_latest_results(results: list[dict], *, target: str) -> None:
    if not results:
        return

    st.subheader("Latest Results")
    st.caption(f"Target: `{target}`")

    for index, result in enumerate(results):
        module = get_module(result["module_id"])
        display_name = module.display_name if module else result["module_id"]
        interpreter_findings = result.get("interpreter_findings") or []
        highest = _highest_severity(interpreter_findings)

        if result["status"] == "blocked":
            st.warning(f"**{display_name}** — blocked · {result.get('summary', '')}")
            continue
        if result["status"] == "error" or not result.get("success"):
            st.error(f"**{display_name}** — error · {result.get('summary', '')}")
            with st.expander(f"{display_name} details", expanded=False):
                render_result_detail_tabs(result)
            continue

        summary_bits = [
            f"**{display_name}**",
            f"status: {result.get('status', 'completed')}",
            f"findings: {len(interpreter_findings)}",
        ]
        if highest:
            summary_bits.append(f"highest severity: {highest}")
        st.markdown(" · ".join(summary_bits))
        st.write(result.get("summary", ""))

        with st.expander(f"View {display_name} result details", expanded=index == 0):
            render_result_detail_tabs(result)

    st.divider()

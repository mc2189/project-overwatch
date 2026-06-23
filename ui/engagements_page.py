"""Client engagement, scope, and rules-of-engagement management UI."""

from __future__ import annotations

import streamlit as st

from database.db_setup import list_cases
from database.engagements import (
    ENGAGEMENT_STATUSES,
    ENGAGEMENT_TYPES,
    PERMITTED_TESTING_LEVELS,
    SCOPE_ASSET_TYPES,
    SCOPE_STATUSES,
    add_scope_item,
    create_engagement,
    default_roe_payload,
    delete_scope_item,
    get_engagement,
    get_roe,
    link_case_to_engagement,
    list_engagements,
    list_scope_items,
    update_engagement,
    update_scope_item,
    upsert_roe,
)


def _roe_bool_fields() -> list[tuple[str, str]]:
    return [
        ("active_scanning_allowed", "Active scanning allowed"),
        ("intrusive_testing_allowed", "Intrusive testing allowed"),
        ("denial_of_service_allowed", "Denial-of-service testing allowed"),
        ("credential_testing_allowed", "Credential testing allowed"),
        ("social_engineering_allowed", "Social engineering allowed"),
        ("malware_handling_allowed", "Malware handling allowed"),
    ]


def render_engagements_page(current_case: dict) -> None:
    st.title("Client Engagements")
    st.caption(
        "Document client authorisation, scope, and rules of engagement before active or intrusive testing. "
        "Passive OSINT modules may run without an engagement, but active modules require controls."
    )

    engagements = list_engagements()
    engagement_labels = {eng["id"]: f"{eng['name']} — {eng.get('client_name') or 'No client'} ({eng['status']})" for eng in engagements}
    label_to_id = {label: eng_id for eng_id, label in engagement_labels.items()}

    tab_list, tab_create, tab_link = st.tabs(["Engagements", "Create engagement", "Link case"])

    with tab_create:
        st.markdown("### Create engagement")
        with st.form("create_engagement_form"):
            name = st.text_input("Engagement name", placeholder="Acme Corp Q2 External Review")
            client_name = st.text_input("Client name")
            engagement_type = st.selectbox("Engagement type", ENGAGEMENT_TYPES)
            col1, col2 = st.columns(2)
            with col1:
                start_date = st.text_input("Start date (YYYY-MM-DD)", placeholder="2026-06-01")
            with col2:
                end_date = st.text_input("End date (YYYY-MM-DD)", placeholder="2026-06-30")
            status = st.selectbox("Status", ENGAGEMENT_STATUSES, index=0)
            primary_contact = st.text_input("Primary contact")
            emergency_contact = st.text_input("Emergency contact")
            authorisation_reference = st.text_input("Authorisation reference")
            sow_reference = st.text_input("Statement of work reference")
            notes = st.text_area("Notes")
            if st.form_submit_button("Create engagement", type="primary"):
                if not name.strip():
                    st.error("Engagement name is required.")
                else:
                    created = create_engagement(
                        name=name,
                        client_name=client_name,
                        engagement_type=engagement_type,
                        start_date=start_date,
                        end_date=end_date,
                        status=status,
                        primary_contact=primary_contact,
                        emergency_contact=emergency_contact,
                        authorisation_reference=authorisation_reference,
                        statement_of_work_reference=sow_reference,
                        notes=notes,
                    )
                    st.success(f"Created engagement #{created.get('id')} — {created.get('name')}")
                    st.rerun()

    with tab_link:
        st.markdown("### Link case to engagement")
        cases = list_cases()
        case_options = {case["id"]: f"{case['name']} (#{case['id']})" for case in cases}
        selected_case_id = st.selectbox(
            "Case",
            options=list(case_options.keys()),
            format_func=lambda cid: case_options[cid],
            index=list(case_options.keys()).index(current_case["id"])
            if current_case["id"] in case_options
            else 0,
        )
        engagement_choice = st.selectbox(
            "Engagement",
            options=[None, *engagement_labels.keys()],
            format_func=lambda eid: "— No engagement —" if eid is None else engagement_labels[eid],
        )
        if st.button("Save case link", type="primary"):
            link_case_to_engagement(int(selected_case_id), engagement_choice)
            st.success("Case engagement link updated.")
            st.rerun()

    with tab_list:
        if not engagements:
            st.info("No engagements recorded yet. Create one in the Create engagement tab.")
            return

        selected_label = st.selectbox(
            "Select engagement",
            options=list(label_to_id.keys()),
            key="engagement_selector",
        )
        engagement_id = label_to_id[selected_label]
        engagement = get_engagement(engagement_id) or {}
        roe = get_roe(engagement_id)
        scope_items = list_scope_items(engagement_id)

        st.markdown(f"### {engagement.get('name')}")
        st.caption(
            f"Client: {engagement.get('client_name') or '—'} · Type: {engagement.get('engagement_type') or '—'} · "
            f"Status: **{engagement.get('status')}**"
        )

        emergency_stop = bool(engagement.get("emergency_stop_active"))
        if emergency_stop:
            st.error("Emergency stop is ACTIVE — active/intrusive modules are blocked for this engagement.")
        col_a, col_b = st.columns(2)
        with col_a:
            if st.button("Enable emergency stop", disabled=emergency_stop):
                update_engagement(engagement_id, {"emergency_stop_active": True})
                st.rerun()
        with col_b:
            if st.button("Clear emergency stop", disabled=not emergency_stop):
                update_engagement(engagement_id, {"emergency_stop_active": False})
                st.rerun()

        with st.expander("Edit engagement details", expanded=False):
            with st.form("edit_engagement_form"):
                name = st.text_input("Engagement name", value=engagement.get("name") or "")
                client_name = st.text_input("Client name", value=engagement.get("client_name") or "")
                engagement_type = st.selectbox(
                    "Engagement type",
                    ENGAGEMENT_TYPES,
                    index=ENGAGEMENT_TYPES.index(engagement.get("engagement_type"))
                    if engagement.get("engagement_type") in ENGAGEMENT_TYPES
                    else 0,
                )
                c1, c2 = st.columns(2)
                with c1:
                    start_date = st.text_input("Start date", value=engagement.get("start_date") or "")
                with c2:
                    end_date = st.text_input("End date", value=engagement.get("end_date") or "")
                status = st.selectbox(
                    "Status",
                    ENGAGEMENT_STATUSES,
                    index=ENGAGEMENT_STATUSES.index(engagement.get("status"))
                    if engagement.get("status") in ENGAGEMENT_STATUSES
                    else 0,
                )
                primary_contact = st.text_input("Primary contact", value=engagement.get("primary_contact") or "")
                emergency_contact = st.text_input("Emergency contact", value=engagement.get("emergency_contact") or "")
                authorisation_reference = st.text_input(
                    "Authorisation reference",
                    value=engagement.get("authorisation_reference") or "",
                )
                sow_reference = st.text_input(
                    "Statement of work reference",
                    value=engagement.get("statement_of_work_reference") or "",
                )
                notes = st.text_area("Notes", value=engagement.get("notes") or "")
                if st.form_submit_button("Save engagement"):
                    update_engagement(
                        engagement_id,
                        {
                            "name": name,
                            "client_name": client_name,
                            "engagement_type": engagement_type,
                            "start_date": start_date,
                            "end_date": end_date,
                            "status": status,
                            "primary_contact": primary_contact,
                            "emergency_contact": emergency_contact,
                            "authorisation_reference": authorisation_reference,
                            "statement_of_work_reference": sow_reference,
                            "notes": notes,
                        },
                    )
                    st.success("Engagement updated.")
                    st.rerun()

        st.markdown("#### Rules of engagement")
        defaults = default_roe_payload()
        with st.form("roe_form"):
            permitted_test_windows = st.text_area(
                "Permitted test windows",
                value=roe.get("permitted_test_windows") or "",
            )
            prohibited_actions = st.text_area(
                "Prohibited actions",
                value=roe.get("prohibited_actions") or defaults["prohibited_actions"],
            )
            rate_limits = st.text_area("Rate limits", value=roe.get("rate_limits") or defaults["rate_limits"])
            maximum_request_rate = st.number_input(
                "Maximum request rate (optional)",
                min_value=0,
                value=int(roe.get("maximum_request_rate") or 0),
                step=1,
            )
            bool_values: dict[str, bool] = {}
            for key, label in _roe_bool_fields():
                bool_values[key] = st.checkbox(label, value=bool(roe.get(key)))
            client_notification_requirements = st.text_area(
                "Client notification requirements",
                value=roe.get("client_notification_requirements") or "",
            )
            emergency_stop_procedure = st.text_area(
                "Emergency stop procedure",
                value=roe.get("emergency_stop_procedure") or defaults["emergency_stop_procedure"],
            )
            evidence_handling_notes = st.text_area(
                "Evidence handling notes",
                value=roe.get("evidence_handling_notes") or defaults["evidence_handling_notes"],
            )
            data_retention_notes = st.text_area(
                "Data retention notes",
                value=roe.get("data_retention_notes") or "",
            )
            if st.form_submit_button("Save rules of engagement"):
                upsert_roe(
                    engagement_id,
                    {
                        "permitted_test_windows": permitted_test_windows,
                        "prohibited_actions": prohibited_actions,
                        "rate_limits": rate_limits,
                        "maximum_request_rate": maximum_request_rate or None,
                        **bool_values,
                        "client_notification_requirements": client_notification_requirements,
                        "emergency_stop_procedure": emergency_stop_procedure,
                        "evidence_handling_notes": evidence_handling_notes,
                        "data_retention_notes": data_retention_notes,
                    },
                )
                st.success("Rules of engagement saved.")
                st.rerun()

        st.markdown("#### Scope assets")
        if scope_items:
            st.dataframe(
                [
                    {
                        "id": item["id"],
                        "asset": item["asset_value"],
                        "type": item["asset_type"],
                        "status": item["scope_status"],
                        "permitted level": item["permitted_testing_level"],
                        "notes": item.get("notes") or "",
                    }
                    for item in scope_items
                ],
                width="stretch",
                hide_index=True,
            )
        else:
            st.caption("No scope assets recorded.")

        with st.form("add_scope_form"):
            st.markdown("**Add scope asset**")
            asset_value = st.text_input("Asset value", placeholder="example.com")
            asset_type = st.selectbox("Asset type", SCOPE_ASSET_TYPES)
            scope_status = st.selectbox("Scope status", SCOPE_STATUSES)
            permitted_testing_level = st.selectbox("Permitted testing level", PERMITTED_TESTING_LEVELS)
            scope_notes = st.text_input("Notes")
            if st.form_submit_button("Add scope asset"):
                if not asset_value.strip():
                    st.error("Asset value is required.")
                else:
                    add_scope_item(
                        engagement_id,
                        asset_value=asset_value,
                        asset_type=asset_type,
                        scope_status=scope_status,
                        permitted_testing_level=permitted_testing_level,
                        notes=scope_notes,
                    )
                    st.success("Scope asset added.")
                    st.rerun()

        if scope_items:
            st.markdown("**Update scope asset**")
            scope_ids = {f"{item['asset_value']} ({item['asset_type']})": item["id"] for item in scope_items}
            selected_scope_label = st.selectbox("Scope item", options=list(scope_ids.keys()))
            scope_id = scope_ids[selected_scope_label]
            current = next(item for item in scope_items if item["id"] == scope_id)
            with st.form("update_scope_form"):
                new_status = st.selectbox(
                    "Scope status",
                    SCOPE_STATUSES,
                    index=SCOPE_STATUSES.index(current.get("scope_status"))
                    if current.get("scope_status") in SCOPE_STATUSES
                    else 0,
                )
                new_level = st.selectbox(
                    "Permitted testing level",
                    PERMITTED_TESTING_LEVELS,
                    index=PERMITTED_TESTING_LEVELS.index(current.get("permitted_testing_level"))
                    if current.get("permitted_testing_level") in PERMITTED_TESTING_LEVELS
                    else 0,
                )
                new_notes = st.text_input("Notes", value=current.get("notes") or "")
                c1, c2 = st.columns(2)
                with c1:
                    save_scope = st.form_submit_button("Save scope item")
                with c2:
                    delete_scope = st.form_submit_button("Delete scope item")
                if save_scope:
                    update_scope_item(
                        scope_id,
                        {
                            "scope_status": new_status,
                            "permitted_testing_level": new_level,
                            "notes": new_notes,
                        },
                    )
                    st.success("Scope item updated.")
                    st.rerun()
                if delete_scope:
                    delete_scope_item(scope_id)
                    st.success("Scope item deleted.")
                    st.rerun()

        st.markdown("#### ROE summary")
        st.write(
            f"Active scanning: {'allowed' if roe.get('active_scanning_allowed') else 'not allowed'} · "
            f"Intrusive testing: {'allowed' if roe.get('intrusive_testing_allowed') else 'not allowed'} · "
            f"DoS: {'allowed' if roe.get('denial_of_service_allowed') else 'not allowed (default)'}"
        )

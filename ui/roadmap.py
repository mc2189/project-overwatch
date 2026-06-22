"""Planned modules roadmap page for Project Overwatch."""

from __future__ import annotations

import streamlit as st

from modules.module_registry import CATEGORIES, MODULES, is_executable
from utils.module_compatibility import module_detailed_help, module_short_help


def render_roadmap_page() -> None:
    st.title("Roadmap")
    st.caption(
        "Planned collection and analysis modules registered for future releases. "
        "Only implemented modules appear on the Run Operation page."
    )

    planned = [module for module in MODULES if not is_executable(module)]
    if not planned:
        st.info("No planned modules are registered.")
        return

    for category in CATEGORIES:
        category_key = str(category["key"])
        category_label = str(category["label"])
        category_modules = [module for module in planned if module.category == category_key]
        if not category_modules:
            continue
        with st.expander(category_label, expanded=False):
            for module in category_modules:
                st.markdown(
                    f"**{module.display_name}** · {module.mode.title()} · "
                    f"{module.risk_level.title()} risk · Status: {module.status}"
                )
                st.write(module_short_help(module))
                st.caption(module_detailed_help(module))
                if module.accepted_target_types:
                    st.caption(
                        "Planned target types: "
                        + ", ".join(module.accepted_target_types)
                    )
                st.divider()

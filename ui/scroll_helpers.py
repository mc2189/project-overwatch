"""Lightweight scroll helpers for Streamlit pages."""

from __future__ import annotations

import streamlit.components.v1 as components


def scroll_to_anchor(anchor_id: str) -> None:
    """Scroll the parent frame to an element id (best-effort in Streamlit)."""
    components.html(
        f"""
        <script>
            const parent = window.parent.document;
            const el = parent.getElementById("{anchor_id}");
            if (el) {{
                el.scrollIntoView({{ behavior: "smooth", block: "start" }});
            }}
        </script>
        """,
        height=0,
    )

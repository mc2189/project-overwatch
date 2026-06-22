"""Simple entity relationship graph rendering for Streamlit."""

from __future__ import annotations

from typing import Any

import networkx as nx
import plotly.graph_objects as go

from database.db_setup import effective_finding_severity, normalize_finding_status

SEVERITY_ORDER = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
SEVERITY_COLORS = {
    "critical": "#d62728",
    "high": "#ff7f0e",
    "medium": "#bcbd22",
    "low": "#aec7e8",
    "info": "#1f77b4",
    "none": "#cccccc",
}


def entity_max_severity(
    findings: list[dict[str, Any]],
    *,
    statuses: tuple[str, ...] = ("open", "in_review", "action_required"),
) -> dict[int, str]:
    """Map entity IDs to their highest active finding severity."""
    entity_severity: dict[int, str] = {}
    for finding in findings:
        status = normalize_finding_status(finding.get("status"))
        if status not in statuses:
            continue
        entity_id = finding.get("entity_id")
        if entity_id is None:
            continue
        severity = effective_finding_severity(finding)
        current = entity_severity.get(entity_id, "none")
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(current, 0):
            entity_severity[entity_id] = severity
    return entity_severity


def build_entity_graph(
    entities: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
) -> nx.Graph:
    """Build a NetworkX graph from stored entities and relationships."""
    graph = nx.Graph()
    entity_ids = {entity["id"] for entity in entities}

    for entity in entities:
        label = entity.get("label") or entity.get("value") or str(entity["id"])
        graph.add_node(
            entity["id"],
            label=label,
            entity_type=entity.get("entity_type", "unknown"),
        )

    for relationship in relationships:
        source_id = relationship["source_entity_id"]
        target_id = relationship["target_entity_id"]
        if source_id not in entity_ids or target_id not in entity_ids:
            continue
        graph.add_edge(
            source_id,
            target_id,
            relationship_type=relationship["relationship_type"],
        )

    return graph


def entity_graph_figure(
    entities: list[dict[str, Any]],
    relationships: list[dict[str, Any]],
    findings: list[dict[str, Any]] | None = None,
) -> go.Figure | None:
    """Create a simple Plotly figure for the entity graph."""
    graph = build_entity_graph(entities, relationships)
    if graph.number_of_nodes() == 0:
        return None

    severity_by_entity = entity_max_severity(findings or [])
    labels = nx.get_node_attributes(graph, "label")
    positions = nx.spring_layout(graph, seed=42)

    edge_x: list[float | None] = []
    edge_y: list[float | None] = []

    for source_id, target_id, _edge_data in graph.edges(data=True):
        x0, y0 = positions[source_id]
        x1, y1 = positions[target_id]
        edge_x.extend([x0, x1, None])
        edge_y.extend([y0, y1, None])

    edge_trace = go.Scatter(
        x=edge_x,
        y=edge_y,
        mode="lines",
        line={"width": 1.5, "color": "#888888"},
        hoverinfo="none",
        name="Relationships",
    )

    node_x: list[float] = []
    node_y: list[float] = []
    node_labels: list[str] = []
    node_hover: list[str] = []
    node_colors: list[str] = []

    for node_id in graph.nodes():
        x, y = positions[node_id]
        node_x.append(x)
        node_y.append(y)
        node_labels.append(labels.get(node_id, str(node_id)))
        node_type = graph.nodes[node_id].get("entity_type", "unknown")
        severity = severity_by_entity.get(node_id, "none")
        severity_label = severity if severity != "none" else "no open findings"
        node_hover.append(
            f"{labels.get(node_id, node_id)}<br>type: {node_type}<br>"
            f"finding severity: {severity_label}<br>id: {node_id}"
        )
        node_colors.append(SEVERITY_COLORS.get(severity, SEVERITY_COLORS["none"]))

    node_trace = go.Scatter(
        x=node_x,
        y=node_y,
        mode="markers+text",
        text=node_labels,
        textposition="top center",
        hovertext=node_hover,
        hoverinfo="text",
        marker={"size": 18, "color": node_colors, "line": {"width": 1, "color": "#ffffff"}},
        name="Entities",
    )

    figure = go.Figure(data=[edge_trace, node_trace])
    figure.update_layout(
        title="Entity Relationship Graph",
        showlegend=False,
        hovermode="closest",
        margin={"l": 20, "r": 20, "t": 40, "b": 20},
        xaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
        yaxis={"showgrid": False, "zeroline": False, "showticklabels": False},
        plot_bgcolor="#ffffff",
    )

    relationship_types = sorted(
        {data.get("relationship_type", "related") for _, _, data in graph.edges(data=True)}
    )
    annotations = []
    if relationship_types:
        annotations.append(
            dict(
                text="Edge types: " + ", ".join(relationship_types),
                xref="paper",
                yref="paper",
                x=0,
                y=-0.08,
                showarrow=False,
                font={"size": 11, "color": "#666666"},
            )
        )
    annotations.append(
        dict(
            text="Node colour: highest open/reviewed finding severity (grey = none)",
            xref="paper",
            yref="paper",
            x=0,
            y=-0.14,
            showarrow=False,
            font={"size": 11, "color": "#666666"},
        )
    )
    figure.update_layout(annotations=annotations)

    return figure

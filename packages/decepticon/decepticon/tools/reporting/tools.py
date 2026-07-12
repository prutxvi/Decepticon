# -*- coding: utf-8 -*-
"""LangChain @tool wrappers for the reporting package.

The reporting tools read the engagement KG that ``KGMiddleware`` and
``kg_record`` / ``kg_ingest`` write to (the post-#545 backend) — they
no longer use the legacy ``tools/research/_state`` shim. The
engagement label is resolved from the ``EngagementContextMiddleware``
contextvar; if it is not set (e.g. agent invoked outside the standard
middleware stack), every report tool returns the structure for an
empty graph and the agent can recover.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from langchain_core.tools import tool

from decepticon.tools.reporting.bugcrowd import render_bugcrowd_csv
from decepticon.tools.reporting.executive import render_executive_summary
from decepticon.tools.reporting.hackerone import render_hackerone_markdown
from decepticon.tools.reporting.kg_adapter import load_engagement_graph
from decepticon.tools.reporting.sarif import render_sarif
from decepticon.tools.reporting.timeline import extract_timeline
from decepticon_core.types.kg import KnowledgeGraph
from decepticon_core.utils.engagement_scope import get_active_engagement


def _load() -> tuple[KnowledgeGraph, None]:
    """Load the engagement KG for reporting.

    Reads the engagement label from the contextvar
    (``EngagementContextMiddleware`` sets it for every tool dispatch).
    Returns an empty graph when no engagement is active so the renderer
    sees a well-formed (but empty) shape.

    Kept under this name so the existing ``mock.patch(
    "decepticon.tools.reporting.tools._load", ...)`` test surface
    continues to work — only the implementation changed.
    """
    engagement = get_active_engagement()
    if not engagement:
        return KnowledgeGraph(), None
    return load_engagement_graph(engagement), None


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)


@tool
def report_hackerone(finding_id: str) -> str:
    """Render a HackerOne-style markdown report for a finding or vulnerability node."""
    graph, _ = _load()
    node = graph.nodes.get(finding_id)
    if node is None:
        return _json({"error": f"no node {finding_id} in graph"})
    md = render_hackerone_markdown(node, graph=graph)
    return _json({"id": finding_id, "markdown": md})


@tool
def report_bugcrowd_csv(min_severity: str = "medium") -> str:
    """Render the current graph as a Bugcrowd CSV submission bundle."""
    graph, _ = _load()
    csv = render_bugcrowd_csv(graph, min_severity=min_severity)
    return _json({"rows": csv.count("\n") - 1, "csv": csv})


@tool
def report_executive(engagement_name: str = "Engagement") -> str:
    """Produce an engagement-level executive summary from the graph."""
    graph, _ = _load()
    md = render_executive_summary(graph, engagement_name=engagement_name)
    return _json({"markdown": md})


@tool
def report_timeline() -> str:
    """Extract a chronological timeline of graph events."""
    graph, _ = _load()
    events = extract_timeline(graph)
    return _json({"count": len(events), "events": [e.to_dict() for e in events]})


@tool
def report_sarif(engagement_id: str, output_path: str) -> str:
    """Render the engagement graph as SARIF v2.1.0 JSON for GitHub code scanning / DefectDojo / SARIF aggregators.

    Writes UTF-8 to ``output_path`` (parent directories are created) and
    returns a JSON summary with the engagement id, written path, byte
    count, and number of result entries emitted.
    """
    graph, _ = _load()
    sarif = render_sarif(graph, engagement_id=engagement_id)
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(sarif, encoding="utf-8")
    payload = json.loads(sarif)
    results = payload["runs"][0]["results"]
    return _json(
        {
            "engagement_id": engagement_id,
            "path": str(path),
            "bytes": len(sarif.encode("utf-8")),
            "results": len(results),
        }
    )


REPORTING_TOOLS = [
    report_hackerone,
    report_bugcrowd_csv,
    report_executive,
    report_timeline,
    report_sarif,
]

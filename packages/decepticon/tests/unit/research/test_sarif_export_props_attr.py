"""test_sarif_export_props_attr module."""

from __future__ import annotations

from decepticon.tools.research.sarif_export import (
    export_findings_to_sarif,
    severity_threshold_breach,
)
from decepticon_core.types.kg import KnowledgeGraph, Node, NodeKind


def _real_finding_node(severity: str, vuln_class: str = "sqli") -> Node:
    return Node.make(
        NodeKind.FINDING,
        "SQL injection in login endpoint",
        severity=severity,
        vuln_class=vuln_class,
        description="Unsanitized user input passed to query",
        file="src/auth.py",
        start_line=42,
    )


def _graph_with(*nodes: Node) -> KnowledgeGraph:
    kg = KnowledgeGraph()
    for n in nodes:
        kg.upsert_node(n)
    return kg


def test_real_node_props_attr_severity_flows_through():
    node = _real_finding_node("critical")
    assert not hasattr(node, "properties"), "Node must not have a .properties attribute"
    kg = _graph_with(node)
    doc = export_findings_to_sarif(kg)
    result = doc["runs"][0]["results"][0]
    assert result["level"] == "error", f"expected error for critical, got {result['level']}"
    assert result["properties"]["security-severity"] == "10.0"


def test_real_node_high_severity_triggers_ci_gate():
    node = _real_finding_node("high")
    kg = _graph_with(node)
    doc = export_findings_to_sarif(kg)
    assert severity_threshold_breach(doc, fail_on="high"), (
        "CI gate must fire for a real Finding node with severity=high"
    )


def test_real_node_medium_does_not_trigger_high_gate():
    node = _real_finding_node("medium")
    kg = _graph_with(node)
    doc = export_findings_to_sarif(kg)
    assert not severity_threshold_breach(doc, fail_on="high"), (
        "CI gate must not fire for medium severity"
    )


def test_real_node_location_extracted_from_props():
    node = _real_finding_node("high")
    kg = _graph_with(node)
    doc = export_findings_to_sarif(kg)
    result = doc["runs"][0]["results"][0]
    assert "locations" in result, "location from node.props must appear in SARIF result"
    loc = result["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "src/auth.py"
    assert loc["region"]["startLine"] == 42

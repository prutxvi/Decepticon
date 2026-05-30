from __future__ import annotations

import pytest

from decepticon.tools.reporting.hackerone import HackerOneReport, render_hackerone_markdown
from decepticon_core.types.kg import Edge, EdgeKind, KnowledgeGraph, Node, NodeKind


class TestHackerOneReportToMarkdown:
    def test_no_cvss_score_omits_cvss_line(self) -> None:
        r = HackerOneReport(title="T", severity="high", cvss_score=None)
        md = r.to_markdown()
        assert "**CVSS:**" not in md
        assert "**Severity:** HIGH" in md

    def test_empty_steps_produces_no_steps_recorded(self) -> None:
        r = HackerOneReport(title="T", severity="medium", steps=[])
        md = r.to_markdown()
        assert "_(no steps recorded)_" in md
        assert "1." not in md

    def test_empty_poc_produces_attach_placeholder(self) -> None:
        r = HackerOneReport(title="T", severity="low", poc="")
        md = r.to_markdown()
        assert "(attach PoC script or request)" in md

    def test_empty_summary_impact_remediation_produce_pending_placeholders(self) -> None:
        r = HackerOneReport(title="T", severity="high", summary="", impact="", remediation="")
        md = r.to_markdown()
        assert md.count("_(pending)_") == 3

    def test_references_list_present_renders_references_section(self) -> None:
        r = HackerOneReport(title="T", severity="high", references=["https://a", "https://b"])
        md = r.to_markdown()
        assert "## References" in md
        assert "- https://a" in md
        assert "- https://b" in md

    def test_empty_references_omits_references_section(self) -> None:
        r = HackerOneReport(title="T", severity="high", references=[])
        md = r.to_markdown()
        assert "## References" not in md

    def test_chain_id_present_renders_footer(self) -> None:
        r = HackerOneReport(title="T", severity="high", chain_id="abc123")
        md = r.to_markdown()
        assert "_Chain ID: abc123_" in md

    def test_chain_id_none_omits_footer(self) -> None:
        r = HackerOneReport(title="T", severity="high", chain_id=None)
        md = r.to_markdown()
        assert "_Chain ID" not in md


class TestRenderHackeroneMarkdown:
    def test_title_and_severity_fallbacks_when_missing_from_props(self) -> None:
        g = KnowledgeGraph()
        node = Node.make(NodeKind.FINDING, "Bare Finding")
        g.upsert_node(node)
        md = render_hackerone_markdown(node, graph=g)
        assert "# Bare Finding" in md
        assert "**Severity:** MEDIUM" in md

    def test_summary_from_description_and_poc_from_stdout_excerpt(self) -> None:
        g = KnowledgeGraph()
        node = Node.make(
            NodeKind.VULNERABILITY,
            "V",
            description="desc text",
            stdout_excerpt="boom output",
            severity="high",
        )
        g.upsert_node(node)
        md = render_hackerone_markdown(node, graph=g)
        assert "desc text" in md
        assert "boom output" in md

    @pytest.mark.parametrize(
        "severity,expected_fragment",
        [
            ("critical", "Unauthenticated remote compromise"),
            ("high", "Significant unauthorised access"),
            ("medium", "Limited unauthorised access"),
            ("low", "Minor information disclosure"),
            ("info", "Informational; no direct security impact."),
        ],
    )
    def test_derived_impact_per_severity(self, severity: str, expected_fragment: str) -> None:
        g = KnowledgeGraph()
        node = Node.make(NodeKind.VULNERABILITY, "V", severity=severity)
        g.upsert_node(node)
        md = render_hackerone_markdown(node, graph=g)
        assert expected_fragment in md

    def test_unknown_severity_uses_default_impact(self) -> None:
        g = KnowledgeGraph()
        node = Node.make(NodeKind.VULNERABILITY, "V", severity="bogus")
        g.upsert_node(node)
        md = render_hackerone_markdown(node, graph=g)
        assert "See details." in md

    def test_non_numeric_cvss_score_rejected_no_cvss_line(self) -> None:
        g = KnowledgeGraph()
        node = Node.make(NodeKind.VULNERABILITY, "V", severity="high", cvss_score="not-a-number")
        g.upsert_node(node)
        md = render_hackerone_markdown(node, graph=g)
        assert "**CVSS:**" not in md

    def test_numeric_cvss_score_renders(self) -> None:
        g = KnowledgeGraph()
        node = Node.make(
            NodeKind.VULNERABILITY,
            "V",
            severity="high",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/AV:N",
        )
        g.upsert_node(node)
        md = render_hackerone_markdown(node, graph=g)
        assert "**CVSS:** 7.5" in md

    def test_references_str_coercion(self) -> None:
        g = KnowledgeGraph()
        node = Node.make(
            NodeKind.VULNERABILITY,
            "V",
            severity="medium",
            references=[123, {"url": "x"}],
        )
        g.upsert_node(node)
        md = render_hackerone_markdown(node, graph=g)
        assert "- 123" in md
        assert "- " + str({"url": "x"}) in md

    def test_explicit_steps_prop_wins_over_auto_build(self) -> None:
        g = KnowledgeGraph()
        node = Node.make(
            NodeKind.VULNERABILITY,
            "V",
            severity="high",
            steps=["manual step one"],
            poc="curl ...",
        )
        g.upsert_node(node)
        md = render_hackerone_markdown(node, graph=g)
        assert "1. manual step one" in md
        assert "Run the PoC" not in md

    def test_chain_edge_loop_executes_but_chain_id_stays_none_for_attack_path(self) -> None:
        g = KnowledgeGraph()
        finding = Node.make(NodeKind.FINDING, "F", severity="high")
        attack_path = Node.make(NodeKind.ATTACK_PATH, "some attack path")
        g.upsert_node(finding)
        g.upsert_node(attack_path)
        edge = Edge.make(attack_path.id, finding.id, EdgeKind.STEP)
        g.upsert_edge(edge)
        md = render_hackerone_markdown(finding, graph=g)
        assert "_Chain ID" not in md

    def test_edge_with_dangling_src_does_not_crash_and_chain_id_stays_none(self) -> None:
        g = KnowledgeGraph()
        finding = Node.make(NodeKind.FINDING, "F", severity="medium")
        g.upsert_node(finding)
        edge = Edge.make("missing-src-id", finding.id, EdgeKind.STEP)
        g.upsert_edge(edge)
        md = render_hackerone_markdown(finding, graph=g)
        assert "_Chain ID" not in md
        assert "# F" in md

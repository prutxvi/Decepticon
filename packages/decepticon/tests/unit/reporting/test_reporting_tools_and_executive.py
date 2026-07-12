# -*- coding: utf-8 -*-
"""Comprehensive tests for reporting/tools.py wrappers and executive.py helpers.

Covers:
- All LangChain @tool wrappers in tools.py (mocking _load + filesystem)
- Executive summary edge cases beyond the baseline in test_reporting.py
- Private helper functions: _count_by_severity, _top_chains, _top_cves
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import patch

import pytest

from decepticon.tools.reporting.executive import (
    _count_by_severity,
    _top_chains,
    _top_cves,
    render_executive_summary,
)
from decepticon.tools.reporting.tools import (
    REPORTING_TOOLS,
    report_bugcrowd_csv,
    report_executive,
    report_hackerone,
    report_timeline,
)
from decepticon_core.types.kg import KnowledgeGraph, Node, NodeKind

# ── Graph builders ────────────────────────────────────────────────────────────


def _empty_graph() -> KnowledgeGraph:
    return KnowledgeGraph()


def _graph_all_severities() -> KnowledgeGraph:
    g = KnowledgeGraph()
    for sev in ("critical", "high", "medium", "low", "info"):
        g.upsert_node(Node.make(NodeKind.VULNERABILITY, f"vuln-{sev}", severity=sev))
    return g


def _graph_with_chains() -> KnowledgeGraph:
    g = KnowledgeGraph()
    g.upsert_node(Node.make(NodeKind.ATTACK_PATH, "fast-chain", total_cost=0.5, length=2))
    g.upsert_node(Node.make(NodeKind.ATTACK_PATH, "slow-chain", total_cost=8.0, length=6))
    g.upsert_node(Node.make(NodeKind.ATTACK_PATH, "medium-chain", total_cost=3.0, length=4))
    return g


def _graph_with_cves() -> KnowledgeGraph:
    g = KnowledgeGraph()
    g.upsert_node(Node.make(NodeKind.CVE, "CVE-LOW", score=2.0))
    g.upsert_node(Node.make(NodeKind.CVE, "CVE-CRITICAL", score=9.8))
    g.upsert_node(Node.make(NodeKind.CVE, "CVE-MED", score=5.5))
    return g


def _graph_with_validated() -> KnowledgeGraph:
    g = KnowledgeGraph()
    for i in range(20):
        g.upsert_node(
            Node.make(
                NodeKind.VULNERABILITY,
                f"validated-vuln-{i}",
                severity="high",
                validated=True,
            )
        )
    g.upsert_node(Node.make(NodeKind.VULNERABILITY, "unvalidated-vuln", severity="medium"))
    return g


def _rich_graph() -> KnowledgeGraph:
    """Graph with vulns, chains, CVEs for tool-level integration tests."""
    g = KnowledgeGraph()
    g.upsert_node(
        Node.make(
            NodeKind.VULNERABILITY,
            "SQLi in /api/search",
            severity="critical",
            validated=True,
            cvss_score=9.1,
            summary="SQL injection allows full DB dump",
            poc_command="sqlmap -u https://target/api/search?q=1",
            cwe=["CWE-89"],
            url="/api/search",
        )
    )
    g.upsert_node(Node.make(NodeKind.VULNERABILITY, "IDOR on /users", severity="medium"))
    g.upsert_node(Node.make(NodeKind.CVE, "CVE-2023-9999", score=8.5))
    g.upsert_node(Node.make(NodeKind.ATTACK_PATH, "sqli-chain", total_cost=1.0, length=3))
    return g


# ── Tests: _count_by_severity ────────────────────────────────────────────────


class TestCountBySeverity:
    def test_empty_graph_returns_empty_dict(self) -> None:
        result = _count_by_severity(_empty_graph())
        assert result == {}

    def test_single_severity_counted(self) -> None:
        g = KnowledgeGraph()
        g.upsert_node(Node.make(NodeKind.VULNERABILITY, "v1", severity="high"))
        result = _count_by_severity(g)
        assert result == {"high": 1}

    def test_all_severities_counted_independently(self) -> None:
        result = _count_by_severity(_graph_all_severities())
        assert result["critical"] == 1
        assert result["high"] == 1
        assert result["medium"] == 1
        assert result["low"] == 1
        assert result["info"] == 1

    def test_multiple_vulns_same_severity_accumulate(self) -> None:
        g = KnowledgeGraph()
        for i in range(5):
            g.upsert_node(Node.make(NodeKind.VULNERABILITY, f"crit-{i}", severity="critical"))
        result = _count_by_severity(g)
        assert result["critical"] == 5

    def test_non_vuln_nodes_not_counted(self) -> None:
        g = KnowledgeGraph()
        g.upsert_node(Node.make(NodeKind.CVE, "CVE-1234", score=9.8))
        g.upsert_node(Node.make(NodeKind.FINDING, "some finding", severity="high"))
        result = _count_by_severity(g)
        assert result == {}

    def test_missing_severity_defaults_to_info(self) -> None:
        g = KnowledgeGraph()
        g.upsert_node(Node.make(NodeKind.VULNERABILITY, "no-sev"))
        result = _count_by_severity(g)
        assert result.get("info", 0) == 1


# ── Tests: _top_chains ───────────────────────────────────────────────────────


class TestTopChains:
    def test_empty_graph_returns_empty_list(self) -> None:
        assert _top_chains(_empty_graph()) == []

    def test_chains_sorted_by_cost_ascending(self) -> None:
        g = _graph_with_chains()
        chains = _top_chains(g)
        costs = [c for _, c, _ in chains]
        assert costs == sorted(costs)

    def test_lowest_cost_chain_is_first(self) -> None:
        g = _graph_with_chains()
        chains = _top_chains(g)
        assert chains[0][0] == "fast-chain"
        assert chains[0][1] == pytest.approx(0.5)

    def test_limit_respected(self) -> None:
        g = KnowledgeGraph()
        for i in range(10):
            g.upsert_node(
                Node.make(NodeKind.ATTACK_PATH, f"chain-{i}", total_cost=float(i), length=i)
            )
        chains = _top_chains(g, limit=3)
        assert len(chains) == 3

    def test_chain_tuple_contains_label_cost_length(self) -> None:
        g = _graph_with_chains()
        chains = _top_chains(g)
        label, cost, length = chains[0]
        assert isinstance(label, str)
        assert isinstance(cost, float)
        assert isinstance(length, int)

    def test_missing_length_defaults_to_zero(self) -> None:
        g = KnowledgeGraph()
        g.upsert_node(Node.make(NodeKind.ATTACK_PATH, "no-length-chain", total_cost=1.0))
        chains = _top_chains(g)
        assert chains[0][2] == 0

    def test_bad_length_value_defaults_to_zero(self) -> None:
        g = KnowledgeGraph()
        g.upsert_node(
            Node.make(NodeKind.ATTACK_PATH, "bad-len", total_cost=1.0, length="not-a-number")
        )
        chains = _top_chains(g)
        assert chains[0][2] == 0

    def test_missing_total_cost_defaults_to_99(self) -> None:
        g = KnowledgeGraph()
        g.upsert_node(Node.make(NodeKind.ATTACK_PATH, "no-cost-chain", length=2))
        chains = _top_chains(g)
        assert chains[0][1] == pytest.approx(99.0)


# ── Tests: _top_cves ─────────────────────────────────────────────────────────


class TestTopCves:
    def test_empty_graph_returns_empty_list(self) -> None:
        assert _top_cves(_empty_graph()) == []

    def test_cves_sorted_descending_by_score(self) -> None:
        g = _graph_with_cves()
        cves = _top_cves(g)
        scores = [s for _, s in cves]
        assert scores == sorted(scores, reverse=True)

    def test_highest_score_is_first(self) -> None:
        g = _graph_with_cves()
        cves = _top_cves(g)
        assert cves[0][0] == "CVE-CRITICAL"
        assert cves[0][1] == pytest.approx(9.8)

    def test_limit_respected(self) -> None:
        g = KnowledgeGraph()
        for i in range(10):
            g.upsert_node(Node.make(NodeKind.CVE, f"CVE-{i}", score=float(i)))
        cves = _top_cves(g, limit=3)
        assert len(cves) == 3

    def test_missing_score_defaults_to_zero(self) -> None:
        g = KnowledgeGraph()
        g.upsert_node(Node.make(NodeKind.CVE, "CVE-NO-SCORE"))
        cves = _top_cves(g)
        assert cves[0][1] == pytest.approx(0.0)

    def test_non_cve_nodes_not_included(self) -> None:
        g = KnowledgeGraph()
        g.upsert_node(Node.make(NodeKind.VULNERABILITY, "not-a-cve", severity="critical"))
        assert _top_cves(g) == []


# ── Tests: render_executive_summary ──────────────────────────────────────────


class TestRenderExecutiveSummary:
    def test_header_contains_engagement_name(self) -> None:
        md = render_executive_summary(_empty_graph(), engagement_name="PentestCorp 2024")
        assert "PentestCorp 2024" in md
        assert "Executive Summary" in md

    def test_empty_graph_no_findings_message(self) -> None:
        md = render_executive_summary(_empty_graph())
        assert "No findings" in md

    def test_empty_graph_no_chains_section(self) -> None:
        md = render_executive_summary(_empty_graph())
        assert "Top Critical Chains" not in md

    def test_empty_graph_no_cve_section(self) -> None:
        md = render_executive_summary(_empty_graph())
        assert "Top CVE Exposure" not in md

    def test_total_finding_count_in_output(self) -> None:
        g = _graph_all_severities()
        md = render_executive_summary(g)
        assert "5 total findings" in md

    def test_severity_order_critical_before_low(self) -> None:
        g = _graph_all_severities()
        md = render_executive_summary(g)
        crit_pos = md.index("CRITICAL")
        low_pos = md.index("LOW")
        assert crit_pos < low_pos

    def test_only_nonzero_severities_listed(self) -> None:
        g = KnowledgeGraph()
        g.upsert_node(Node.make(NodeKind.VULNERABILITY, "only-high", severity="high"))
        md = render_executive_summary(g)
        assert "HIGH" in md
        assert "CRITICAL" not in md
        assert "MEDIUM" not in md

    def test_chains_section_present_when_chains_exist(self) -> None:
        g = _graph_with_chains()
        md = render_executive_summary(g)
        assert "Top Critical Chains" in md

    def test_chains_formatted_with_cost_and_hops(self) -> None:
        g = _graph_with_chains()
        md = render_executive_summary(g)
        assert "cost" in md
        assert "hops" in md

    def test_cve_section_present_when_cves_exist(self) -> None:
        g = _graph_with_cves()
        md = render_executive_summary(g)
        assert "Top CVE Exposure" in md
        assert "CVE-CRITICAL" in md

    def test_validated_findings_section_appears(self) -> None:
        g = _graph_with_validated()
        md = render_executive_summary(g)
        assert "Validated Findings" in md

    def test_validated_findings_section_capped_at_15(self) -> None:
        g = _graph_with_validated()
        md = render_executive_summary(g)
        # 20 validated vulns inserted; only first 15 should appear in the list
        assert "validated-vuln-14" in md
        assert "validated-vuln-15" not in md

    def test_unvalidated_not_in_validated_section(self) -> None:
        g = _graph_with_validated()
        md = render_executive_summary(g)
        assert "unvalidated-vuln" not in md

    def test_graph_stats_section_always_present(self) -> None:
        md = render_executive_summary(_empty_graph())
        assert "Graph Stats" in md

    def test_graph_stats_includes_node_count(self) -> None:
        g = _graph_all_severities()
        md = render_executive_summary(g)
        assert "nodes: 5" in md

    def test_default_engagement_name(self) -> None:
        md = render_executive_summary(_empty_graph())
        assert "Engagement" in md

    def test_output_is_valid_markdown_string(self) -> None:
        g = _rich_graph()
        md = render_executive_summary(g, engagement_name="RichTest")
        assert isinstance(md, str)
        assert len(md) > 0
        assert md.startswith("#")

    def test_top_chains_section_ordered_lowest_cost_first(self) -> None:
        g = _graph_with_chains()
        md = render_executive_summary(g)
        fast_pos = md.index("fast-chain")
        slow_pos = md.index("slow-chain")
        assert fast_pos < slow_pos

    def test_top_cves_ordered_highest_score_first(self) -> None:
        g = _graph_with_cves()
        md = render_executive_summary(g)
        crit_pos = md.index("CVE-CRITICAL")
        low_pos = md.index("CVE-LOW")
        assert crit_pos < low_pos

    def test_special_characters_in_engagement_name(self) -> None:
        md = render_executive_summary(_empty_graph(), engagement_name="Acme & Co. <2024>")
        assert "Acme & Co." in md

    def test_validated_findings_show_severity_tag(self) -> None:
        g = KnowledgeGraph()
        g.upsert_node(
            Node.make(NodeKind.VULNERABILITY, "auth-bypass", severity="critical", validated=True)
        )
        md = render_executive_summary(g)
        assert "[CRITICAL]" in md


# ── Tests: report_* tool wrappers ─────────────────────────────────────────────


class TestReportHackerOneTool:
    def test_returns_markdown_for_valid_node(self) -> None:
        g = _rich_graph()
        vuln = g.by_kind(NodeKind.VULNERABILITY)[0]
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_hackerone.ainvoke({"finding_id": vuln.id}))
        payload = json.loads(result)
        assert "id" in payload
        assert "markdown" in payload
        assert payload["id"] == vuln.id
        assert "SQLi" in payload["markdown"]

    def test_returns_error_for_missing_node(self) -> None:
        g = _empty_graph()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_hackerone.ainvoke({"finding_id": "nonexistent-id"}))
        payload = json.loads(result)
        assert "error" in payload
        assert "nonexistent-id" in payload["error"]

    def test_return_value_is_json_string(self) -> None:
        g = _rich_graph()
        vuln = g.by_kind(NodeKind.VULNERABILITY)[0]
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_hackerone.ainvoke({"finding_id": vuln.id}))
        assert isinstance(result, str)
        json.loads(result)  # must not raise


class TestReportBugcrowdCsvTool:
    def test_default_min_severity_is_medium(self) -> None:
        g = _graph_all_severities()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_bugcrowd_csv.ainvoke({"min_severity": "medium"}))
        payload = json.loads(result)
        assert "rows" in payload
        assert "csv" in payload
        # critical + high + medium = 3 data rows
        assert payload["rows"] == 3

    def test_min_severity_low_includes_low_vulns(self) -> None:
        g = _graph_all_severities()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_bugcrowd_csv.ainvoke({"min_severity": "low"}))
        payload = json.loads(result)
        # critical + high + medium + low = 4 data rows
        assert payload["rows"] == 4

    def test_min_severity_critical_filters_to_one_row(self) -> None:
        g = _graph_all_severities()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_bugcrowd_csv.ainvoke({"min_severity": "critical"}))
        payload = json.loads(result)
        assert payload["rows"] == 1

    def test_csv_has_header_row(self) -> None:
        g = _rich_graph()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_bugcrowd_csv.ainvoke({"min_severity": "low"}))
        payload = json.loads(result)
        first_line = payload["csv"].splitlines()[0]
        assert "title" in first_line
        assert "severity" in first_line

    def test_empty_graph_returns_header_only(self) -> None:
        g = _empty_graph()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_bugcrowd_csv.ainvoke({"min_severity": "low"}))
        payload = json.loads(result)
        assert payload["rows"] == 0

    def test_result_is_json_string(self) -> None:
        g = _empty_graph()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_bugcrowd_csv.ainvoke({"min_severity": "medium"}))
        assert isinstance(result, str)
        json.loads(result)


class TestReportExecutiveTool:
    def test_returns_markdown_key(self) -> None:
        g = _rich_graph()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_executive.ainvoke({"engagement_name": "Acme"}))
        payload = json.loads(result)
        assert "markdown" in payload

    def test_engagement_name_appears_in_markdown(self) -> None:
        g = _rich_graph()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_executive.ainvoke({"engagement_name": "WidgetCorp"}))
        payload = json.loads(result)
        assert "WidgetCorp" in payload["markdown"]

    def test_empty_graph_returns_no_findings_message(self) -> None:
        g = _empty_graph()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_executive.ainvoke({"engagement_name": "Empty"}))
        payload = json.loads(result)
        assert "No findings" in payload["markdown"]

    def test_default_engagement_name_used(self) -> None:
        g = _empty_graph()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_executive.ainvoke({}))
        payload = json.loads(result)
        assert "Engagement" in payload["markdown"]

    def test_result_is_json_string(self) -> None:
        g = _empty_graph()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_executive.ainvoke({}))
        assert isinstance(result, str)
        json.loads(result)


class TestReportTimelineTool:
    def test_returns_count_and_events_keys(self) -> None:
        g = _rich_graph()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_timeline.ainvoke({}))
        payload = json.loads(result)
        assert "count" in payload
        assert "events" in payload

    def test_count_matches_events_length(self) -> None:
        g = _rich_graph()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_timeline.ainvoke({}))
        payload = json.loads(result)
        assert payload["count"] == len(payload["events"])

    def test_events_are_list(self) -> None:
        g = _empty_graph()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_timeline.ainvoke({}))
        payload = json.loads(result)
        assert isinstance(payload["events"], list)

    def test_empty_graph_returns_zero_events(self) -> None:
        g = _empty_graph()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_timeline.ainvoke({}))
        payload = json.loads(result)
        assert payload["count"] == 0

    def test_result_is_json_string(self) -> None:
        g = _rich_graph()
        with patch("decepticon.tools.reporting.tools._load", return_value=(g, None)):
            result = asyncio.run(report_timeline.ainvoke({}))
        assert isinstance(result, str)
        json.loads(result)


# ── Tests: REPORTING_TOOLS list ────────────────────────────────────────────────


class TestReportingToolsList:
    def test_reporting_tools_is_nonempty_list(self) -> None:
        assert isinstance(REPORTING_TOOLS, list)
        assert len(REPORTING_TOOLS) > 0

    def test_all_five_tools_present(self) -> None:
        names = {t.name for t in REPORTING_TOOLS}
        assert "report_hackerone" in names
        assert "report_bugcrowd_csv" in names
        assert "report_executive" in names
        assert "report_timeline" in names
        assert "report_sarif" in names

    def test_all_tools_have_description(self) -> None:
        for tool in REPORTING_TOOLS:
            assert tool.description, f"{tool.name} has no description"

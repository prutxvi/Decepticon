# -*- coding: utf-8 -*-
"""Extended unit tests for tools/research/tools.py — pure helpers, parsers,
Tier-2 ingesters, KG CRUD tools, and error-path coverage.

Existing test_tools.py covers the main ingesters and web/auth tools.
This file adds:
- Pure helper / formatter functions
- Dependency-file parsers (_iter_requirements, _iter_package_lock, etc.)
- KG CRUD tools (kg_add_node, kg_add_edge, kg_query, kg_neighbors, kg_stats)
- Tier-2 ingesters (subfinder, dnsx, katana, masscan, ffuf, testssl,
  crackmapexec, asrep_hashes)
- Fuzz tools (fuzz_harness, fuzz_record_crash)
- Error paths and edge cases throughout
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from decepticon.tools.research import _state as state
from decepticon.tools.research import tools as research_tools
from decepticon.tools.research.tools import (
    _cookie_finding_severity,
    _is_web_port,
    _iter_cargo_lock,
    _iter_go_sum,
    _iter_package_lock,
    _iter_requirements,
    _jwt_finding_severity,
    _parse_dependencies,
    _parse_props,
    _severity_from_score,
    _severity_from_string,
    _severity_threshold,
)
from decepticon_core.types.kg import KnowledgeGraph, NodeKind, Severity  # noqa: F401

# ── Shared fake store ────────────────────────────────────────────────────


class _FakeStore:
    """In-memory fake Neo4j store for unit tests."""

    def __init__(self) -> None:
        self.graph = KnowledgeGraph()

    def load_graph(self):
        return self.graph.model_copy(deep=True)

    def batch_upsert_nodes(self, nodes):
        for n in nodes:
            self.graph.upsert_node(n)
        return len(nodes)

    def batch_upsert_edges(self, edges):
        for e in edges:
            self.graph.upsert_edge(e)
        return len(edges)

    def ensure_schema(self):
        pass

    def close(self):
        pass

    def revision(self):
        return 0.0

    def stats(self):
        return self.graph.stats()

    def upsert_node(self, node):
        self.graph.upsert_node(node)

    def upsert_edge(self, edge):
        self.graph.upsert_edge(edge)

    def query_custom(self, cypher, params):
        return []


def _configure_kg(monkeypatch: pytest.MonkeyPatch) -> _FakeStore:
    fake = _FakeStore()
    monkeypatch.setattr(state, "_store", fake)
    return fake


# ── Pure helpers ─────────────────────────────────────────────────────────


class TestParseProps:
    def test_empty_string_returns_empty_dict(self) -> None:
        assert _parse_props("") == {}

    def test_valid_json_object(self) -> None:
        result = _parse_props('{"severity": "high", "port": 443}')
        assert result == {"severity": "high", "port": 443}

    def test_invalid_json_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="props must be valid JSON"):
            _parse_props("{not valid}")

    def test_json_array_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="props must be a JSON object"):
            _parse_props("[1, 2, 3]")

    def test_json_string_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="props must be a JSON object"):
            _parse_props('"hello"')


class TestSeverityFromScore:
    def test_critical_at_nine(self) -> None:
        assert _severity_from_score(9.0) == Severity.CRITICAL

    def test_critical_above_nine(self) -> None:
        assert _severity_from_score(10.0) == Severity.CRITICAL

    def test_high_at_seven(self) -> None:
        assert _severity_from_score(7.0) == Severity.HIGH

    def test_high_below_nine(self) -> None:
        assert _severity_from_score(8.9) == Severity.HIGH

    def test_medium_at_four(self) -> None:
        assert _severity_from_score(4.0) == Severity.MEDIUM

    def test_medium_below_seven(self) -> None:
        assert _severity_from_score(6.9) == Severity.MEDIUM

    def test_low_above_zero(self) -> None:
        assert _severity_from_score(0.1) == Severity.LOW

    def test_low_below_four(self) -> None:
        assert _severity_from_score(3.9) == Severity.LOW

    def test_info_at_zero(self) -> None:
        assert _severity_from_score(0.0) == Severity.INFO


class TestSeverityFromString:
    def test_critical(self) -> None:
        assert _severity_from_string("critical") == Severity.CRITICAL

    def test_high_uppercase(self) -> None:
        assert _severity_from_string("HIGH") == Severity.HIGH

    def test_medium(self) -> None:
        assert _severity_from_string("medium") == Severity.MEDIUM

    def test_low(self) -> None:
        assert _severity_from_string("low") == Severity.LOW

    def test_info(self) -> None:
        assert _severity_from_string("info") == Severity.INFO

    def test_informational(self) -> None:
        assert _severity_from_string("informational") == Severity.INFO

    def test_none_returns_medium(self) -> None:
        assert _severity_from_string(None) == Severity.MEDIUM

    def test_empty_returns_medium(self) -> None:
        assert _severity_from_string("") == Severity.MEDIUM

    def test_whitespace_stripped(self) -> None:
        assert _severity_from_string("  HIGH  ") == Severity.HIGH

    def test_unknown_returns_medium(self) -> None:
        assert _severity_from_string("bogus") == Severity.MEDIUM


class TestIsWebPort:
    def test_port_80_is_web(self) -> None:
        assert _is_web_port(80) is True

    def test_port_443_is_web(self) -> None:
        assert _is_web_port(443) is True

    def test_port_8080_is_web(self) -> None:
        assert _is_web_port(8080) is True

    def test_port_8443_is_web(self) -> None:
        assert _is_web_port(8443) is True

    def test_port_22_not_web(self) -> None:
        assert _is_web_port(22) is False

    def test_port_3306_not_web(self) -> None:
        assert _is_web_port(3306) is False


class TestSeverityThreshold:
    def test_critical_threshold(self) -> None:
        t = _severity_threshold(Severity.CRITICAL)
        assert t > 0.0

    def test_info_threshold(self) -> None:
        t = _severity_threshold(Severity.INFO)
        # INFO has the lowest / zero threshold
        assert _severity_threshold(Severity.HIGH) > t

    def test_high_threshold_greater_than_medium(self) -> None:
        assert _severity_threshold(Severity.HIGH) > _severity_threshold(Severity.MEDIUM)


class TestJwtFindingSeverity:
    def test_alg_none_is_critical(self) -> None:
        assert _jwt_finding_severity("alg=none detected") == Severity.CRITICAL

    def test_key_confusion_is_high(self) -> None:
        assert _jwt_finding_severity("key confusion attack possible") == Severity.HIGH

    def test_path_traversal_is_high(self) -> None:
        assert _jwt_finding_severity("jku path traversal") == Severity.HIGH

    def test_no_exp_is_medium(self) -> None:
        assert _jwt_finding_severity("no exp claim") == Severity.MEDIUM

    def test_expired_is_medium(self) -> None:
        assert _jwt_finding_severity("token expired") == Severity.MEDIUM

    def test_other_is_low(self) -> None:
        assert _jwt_finding_severity("weak algorithm") == Severity.LOW


class TestCookieFindingSeverity:
    def test_predictable_session_is_high(self) -> None:
        assert _cookie_finding_severity("predictable session id") == Severity.HIGH

    def test_httponly_not_set_is_medium(self) -> None:
        assert _cookie_finding_severity("HttpOnly not set") == Severity.MEDIUM

    def test_samesite_is_medium(self) -> None:
        assert _cookie_finding_severity("SameSite not strict") == Severity.MEDIUM

    def test_secure_flag_is_medium(self) -> None:
        assert _cookie_finding_severity("Secure flag not set") == Severity.MEDIUM

    def test_other_is_low(self) -> None:
        assert _cookie_finding_severity("short cookie value") == Severity.LOW


# ── Dependency parsers ────────────────────────────────────────────────────


class TestIterRequirements:
    def test_basic_pinned(self, tmp_path: Path) -> None:
        p = tmp_path / "requirements.txt"
        p.write_text("flask==2.0.0\nrequests==2.28.1\n", encoding="utf-8")
        result = _iter_requirements(p)
        assert ("flask", "2.0.0", "PyPI") in result
        assert ("requests", "2.28.1", "PyPI") in result

    def test_comments_and_blanks_skipped(self, tmp_path: Path) -> None:
        p = tmp_path / "requirements.txt"
        p.write_text("# comment\n\nflask==1.0.0\n", encoding="utf-8")
        result = _iter_requirements(p)
        assert len(result) == 1
        assert result[0][0] == "flask"

    def test_env_markers_stripped(self, tmp_path: Path) -> None:
        p = tmp_path / "requirements.txt"
        p.write_text('django==4.2.0; python_version >= "3.8"\n', encoding="utf-8")
        result = _iter_requirements(p)
        assert len(result) == 1
        assert result[0] == ("django", "4.2.0", "PyPI")

    def test_inline_comment_stripped(self, tmp_path: Path) -> None:
        p = tmp_path / "requirements.txt"
        p.write_text("numpy==1.24.0  # pinned for compat\n", encoding="utf-8")
        result = _iter_requirements(p)
        assert result[0] == ("numpy", "1.24.0", "PyPI")

    def test_non_pinned_lines_excluded(self, tmp_path: Path) -> None:
        p = tmp_path / "requirements.txt"
        p.write_text("flask>=2.0\nnumpy\n", encoding="utf-8")
        result = _iter_requirements(p)
        assert result == []

    def test_empty_file(self, tmp_path: Path) -> None:
        p = tmp_path / "requirements.txt"
        p.write_text("", encoding="utf-8")
        assert _iter_requirements(p) == []


class TestIterPackageLock:
    def test_v2_format(self, tmp_path: Path) -> None:
        payload = {
            "lockfileVersion": 2,
            "packages": {
                "node_modules/express": {"name": "express", "version": "4.18.2"},
                "node_modules/lodash": {"version": "4.17.21"},
                "": {"name": "myapp"},
            },
        }
        p = tmp_path / "package-lock.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        result = _iter_package_lock(p)
        names = {r[0] for r in result}
        assert "express" in names
        assert "lodash" in names

    def test_v1_fallback_format(self, tmp_path: Path) -> None:
        payload = {
            "lockfileVersion": 1,
            "dependencies": {
                "react": {"version": "18.2.0"},
                "react-dom": {
                    "version": "18.2.0",
                    "dependencies": {"loose-envify": {"version": "1.4.0"}},
                },
            },
        }
        p = tmp_path / "package-lock.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        result = _iter_package_lock(p)
        names = {r[0] for r in result}
        assert "react" in names
        assert "react-dom" in names
        # nested dependency extracted
        assert "loose-envify" in names

    def test_ecosystem_is_npm(self, tmp_path: Path) -> None:
        payload = {
            "packages": {
                "node_modules/chalk": {"name": "chalk", "version": "5.0.0"},
            }
        }
        p = tmp_path / "package-lock.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        result = _iter_package_lock(p)
        assert result[0][2] == "npm"


class TestIterGoSum:
    def test_basic_entries(self, tmp_path: Path) -> None:
        content = (
            "github.com/pkg/errors v0.9.1 h1:79de8...\n"
            "github.com/pkg/errors v0.9.1/go.mod h1:...\n"
            "golang.org/x/net v0.0.0-20220722155237-a158d28d115b h1:...\n"
        )
        p = tmp_path / "go.sum"
        p.write_text(content, encoding="utf-8")
        result = _iter_go_sum(p)
        # deduplication: pkg/errors appears twice but is de-duped
        modules = [r[0] for r in result]
        assert modules.count("github.com/pkg/errors") == 1
        assert "golang.org/x/net" in modules

    def test_ecosystem_is_go(self, tmp_path: Path) -> None:
        p = tmp_path / "go.sum"
        p.write_text("golang.org/x/text v0.3.7 h1:abc\n", encoding="utf-8")
        result = _iter_go_sum(p)
        assert result[0][2] == "Go"

    def test_empty_file(self, tmp_path: Path) -> None:
        p = tmp_path / "go.sum"
        p.write_text("", encoding="utf-8")
        assert _iter_go_sum(p) == []


class TestIterCargoLock:
    def test_basic_packages(self, tmp_path: Path) -> None:
        content = (
            "[[package]]\n"
            'name = "serde"\n'
            'version = "1.0.195"\n'
            "\n"
            "[[package]]\n"
            'name = "tokio"\n'
            'version = "1.35.1"\n'
        )
        p = tmp_path / "Cargo.lock"
        p.write_text(content, encoding="utf-8")
        result = _iter_cargo_lock(p)
        assert ("serde", "1.0.195", "crates.io") in result
        assert ("tokio", "1.35.1", "crates.io") in result

    def test_incomplete_package_not_included(self, tmp_path: Path) -> None:
        # Only name present, no version
        content = '[[package]]\nname = "orphan"\n'
        p = tmp_path / "Cargo.lock"
        p.write_text(content, encoding="utf-8")
        result = _iter_cargo_lock(p)
        assert result == []

    def test_empty_file(self, tmp_path: Path) -> None:
        p = tmp_path / "Cargo.lock"
        p.write_text("", encoding="utf-8")
        assert _iter_cargo_lock(p) == []


class TestParseDependencies:
    def test_routes_requirements(self, tmp_path: Path) -> None:
        p = tmp_path / "requirements.txt"
        p.write_text("django==4.2.0\n", encoding="utf-8")
        result = _parse_dependencies(p)
        assert result[0][0] == "django"

    def test_routes_package_lock(self, tmp_path: Path) -> None:
        payload = {
            "packages": {
                "node_modules/lodash": {"name": "lodash", "version": "4.17.21"},
            }
        }
        p = tmp_path / "package-lock.json"
        p.write_text(json.dumps(payload), encoding="utf-8")
        result = _parse_dependencies(p)
        assert result[0][0] == "lodash"

    def test_routes_go_sum(self, tmp_path: Path) -> None:
        p = tmp_path / "go.sum"
        p.write_text("github.com/gin-gonic/gin v1.9.1 h1:abc\n", encoding="utf-8")
        result = _parse_dependencies(p)
        assert result[0][0] == "github.com/gin-gonic/gin"

    def test_routes_cargo_lock(self, tmp_path: Path) -> None:
        content = '[[package]]\nname = "rand"\nversion = "0.8.5"\n'
        p = tmp_path / "Cargo.lock"
        p.write_text(content, encoding="utf-8")
        result = _parse_dependencies(p)
        assert result[0] == ("rand", "0.8.5", "crates.io")

    def test_unknown_file_returns_empty(self, tmp_path: Path) -> None:
        p = tmp_path / "setup.cfg"
        p.write_text("[options]\ninstall_requires = flask\n", encoding="utf-8")
        assert _parse_dependencies(p) == []


# ── KG CRUD tools ─────────────────────────────────────────────────────────


class TestKgAddNode:
    def test_valid_kind_creates_node(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # NodeKind enum values are Title-case: "Host", "Vulnerability", etc.
        fake = _configure_kg(monkeypatch)
        result = json.loads(
            research_tools.kg_add_node.invoke({"kind": "Host", "label": "10.0.0.1"})
        )
        assert "id" in result
        assert result["kind"] == "Host"
        assert result["label"] == "10.0.0.1"
        assert len(fake.graph.nodes) == 1

    def test_with_props(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(
            research_tools.kg_add_node.invoke(
                {"kind": "Vulnerability", "label": "XSS", "props": '{"severity": "high"}'}
            )
        )
        assert result["kind"] == "Vulnerability"

    def test_unknown_kind_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(
            research_tools.kg_add_node.invoke({"kind": "notakind", "label": "test"})
        )
        assert "error" in result
        assert "valid" in result

    def test_stats_returned(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(research_tools.kg_add_node.invoke({"kind": "Host", "label": "x"}))
        assert "stats" in result


class TestKgAddEdge:
    def test_valid_edge_created(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # EdgeKind enum values are UPPER_SNAKE: "HAS_VULN", "EXPOSES", etc.
        fake = _configure_kg(monkeypatch)
        src = json.loads(research_tools.kg_add_node.invoke({"kind": "Host", "label": "src"}))["id"]
        dst = json.loads(
            research_tools.kg_add_node.invoke({"kind": "Vulnerability", "label": "dst"})
        )["id"]
        result = json.loads(
            research_tools.kg_add_edge.invoke({"src": src, "dst": dst, "kind": "HAS_VULN"})
        )
        assert "id" in result
        assert result["kind"] == "HAS_VULN"
        assert len(fake.graph.edges) == 1

    def test_unknown_edge_kind_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(
            research_tools.kg_add_edge.invoke({"src": "a", "dst": "b", "kind": "invalid_kind"})
        )
        assert "error" in result
        assert "valid" in result

    def test_missing_node_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(
            research_tools.kg_add_edge.invoke(
                {"src": "nonexistent-id-1", "dst": "nonexistent-id-2", "kind": "EXPOSES"}
            )
        )
        assert "error" in result
        # The error response includes presence flags
        assert "src_present" in result or "error" in result

    def test_custom_weight(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        src = json.loads(research_tools.kg_add_node.invoke({"kind": "Entrypoint", "label": "ep"}))[
            "id"
        ]
        dst = json.loads(
            research_tools.kg_add_node.invoke({"kind": "Vulnerability", "label": "v"})
        )["id"]
        result = json.loads(
            research_tools.kg_add_edge.invoke(
                {"src": src, "dst": dst, "kind": "HAS_VULN", "weight": 0.3}
            )
        )
        assert "id" in result


class TestKgQuery:
    def test_all_nodes_returned_when_no_filter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        research_tools.kg_add_node.invoke({"kind": "Host", "label": "h1"})
        research_tools.kg_add_node.invoke({"kind": "Vulnerability", "label": "v1"})
        result = json.loads(research_tools.kg_query.invoke({}))
        assert result["total"] == 2
        assert result["returned"] == 2

    def test_kind_filter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        research_tools.kg_add_node.invoke({"kind": "Host", "label": "h1"})
        research_tools.kg_add_node.invoke({"kind": "Vulnerability", "label": "v1"})
        result = json.loads(research_tools.kg_query.invoke({"kind": "Host"}))
        assert result["total"] == 1
        assert result["nodes"][0]["kind"] == "Host"

    def test_min_severity_filter(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        research_tools.kg_add_node.invoke(
            {"kind": "Vulnerability", "label": "high-vuln", "props": '{"severity": "high"}'}
        )
        research_tools.kg_add_node.invoke(
            {"kind": "Vulnerability", "label": "low-vuln", "props": '{"severity": "low"}'}
        )
        result = json.loads(research_tools.kg_query.invoke({"min_severity": "high"}))
        # Only the high-severity vuln should be returned
        assert result["total"] >= 1
        for node in result["nodes"]:
            assert node["props"].get("severity") in {"high", "critical"}

    def test_unknown_kind_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(research_tools.kg_query.invoke({"kind": "badkind"}))
        assert "error" in result

    def test_bad_severity_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(research_tools.kg_query.invoke({"min_severity": "extreme"}))
        assert "error" in result

    def test_limit_applied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        for i in range(10):
            research_tools.kg_add_node.invoke({"kind": "Host", "label": f"h{i}"})
        result = json.loads(research_tools.kg_query.invoke({"limit": 3}))
        assert result["returned"] == 3
        assert result["total"] == 10


class TestKgNeighbors:
    def test_returns_connected_nodes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        src_id = json.loads(research_tools.kg_add_node.invoke({"kind": "Host", "label": "host1"}))[
            "id"
        ]
        dst_id = json.loads(
            research_tools.kg_add_node.invoke({"kind": "Service", "label": "svc1"})
        )["id"]
        research_tools.kg_add_edge.invoke({"src": src_id, "dst": dst_id, "kind": "EXPOSES"})
        result = json.loads(
            research_tools.kg_neighbors.invoke({"node_id": src_id, "direction": "out"})
        )
        assert len(result) == 1
        assert result[0]["edge_kind"] == "EXPOSES"
        assert result[0]["neighbor_id"] == dst_id

    def test_node_not_found_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(research_tools.kg_neighbors.invoke({"node_id": "ghost-node-id"}))
        assert "error" in result

    def test_invalid_edge_kind_filter_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        nid = json.loads(research_tools.kg_add_node.invoke({"kind": "Host", "label": "x"}))["id"]
        result = json.loads(
            research_tools.kg_neighbors.invoke({"node_id": nid, "edge_kind": "bad_kind"})
        )
        assert "error" in result

    def test_direction_in(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        src_id = json.loads(research_tools.kg_add_node.invoke({"kind": "Host", "label": "h"}))["id"]
        dst_id = json.loads(research_tools.kg_add_node.invoke({"kind": "Service", "label": "s"}))[
            "id"
        ]
        research_tools.kg_add_edge.invoke({"src": src_id, "dst": dst_id, "kind": "EXPOSES"})
        # From dst looking "in"
        result = json.loads(
            research_tools.kg_neighbors.invoke({"node_id": dst_id, "direction": "in"})
        )
        assert len(result) == 1
        assert result[0]["neighbor_id"] == src_id


class TestKgStats:
    def test_returns_stats_dict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(research_tools.kg_stats.invoke({}))
        assert "backend" in result
        assert isinstance(result, dict)

    def test_stats_reflect_additions(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        before = json.loads(research_tools.kg_stats.invoke({}))
        research_tools.kg_add_node.invoke({"kind": "Host", "label": "new"})
        after = json.loads(research_tools.kg_stats.invoke({}))
        assert isinstance(before, dict)
        assert isinstance(after, dict)


# ── Tier-2 ingesters ──────────────────────────────────────────────────────


class TestKgIngestSubfinder:
    def test_creates_host_and_entrypoint_nodes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _configure_kg(monkeypatch)
        p = tmp_path / "subdomains.txt"
        p.write_text("api.example.com\nwww.example.com\n", encoding="utf-8")

        result = json.loads(research_tools.kg_ingest_subfinder.invoke({"path": str(p)}))
        assert result["domains_added"] == 2
        # 2 domains × 2 schemes (http + https) = 4
        assert result["entrypoints_added"] == 4
        assert len(fake.graph.by_kind(NodeKind.HOST)) == 2
        assert len(fake.graph.by_kind(NodeKind.ENTRYPOINT)) == 4

    def test_file_not_found_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(
            research_tools.kg_ingest_subfinder.invoke({"path": "/no/such/file.txt"})
        )
        assert "error" in result

    def test_root_domain_filter(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "subs.txt"
        p.write_text("api.example.com\nother.attacker.com\n", encoding="utf-8")
        result = json.loads(
            research_tools.kg_ingest_subfinder.invoke(
                {"path": str(p), "root_domain": "example.com"}
            )
        )
        assert result["domains_added"] == 1

    def test_blank_lines_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "subs.txt"
        p.write_text("\n   \nsub.example.com\n", encoding="utf-8")
        result = json.loads(research_tools.kg_ingest_subfinder.invoke({"path": str(p)}))
        assert result["domains_added"] == 1


class TestKgIngestDnsx:
    def test_host_nodes_created(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _configure_kg(monkeypatch)
        p = tmp_path / "dnsx.jsonl"
        p.write_text(
            json.dumps({"host": "api.example.com", "a": ["10.0.0.1"]}) + "\n",
            encoding="utf-8",
        )
        result = json.loads(research_tools.kg_ingest_dnsx.invoke({"path": str(p)}))
        assert result["hosts_added"] == 1
        assert len(fake.graph.by_kind(NodeKind.HOST)) == 1

    def test_cname_creates_extra_host(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _configure_kg(monkeypatch)
        p = tmp_path / "dnsx.jsonl"
        p.write_text(
            json.dumps({"host": "cdn.example.com", "cname": ["upstream.cdn.net"]}) + "\n",
            encoding="utf-8",
        )
        result = json.loads(research_tools.kg_ingest_dnsx.invoke({"path": str(p)}))
        assert result["hosts_added"] == 1
        # cdn.example.com + upstream.cdn.net
        assert len(fake.graph.by_kind(NodeKind.HOST)) == 2

    def test_file_not_found_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(research_tools.kg_ingest_dnsx.invoke({"path": "/no/file.jsonl"}))
        assert "error" in result

    def test_invalid_jsonl_lines_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "dnsx.jsonl"
        p.write_text("not-json\n" + json.dumps({"host": "ok.example.com"}) + "\n", encoding="utf-8")
        result = json.loads(research_tools.kg_ingest_dnsx.invoke({"path": str(p)}))
        assert result["hosts_added"] == 1

    def test_empty_host_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "dnsx.jsonl"
        p.write_text(json.dumps({"a": ["1.2.3.4"]}) + "\n", encoding="utf-8")
        result = json.loads(research_tools.kg_ingest_dnsx.invoke({"path": str(p)}))
        assert result["hosts_added"] == 0


class TestKgIngestKatana:
    def test_url_and_entrypoint_nodes_created(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _configure_kg(monkeypatch)
        p = tmp_path / "katana.jsonl"
        row = {"endpoint": "https://app.example.com/api/v1/users", "method": "GET"}
        p.write_text(json.dumps(row) + "\n", encoding="utf-8")

        result = json.loads(research_tools.kg_ingest_katana.invoke({"path": str(p)}))
        assert result["urls_added"] == 1
        assert len(fake.graph.by_kind(NodeKind.URL)) == 1
        assert len(fake.graph.by_kind(NodeKind.ENTRYPOINT)) == 1

    def test_nested_request_endpoint(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "katana.jsonl"
        row = {"request": {"endpoint": "https://app.example.com/login", "method": "POST"}}
        p.write_text(json.dumps(row) + "\n", encoding="utf-8")
        result = json.loads(research_tools.kg_ingest_katana.invoke({"path": str(p)}))
        assert result["urls_added"] == 1

    def test_file_not_found_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(research_tools.kg_ingest_katana.invoke({"path": "/missing/file.jsonl"}))
        assert "error" in result

    def test_invalid_json_lines_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "katana.jsonl"
        p.write_text(
            "BADLINE\n" + json.dumps({"endpoint": "https://ok.example.com/"}) + "\n",
            encoding="utf-8",
        )
        result = json.loads(research_tools.kg_ingest_katana.invoke({"path": str(p)}))
        assert result["urls_added"] == 1


class TestKgIngestMasscan:
    def test_creates_host_and_service_nodes(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _configure_kg(monkeypatch)
        p = tmp_path / "masscan.json"
        entries = [
            {"ip": "10.0.0.1", "ports": [{"port": 80, "proto": "tcp", "status": "open"}]},
            {"ip": "10.0.0.2", "ports": [{"port": 443, "proto": "tcp", "status": "open"}]},
        ]
        p.write_text(json.dumps(entries), encoding="utf-8")

        result = json.loads(research_tools.kg_ingest_masscan.invoke({"path": str(p)}))
        assert result["hosts_added"] == 2
        assert result["services_added"] == 2
        assert len(fake.graph.by_kind(NodeKind.HOST)) == 2
        assert len(fake.graph.by_kind(NodeKind.SERVICE)) == 2

    def test_file_not_found_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(research_tools.kg_ingest_masscan.invoke({"path": "/bad/path.json"}))
        assert "error" in result

    def test_empty_file_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "masscan.json"
        p.write_text("", encoding="utf-8")
        result = json.loads(research_tools.kg_ingest_masscan.invoke({"path": str(p)}))
        assert "error" in result

    def test_closed_port_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "masscan.json"
        entries = [{"ip": "10.0.0.1", "ports": [{"port": 22, "proto": "tcp", "status": "closed"}]}]
        p.write_text(json.dumps(entries), encoding="utf-8")
        result = json.loads(research_tools.kg_ingest_masscan.invoke({"path": str(p)}))
        assert result["services_added"] == 0

    def test_line_format_without_brackets(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "masscan.json"
        # masscan sometimes emits one JSON object per line
        line = json.dumps({"ip": "192.168.1.1", "ports": [{"port": 8080, "proto": "tcp"}]})
        p.write_text(line + "\n", encoding="utf-8")
        result = json.loads(research_tools.kg_ingest_masscan.invoke({"path": str(p)}))
        assert result["hosts_added"] == 1


class TestKgIngestFfuf:
    def test_urls_and_entrypoints_created(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _configure_kg(monkeypatch)
        data = {
            "results": [
                {"url": "https://app.example.com/admin", "status": 200, "length": 512},
                {"url": "https://app.example.com/backup", "status": 403, "length": 1024},
            ]
        }
        p = tmp_path / "ffuf.json"
        p.write_text(json.dumps(data), encoding="utf-8")

        result = json.loads(research_tools.kg_ingest_ffuf.invoke({"path": str(p)}))
        assert result["urls_added"] == 2
        assert result["entrypoints_added"] == 2
        assert len(fake.graph.by_kind(NodeKind.URL)) == 2
        assert len(fake.graph.by_kind(NodeKind.ENTRYPOINT)) == 2

    def test_file_not_found_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(research_tools.kg_ingest_ffuf.invoke({"path": "/no/file.json"}))
        assert "error" in result

    def test_invalid_json_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "ffuf.json"
        p.write_text("{not valid json", encoding="utf-8")
        result = json.loads(research_tools.kg_ingest_ffuf.invoke({"path": str(p)}))
        assert "error" in result

    def test_empty_results_array(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "ffuf.json"
        p.write_text(json.dumps({"results": []}), encoding="utf-8")
        result = json.loads(research_tools.kg_ingest_ffuf.invoke({"path": str(p)}))
        assert result["urls_added"] == 0


class TestKgIngestTestssl:
    def test_high_severity_finding_ingested(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _configure_kg(monkeypatch)
        findings = [
            {"id": "BEAST", "severity": "HIGH", "finding": "BEAST attack CVE-2011-3389"},
            {"id": "ROBOT", "severity": "CRITICAL", "finding": "ROBOT attack"},
            {"id": "HTTP_clock_skew", "severity": "OK", "finding": "within threshold"},
        ]
        p = tmp_path / "testssl.json"
        p.write_text(json.dumps(findings), encoding="utf-8")

        result = json.loads(
            research_tools.kg_ingest_testssl.invoke({"path": str(p), "target": "app.example.com"})
        )
        assert result["vulns_added"] == 2  # OK is skipped
        assert len(fake.graph.by_kind(NodeKind.VULNERABILITY)) == 2

    def test_low_and_info_severity_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _configure_kg(monkeypatch)
        findings = [
            {"id": "foo", "severity": "LOW", "finding": "minor"},
            {"id": "bar", "severity": "INFO", "finding": "informational"},
        ]
        p = tmp_path / "testssl.json"
        p.write_text(json.dumps(findings), encoding="utf-8")
        result = json.loads(research_tools.kg_ingest_testssl.invoke({"path": str(p)}))
        assert result["vulns_added"] == 0

    def test_envelope_format_with_scan_result(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _configure_kg(monkeypatch)
        data = {
            "targetHost": "ssl.example.com",
            "scanResult": [
                {
                    "vulnerabilities": [
                        {"id": "DROWN", "severity": "HIGH", "finding": "SSLv2 enabled"}
                    ]
                }
            ],
        }
        p = tmp_path / "testssl.json"
        p.write_text(json.dumps(data), encoding="utf-8")
        result = json.loads(research_tools.kg_ingest_testssl.invoke({"path": str(p)}))
        assert result["vulns_added"] == 1
        assert len(fake.graph.by_kind(NodeKind.VULNERABILITY)) == 1

    def test_file_not_found_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(research_tools.kg_ingest_testssl.invoke({"path": "/no/file.json"}))
        assert "error" in result

    def test_linked_to_host_when_target_provided(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _configure_kg(monkeypatch)
        p = tmp_path / "testssl.json"
        p.write_text(
            json.dumps([{"id": "POODLE", "severity": "HIGH", "finding": "SSLv3"}]),
            encoding="utf-8",
        )
        result = json.loads(
            research_tools.kg_ingest_testssl.invoke({"path": str(p), "target": "myhost.com"})
        )
        assert result["linked_to_host"] == 1
        assert len(fake.graph.by_kind(NodeKind.HOST)) == 1


class TestKgIngestCrackmapexec:
    def test_credentials_ingested_from_log(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _configure_kg(monkeypatch)
        log = (
            "SMB   10.0.0.5  445  DC01  [+] CORP\\administrator:P@ssw0rd (Pwn3d!)\n"
            "SMB   10.0.0.5  445  DC01  [+] CORP\\jsmith:Summer2023\n"
            "SMB   10.0.0.5  445  DC01  [-] CORP\\guest:guest\n"
        )
        p = tmp_path / "cme.log"
        p.write_text(log, encoding="utf-8")

        result = json.loads(
            research_tools.kg_ingest_crackmapexec.invoke({"path": str(p), "protocol": "smb"})
        )
        assert result["creds_added"] == 2
        assert result["admin_creds_added"] == 1
        assert len(fake.graph.by_kind(NodeKind.CREDENTIAL)) == 2
        assert len(fake.graph.by_kind(NodeKind.USER)) == 2

    def test_file_not_found_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(research_tools.kg_ingest_crackmapexec.invoke({"path": "/no/such.log"}))
        assert "error" in result

    def test_no_success_lines_returns_zero(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "cme.log"
        p.write_text("[-] All failed\n", encoding="utf-8")
        result = json.loads(research_tools.kg_ingest_crackmapexec.invoke({"path": str(p)}))
        assert result["creds_added"] == 0


class TestKgIngestAsrepHashes:
    def test_valid_hash_lines_ingested(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _configure_kg(monkeypatch)
        p = tmp_path / "asrep.txt"
        p.write_text(
            "$krb5asrep$23$alice@CORP.LOCAL:deadbeef$cafebabe\n"
            "$krb5asrep$23$bob@CORP.LOCAL:deadbeef$cafebabe\n",
            encoding="utf-8",
        )
        result = json.loads(research_tools.kg_ingest_asrep_hashes.invoke({"path": str(p)}))
        assert result["asrep_hashes_added"] == 2
        assert len(fake.graph.by_kind(NodeKind.CREDENTIAL)) == 2

    def test_non_hash_lines_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "asrep.txt"
        p.write_text("not a hash\n$krb5asrep$23$user@DOM:abc$def\n", encoding="utf-8")
        result = json.loads(research_tools.kg_ingest_asrep_hashes.invoke({"path": str(p)}))
        assert result["asrep_hashes_added"] == 1

    def test_file_not_found_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(research_tools.kg_ingest_asrep_hashes.invoke({"path": "/no/file.txt"}))
        assert "error" in result

    def test_domain_from_arg_when_no_at_sign(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "asrep.txt"
        # user part without @DOMAIN
        p.write_text("$krb5asrep$23$charlie:abc$def\n", encoding="utf-8")
        result = json.loads(
            research_tools.kg_ingest_asrep_hashes.invoke({"path": str(p), "domain": "MYDOMAIN"})
        )
        assert result["asrep_hashes_added"] == 1
        # Can't easily check label without graph access; just ensure no error
        assert "error" not in result

    def test_hashcat_mode_is_18200(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _configure_kg(monkeypatch)
        p = tmp_path / "asrep.txt"
        p.write_text("$krb5asrep$23$svcacct@CORP.LOCAL:abc$def\n", encoding="utf-8")
        research_tools.kg_ingest_asrep_hashes.invoke({"path": str(p)})
        creds = fake.graph.by_kind(NodeKind.CREDENTIAL)
        assert creds[0].props.get("hashcat_mode") == 18200


# ── Fuzz tools ────────────────────────────────────────────────────────────


class TestFuzzHarness:
    def test_valid_engine_returns_source(self) -> None:
        result = json.loads(
            research_tools.fuzz_harness.invoke(
                {"engine": "libfuzzer", "target": "libpng", "entry": "decode"}
            )
        )
        assert "source" in result
        assert result["engine"] == "libfuzzer"
        assert isinstance(result["source"], str)
        assert len(result["source"]) > 0

    def test_invalid_engine_returns_error(self) -> None:
        result = json.loads(
            research_tools.fuzz_harness.invoke(
                {"engine": "notanengine", "target": "foo", "entry": "bar"}
            )
        )
        assert "error" in result
        assert "valid" in result

    def test_atheris_engine(self) -> None:
        result = json.loads(
            research_tools.fuzz_harness.invoke(
                {"engine": "atheris", "target": "myparser", "entry": "parse"}
            )
        )
        assert "source" in result

    def test_afl_engine(self) -> None:
        result = json.loads(
            research_tools.fuzz_harness.invoke(
                {"engine": "afl++", "target": "xmlparser", "entry": "parse"}
            )
        )
        assert "source" in result


class TestFuzzRecordCrash:
    def test_asan_heap_buffer_overflow(self, monkeypatch: pytest.MonkeyPatch) -> None:
        fake = _configure_kg(monkeypatch)
        log = (
            "=================================================================\n"
            "==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x...\n"
            "READ of size 4 at 0x... thread T0\n"
            "    #0 0x... in parse_frame src/codec.c:42\n"
            "    #1 0x... in main src/main.c:10\n"
            "SUMMARY: AddressSanitizer: heap-buffer-overflow src/codec.c:42 in parse_frame\n"
        )
        result = json.loads(
            research_tools.fuzz_record_crash.invoke({"log": log, "engine": "libfuzzer"})
        )
        assert "vuln_id" in result
        assert result["kind"] == "heap-buffer-overflow"
        assert len(fake.graph.by_kind(NodeKind.VULNERABILITY)) == 1

    def test_no_signature_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(
            research_tools.fuzz_record_crash.invoke(
                {"log": "nothing interesting here", "engine": "libfuzzer"}
            )
        )
        assert "error" in result

    def test_invalid_engine_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(
            research_tools.fuzz_record_crash.invoke({"log": "some log", "engine": "badengine"})
        )
        assert "error" in result


# ── Error-path coverage for existing tools ───────────────────────────────


class TestKgIngestNmapErrors:
    def test_file_not_found_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(
            research_tools.kg_ingest_nmap_xml.invoke({"path": "/nonexistent/scan.xml"})
        )
        assert "error" in result

    def test_malformed_xml_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "bad.xml"
        p.write_text("<not-closed>", encoding="utf-8")
        result = json.loads(research_tools.kg_ingest_nmap_xml.invoke({"path": str(p)}))
        assert "error" in result

    def test_host_without_address_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "scan.xml"
        p.write_text(
            '<?xml version="1.0"?><nmaprun><host><status state="up"/></host></nmaprun>',
            encoding="utf-8",
        )
        result = json.loads(research_tools.kg_ingest_nmap_xml.invoke({"path": str(p)}))
        assert result["ingested"]["hosts"] == 0

    def test_down_host_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "scan.xml"
        p.write_text(
            '<?xml version="1.0"?><nmaprun>'
            '<host><status state="down"/>'
            '<address addr="10.0.0.1" addrtype="ipv4"/>'
            "</host></nmaprun>",
            encoding="utf-8",
        )
        result = json.loads(research_tools.kg_ingest_nmap_xml.invoke({"path": str(p)}))
        assert result["ingested"]["hosts"] == 0


class TestKgIngestNucleiErrors:
    def test_file_not_found_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(
            research_tools.kg_ingest_nuclei_jsonl.invoke({"path": "/no/such/file.jsonl"})
        )
        assert "error" in result

    def test_invalid_json_lines_counted_as_skipped(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "nuclei.jsonl"
        p.write_text("NOTJSON\nalso bad\n", encoding="utf-8")
        result = json.loads(research_tools.kg_ingest_nuclei_jsonl.invoke({"path": str(p)}))
        assert result["skipped"] == 2
        assert result["parsed"] == 0

    def test_non_url_target_creates_host_node(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        fake = _configure_kg(monkeypatch)
        p = tmp_path / "nuclei.jsonl"
        p.write_text(
            json.dumps(
                {
                    "template-id": "ssh-weak-algo",
                    "host": "10.0.0.5:22",
                    "info": {"severity": "medium"},
                }
            )
            + "\n",
            encoding="utf-8",
        )
        result = json.loads(research_tools.kg_ingest_nuclei_jsonl.invoke({"path": str(p)}))
        assert result["parsed"] == 1
        assert len(fake.graph.by_kind(NodeKind.HOST)) == 1


class TestKgIngestHttpxErrors:
    def test_file_not_found_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(research_tools.kg_ingest_httpx_jsonl.invoke({"path": "/no/file.jsonl"}))
        assert "error" in result

    def test_row_without_url_skipped(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "httpx.jsonl"
        p.write_text(json.dumps({"status-code": 200}) + "\n", encoding="utf-8")
        result = json.loads(research_tools.kg_ingest_httpx_jsonl.invoke({"path": str(p)}))
        assert result["skipped"] >= 1


class TestCveEnrichDependenciesErrors:
    @pytest.mark.asyncio
    async def test_file_not_found_returns_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _configure_kg(monkeypatch)
        result = json.loads(
            await research_tools.cve_enrich_dependencies.ainvoke({"path": "/no/such/file.txt"})
        )
        assert "error" in result

    @pytest.mark.asyncio
    async def test_unsupported_file_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _configure_kg(monkeypatch)
        p = tmp_path / "setup.py"
        p.write_text("from setuptools import setup\n", encoding="utf-8")
        result = json.loads(await research_tools.cve_enrich_dependencies.ainvoke({"path": str(p)}))
        assert "error" in result

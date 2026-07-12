# -*- coding: utf-8 -*-
"""Tests for decepticon.cli.scan (parsing + scope resolution; live LangGraph not invoked)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from decepticon.cli.scan import (
    EXIT_CONFIG,
    EXIT_FINDINGS,
    EXIT_OK,
    _build_parser,
    _instruction_text,
    _resolve_engagement_name,
    _validate_targets,
    _write_sarif_and_gate,
)


def test_parser_accepts_strix_compatible_flags():
    parser = _build_parser()
    args = parser.parse_args(
        [
            "--target",
            "./",
            "--scan-mode",
            "quick",
            "--scope-mode",
            "diff",
            "--diff-base",
            "origin/main",
            "--sarif-output",
            "out.sarif",
            "--non-interactive",
        ]
    )
    assert args.target == ["./"]
    assert args.scan_mode == "quick"
    assert args.scope_mode == "diff"
    assert args.diff_base == "origin/main"
    assert args.sarif_output == Path("out.sarif")
    assert args.non_interactive is True


def test_parser_multiple_targets_repeat_flag():
    parser = _build_parser()
    args = parser.parse_args(["--target", "a", "-t", "b"])
    assert args.target == ["a", "b"]


def test_validate_targets_rejects_empty():
    assert _validate_targets([]) is not None


def test_validate_targets_accepts_http_urls():
    assert _validate_targets(["https://example.com"]) is None


def test_validate_targets_accepts_git_urls():
    assert _validate_targets(["git@github.com:org/repo.git"]) is None
    assert _validate_targets(["git+https://x/y.git"]) is None


def test_validate_targets_rejects_nonexistent_path(tmp_path: Path):
    bogus = str(tmp_path / "absolutely-not-here")
    err = _validate_targets([bogus])
    assert err is not None and "does not exist" in err


def test_validate_targets_accepts_existing_path(tmp_path: Path):
    assert _validate_targets([str(tmp_path)]) is None


def test_resolve_engagement_name_uses_supplied():
    assert _resolve_engagement_name("custom") == "custom"


def test_resolve_engagement_name_timestamped_default():
    name = _resolve_engagement_name(None)
    assert name.startswith("scan-")
    assert len(name) > len("scan-")


def test_instruction_text_combines_flag_and_file(tmp_path: Path):
    file_path = tmp_path / "roe.md"
    file_path.write_text("Out of scope: production database servers.\n")

    parser = _build_parser()
    args = parser.parse_args(
        [
            "--target",
            str(tmp_path),
            "--instruction",
            "Focus on auth flows.",
            "--instruction-file",
            str(file_path),
        ]
    )
    text = _instruction_text(args)
    assert "Focus on auth flows." in text
    assert "Out of scope: production database servers." in text


def test_instruction_text_missing_file_raises(tmp_path: Path):
    parser = _build_parser()
    args = parser.parse_args(
        [
            "--target",
            str(tmp_path),
            "--instruction-file",
            str(tmp_path / "nope.md"),
        ]
    )
    with pytest.raises(RuntimeError):
        _instruction_text(args)


def test_write_sarif_and_gate_no_graph_no_output(tmp_path: Path):
    out = tmp_path / "x.sarif"
    code = _write_sarif_and_gate(
        graph=None,
        sarif_output=out,
        fail_on="high",
        engagement_name="t",
    )
    assert code == EXIT_OK
    assert out.exists()
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"] == []


class _Node:
    def __init__(self, node_id, kind, label, props):
        self.id = node_id
        self.kind = kind
        self.label = label
        self.properties = props


class _Graph:
    def __init__(self, nodes):
        self.nodes = {n.id: n for n in nodes}


def test_write_sarif_and_gate_with_high_finding_returns_findings_exit(tmp_path: Path):
    graph = _Graph([_Node("f1", "finding", "f1", {"severity": "high", "vuln_class": "sqli"})])
    out = tmp_path / "scan.sarif"
    code = _write_sarif_and_gate(
        graph=graph,
        sarif_output=out,
        fail_on="high",
        engagement_name="t",
    )
    assert code == EXIT_FINDINGS
    doc = json.loads(out.read_text(encoding="utf-8"))
    assert len(doc["runs"][0]["results"]) == 1


def test_write_sarif_and_gate_with_only_low_findings_returns_ok(tmp_path: Path):
    graph = _Graph([_Node("f1", "finding", "f1", {"severity": "low"})])
    out = tmp_path / "scan.sarif"
    code = _write_sarif_and_gate(
        graph=graph,
        sarif_output=out,
        fail_on="high",
        engagement_name="t",
    )
    assert code == EXIT_OK


def test_write_sarif_and_gate_skips_output_when_unset():
    graph = _Graph([_Node("f1", "finding", "f1", {"severity": "low"})])
    code = _write_sarif_and_gate(
        graph=graph,
        sarif_output=None,
        fail_on="high",
        engagement_name="t",
    )
    assert code == EXIT_OK


def test_exit_codes_are_disjoint():
    from decepticon.cli.scan import EXIT_FINDINGS, EXIT_INTERNAL, EXIT_OK

    assert len({EXIT_OK, EXIT_FINDINGS, EXIT_CONFIG, EXIT_INTERNAL}) == 4

# -*- coding: utf-8 -*-
"""Tests for decepticon.tools.evidence."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from decepticon.tools.evidence.asciicast import (
    AsciicastExportError,
    _load_sidecar,
    _segments_from_markers,
    export_asciicast,
    list_recordings,
)


def test_segments_split_on_ps1_markers():
    content = (
        "first command output\n"
        "DECEPTICON_PROMPT_END_a1b2c3\n"
        "second command output\n"
        "DECEPTICON_PROMPT_END_a1b2c3\n"
        "trailing\n"
    )
    segments = _segments_from_markers(content)
    assert len(segments) == 3
    assert "first" in segments[0]
    assert "second" in segments[1]
    assert "trailing" in segments[2]


def test_segments_handles_no_markers():
    content = "just one block of output"
    segments = _segments_from_markers(content)
    assert segments == [content]


def test_segments_drops_empty():
    content = "DECEPTICON_PROMPT_END_xx\n\n\nDECEPTICON_PROMPT_END_xx"
    assert _segments_from_markers(content) == []


def test_load_sidecar_missing_returns_none(tmp_path: Path):
    log = tmp_path / "x.log"
    log.write_text("")
    assert _load_sidecar(log) is None


def test_load_sidecar_relative_timestamps(tmp_path: Path):
    log = tmp_path / "x.log"
    log.write_text("")
    sidecar = tmp_path / "x.log.events"
    sidecar.write_text("1000.0 dispatched cmd_a\n1002.5 dispatched cmd_b\n")
    parsed = _load_sidecar(log)
    assert parsed is not None
    assert parsed[0][0] == 0.0
    assert parsed[1][0] == 2.5


def test_load_sidecar_skips_malformed_lines(tmp_path: Path):
    log = tmp_path / "x.log"
    log.write_text("")
    sidecar = tmp_path / "x.log.events"
    sidecar.write_text("nope\n1000.0 ok\nalso-nope\n1001.0 also-ok\n")
    parsed = _load_sidecar(log)
    assert parsed is not None
    assert len(parsed) == 2


def test_export_asciicast_missing_log_raises(tmp_path: Path):
    with pytest.raises(AsciicastExportError):
        export_asciicast(
            log_path=tmp_path / "nope.log",
            output_path=tmp_path / "out.cast",
        )


def test_export_asciicast_synthetic_timing(tmp_path: Path):
    log = tmp_path / "s.log"
    log.write_text("first\nDECEPTICON_PROMPT_END_xx\nsecond\nDECEPTICON_PROMPT_END_xx\n")
    out = tmp_path / "s.cast"
    manifest = export_asciicast(
        log_path=log,
        output_path=out,
        session_name="s",
    )
    assert manifest["timing_quality"] == "synthetic"
    assert manifest["segments"] == 2
    assert out.exists()
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    header = json.loads(lines[0])
    assert header["version"] == 2
    event0 = json.loads(lines[1])
    assert event0[0] == 0.0
    assert event0[1] == "o"


def test_export_asciicast_measured_timing(tmp_path: Path):
    log = tmp_path / "m.log"
    log.write_text("first\nDECEPTICON_PROMPT_END_xx\nsecond\nDECEPTICON_PROMPT_END_xx\n")
    (tmp_path / "m.log.events").write_text("1000.0 dispatched\n1003.5 dispatched\n")
    out = tmp_path / "m.cast"
    manifest = export_asciicast(
        log_path=log,
        output_path=out,
        session_name="m",
    )
    assert manifest["timing_quality"] == "measured"
    assert manifest["duration_seconds"] == 3.5


def test_export_asciicast_writes_manifest_sidecar(tmp_path: Path):
    log = tmp_path / "x.log"
    log.write_text("hello\n")
    out = tmp_path / "x.cast"
    manifest = export_asciicast(
        log_path=log,
        output_path=out,
        session_name="x",
    )
    manifest_file = out.with_suffix(out.suffix + ".manifest.json")
    assert manifest_file.exists()
    reloaded = json.loads(manifest_file.read_text(encoding="utf-8"))
    assert reloaded["session_name"] == "x"
    assert reloaded["asciicast_path"] == manifest["asciicast_path"]


def test_list_recordings_empty_dir_returns_empty(tmp_path: Path):
    assert list_recordings(tmp_path) == []


def test_list_recordings_collects_manifests(tmp_path: Path):
    (tmp_path / "a.cast.manifest.json").write_text(
        json.dumps({"session_name": "a", "duration_seconds": 1.0})
    )
    (tmp_path / "b.cast.manifest.json").write_text(
        json.dumps({"session_name": "b", "duration_seconds": 2.0})
    )
    out = list_recordings(tmp_path)
    assert len(out) == 2
    names = sorted(m["session_name"] for m in out)
    assert names == ["a", "b"]


def test_list_recordings_skips_malformed(tmp_path: Path):
    (tmp_path / "good.cast.manifest.json").write_text(json.dumps({"session_name": "good"}))
    (tmp_path / "bad.cast.manifest.json").write_text("not json")
    out = list_recordings(tmp_path)
    assert len(out) == 1

"""Tests for decepticon.runtime.recording."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from langchain_core.messages import AIMessage

from decepticon.runtime.recording import (
    ReplayMiddleware,
    ReplayMismatchError,
    _canonicalize,
    _hash_request,
    _serialize_ai_response,
    _serialize_model_request,
    _serialize_tool_request,
    open_record,
    open_replay,
)


def test_canonicalize_drops_volatile_fields():
    out = _canonicalize({"id": "x", "timestamp": "now", "real": 42, "run_id": "r"})
    assert out == {"real": 42}


def test_canonicalize_recurses_into_nested_dicts():
    out = _canonicalize({"outer": {"id": "drop", "keep": 1}})
    assert out == {"outer": {"keep": 1}}


def test_canonicalize_recurses_into_lists():
    out = _canonicalize([{"id": "drop", "n": 1}, {"id": "drop", "n": 2}])
    assert out == [{"n": 1}, {"n": 2}]


def test_hash_request_is_stable_across_ordering():
    h1 = _hash_request({"a": 1, "b": 2})
    h2 = _hash_request({"b": 2, "a": 1})
    assert h1 == h2


def test_hash_request_ignores_timestamp():
    h1 = _hash_request({"msg": "hi", "timestamp": "2024-01-01"})
    h2 = _hash_request({"msg": "hi", "timestamp": "2026-12-31"})
    assert h1 == h2


def test_hash_request_differs_on_real_content():
    assert _hash_request({"msg": "a"}) != _hash_request({"msg": "b"})


def test_open_record_appends_and_seq_increments(tmp_path: Path):
    path = tmp_path / "out.jsonl"
    sink = open_record(path)
    sink.write({"kind": "model_call", "req_hash": "h1", "x": 1})
    sink.write({"kind": "tool_call", "req_hash": "h2", "x": 2})
    sink.close()
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["seq"] == 0
    assert json.loads(lines[1])["seq"] == 1


def test_open_replay_indexes_by_req_hash(tmp_path: Path):
    path = tmp_path / "in.jsonl"
    path.write_text(
        '{"kind":"model_call","req_hash":"H1","response":{"content":"hello"}}\n'
        '{"kind":"tool_call","req_hash":"H2","response":{"content":"world"}}\n',
        encoding="utf-8",
    )
    replay = open_replay(path)
    assert replay.lookup_model("H1") is not None
    assert replay.lookup_tool("H2") is not None
    assert replay.lookup_model("nope") is None
    assert replay.stats == {"model_calls": 1, "tool_calls": 1}


def test_open_replay_skips_malformed_lines(tmp_path: Path):
    path = tmp_path / "in.jsonl"
    path.write_text(
        '{"kind":"model_call","req_hash":"H1","response":{}}\n'
        "not json\n"
        '{"kind":"tool_call","req_hash":"H2","response":{}}\n',
        encoding="utf-8",
    )
    replay = open_replay(path)
    assert replay.stats == {"model_calls": 1, "tool_calls": 1}


def test_replay_mismatch_error_has_useful_fields():
    err = ReplayMismatchError("model_call", "sha256:abc", available_hashes=42)
    assert err.kind == "model_call"
    assert err.req_hash == "sha256:abc"
    assert err.available_hashes == 42
    assert "42 hashes recorded" in str(err)


def test_open_replay_missing_file_raises(tmp_path: Path):
    with pytest.raises(FileNotFoundError):
        open_replay(tmp_path / "missing.jsonl")


class _ToolStub:
    def __init__(self, name: str) -> None:
        self.name = name


class _ToolCallRequestStub:
    def __init__(self, tool_name: str, args: dict[str, object]) -> None:
        self.tool = _ToolStub(tool_name)
        self.tool_call = {"name": tool_name, "args": args}


def test_serialize_tool_request_captures_args_from_tool_call():
    serialized = _serialize_tool_request(_ToolCallRequestStub("bash", {"command": "ls -la"}))
    assert serialized == {"tool": "bash", "args": {"command": "ls -la"}}


def test_same_tool_different_args_hash_differently():
    req_a = _serialize_tool_request(_ToolCallRequestStub("bash", {"command": "whoami"}))
    req_b = _serialize_tool_request(_ToolCallRequestStub("bash", {"command": "id"}))
    assert _hash_request(req_a) != _hash_request(req_b)


def test_ai_response_additional_kwargs_round_trips():
    message = AIMessage(content="answer", additional_kwargs={"reasoning_content": "X"})
    serialized = _serialize_ai_response(message)
    assert serialized["additional_kwargs"] == {"reasoning_content": "X"}
    reconstructed = ReplayMiddleware(path=None)._model_response({"response": serialized})
    assert reconstructed.additional_kwargs["reasoning_content"] == "X"


class _ModelStub:
    def __init__(self, model_name: str) -> None:
        self.model_name = model_name
        self.name = None


class _ModelRequestStub:
    def __init__(self, model_name: str) -> None:
        self.model = _ModelStub(model_name)
        self.system_message = None
        self.messages = []
        self.tools = []


def test_serialize_model_request_records_model_name():
    serialized = _serialize_model_request(_ModelRequestStub("deepseek-reasoner"))
    assert serialized["model"] == "deepseek-reasoner"

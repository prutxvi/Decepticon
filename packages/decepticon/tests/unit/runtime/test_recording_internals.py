"""Serializer + record/replay-middleware coverage for
``decepticon.runtime.recording``.

``test_recording.py`` covers ``_canonicalize`` / ``_hash_request`` and the
basic sink/replay round-trip. This file adds the previously-uncovered parts:

* the five ``_serialize_*`` functions that turn live model/tool
  requests + responses into the stable on-disk shape (a wrong field here
  silently changes the request hash, so a replay never matches);
* ``_Replay`` skipping of entries missing ``kind`` / ``req_hash``;
* the ``RecordingMiddleware`` → ``ReplayMiddleware`` **round-trip** — the
  module's whole reason to exist: a recorded request must be served
  deterministically on replay (strict), mismatch must raise (strict) or
  fall through to the live handler (non-strict), and an unset path must
  be a pure passthrough. Sync + async + tool paths all covered.

Pure-logic + tmp_path; no network / docker / LLM.
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage, HumanMessage, ToolMessage

from decepticon.runtime.recording import (
    RecordingMiddleware,
    ReplayMiddleware,
    ReplayMismatchError,
    _serialize_ai_response,
    _serialize_messages,
    _serialize_model_request,
    _serialize_tool_request,
    _serialize_tool_response,
    open_replay,
)


def _model_request(content: str = "hi", model_name: str = "m1") -> SimpleNamespace:
    return SimpleNamespace(
        system_message=SimpleNamespace(content="sys"),
        model=SimpleNamespace(name=model_name),
        messages=[HumanMessage(content=content)],
        tools=[SimpleNamespace(name="bash")],
    )


def _tool_request(tool_name: str = "bash", args: dict | None = None) -> SimpleNamespace:
    return SimpleNamespace(
        tool=SimpleNamespace(name=tool_name),
        tool_call={"args": args if args is not None else {"cmd": "id"}},
    )


def _close(mw: RecordingMiddleware) -> None:
    if mw._sink is not None:
        mw._sink.close()


# ---------------------------------------------------------------- serializers


def test_serialize_messages_includes_only_truthy_optionals():
    msg = SimpleNamespace(
        type="ai",
        content="hi",
        name="bot",
        tool_calls=[{"id": "1"}],
        tool_call_id="",  # falsy -> omitted
        additional_kwargs={},  # falsy -> omitted
    )
    (entry,) = _serialize_messages([msg])
    assert entry == {"type": "ai", "content": "hi", "name": "bot", "tool_calls": [{"id": "1"}]}


def test_serialize_messages_falls_back_to_class_name():
    class Weird:
        content = "x"

    (entry,) = _serialize_messages([Weird()])
    assert entry["type"] == "Weird"
    assert entry["content"] == "x"


def test_serialize_messages_empty_and_none():
    assert _serialize_messages([]) == []
    assert _serialize_messages(None) == []


def test_serialize_model_request_shape():
    out = _serialize_model_request(_model_request("hi", "gpt"))
    assert out["model"] == "gpt"
    assert out["system"] == "sys"
    assert out["tools"] == ["bash"]
    assert out["messages"][0]["content"] == "hi"


def test_serialize_model_request_handles_missing_system():
    req = SimpleNamespace(
        system_message=None, model=SimpleNamespace(name="m"), messages=[], tools=[]
    )
    out = _serialize_model_request(req)
    assert out["system"] == ""
    assert out["messages"] == []


def test_serialize_tool_request_shape_and_missing_tool():
    out = _serialize_tool_request(_tool_request("nmap", {"target": "x"}))
    assert out == {"tool": "nmap", "args": {"target": "x"}}

    out2 = _serialize_tool_request(SimpleNamespace(tool=None, tool_call_args={}))
    assert out2 == {"tool": "", "args": {}}


def test_serialize_ai_response_shape():
    out = _serialize_ai_response(AIMessage(content="hi"))
    assert out["content"] == "hi"
    assert out["type"] == "ai"
    assert out["tool_calls"] == []


def test_serialize_tool_response_shape():
    out = _serialize_tool_response(
        ToolMessage(content="r", tool_call_id="t", name="bash", status="success")
    )
    assert out["type"] == "tool"
    assert out["content"] == "r"
    assert out["tool_call_id"] == "t"
    assert out["name"] == "bash"
    assert out["status"] == "success"


# ---------------------------------------------------------------- _Replay edges


def test_replay_skips_entries_missing_kind_or_hash(tmp_path: Path):
    path = tmp_path / "in.jsonl"
    path.write_text(
        '{"kind":"model_call","req_hash":"H1","response":{}}\n'
        '{"req_hash":"H2","response":{}}\n'  # missing kind
        '{"kind":"tool_call","response":{}}\n'  # missing req_hash
        '{"kind":"other","req_hash":"H3"}\n',  # unknown kind -> indexed nowhere
        encoding="utf-8",
    )
    replay = open_replay(path)
    assert replay.stats == {"model_calls": 1, "tool_calls": 0}


# ---------------------------------------------------------------- record disabled


def test_recording_disabled_is_passthrough(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DECEPTICON_RUNTIME__RECORD_PATH", raising=False)
    rec = RecordingMiddleware()
    assert rec._sink is None
    out = rec.wrap_model_call(_model_request(), lambda _r: AIMessage(content="X"))
    assert out.content == "X"


def test_replay_disabled_is_passthrough(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DECEPTICON_RUNTIME__REPLAY_PATH", raising=False)
    rep = ReplayMiddleware()
    assert rep._replay is None
    out = rep.wrap_model_call(_model_request(), lambda _r: AIMessage(content="X"))
    assert out.content == "X"


# ---------------------------------------------------------------- model round-trip


def test_record_then_replay_model_roundtrip(tmp_path: Path):
    rec_path = tmp_path / "rec.jsonl"
    req = _model_request("hi", "m1")

    rec = RecordingMiddleware(path=rec_path)
    out = rec.wrap_model_call(req, lambda _r: AIMessage(content="hello"))
    _close(rec)
    assert out.content == "hello"

    rep = ReplayMiddleware(path=rec_path, strict=True)

    def _boom(_r):
        raise AssertionError("handler must not run on a replay hit")

    served = rep.wrap_model_call(req, _boom)
    assert isinstance(served, AIMessage)
    assert served.content == "hello"


def test_replay_strict_mismatch_raises(tmp_path: Path):
    rec_path = tmp_path / "rec.jsonl"
    rec = RecordingMiddleware(path=rec_path)
    rec.wrap_model_call(_model_request("hi", "m1"), lambda _r: AIMessage(content="hello"))
    _close(rec)

    rep = ReplayMiddleware(path=rec_path, strict=True)
    with pytest.raises(ReplayMismatchError):
        rep.wrap_model_call(_model_request("DIFFERENT", "m9"), lambda _r: AIMessage(content="x"))


def test_replay_non_strict_miss_falls_through_to_handler(tmp_path: Path):
    rec_path = tmp_path / "rec.jsonl"
    rec = RecordingMiddleware(path=rec_path)
    rec.wrap_model_call(_model_request("hi", "m1"), lambda _r: AIMessage(content="hello"))
    _close(rec)

    rep = ReplayMiddleware(path=rec_path, strict=False)
    out = rep.wrap_model_call(_model_request("other", "m9"), lambda _r: AIMessage(content="LIVE"))
    assert out.content == "LIVE"


async def test_async_record_then_replay_model_roundtrip(tmp_path: Path):
    rec_path = tmp_path / "rec.jsonl"
    req = _model_request("hi", "m1")

    rec = RecordingMiddleware(path=rec_path)

    async def _h(_r):
        return AIMessage(content="async-hi")

    out = await rec.awrap_model_call(req, _h)
    _close(rec)
    assert out.content == "async-hi"

    rep = ReplayMiddleware(path=rec_path, strict=True)

    async def _boom(_r):
        raise AssertionError("handler must not run on a replay hit")

    served = await rep.awrap_model_call(req, _boom)
    assert served.content == "async-hi"


# ---------------------------------------------------------------- tool round-trip


def test_record_then_replay_tool_roundtrip(tmp_path: Path):
    rec_path = tmp_path / "rec.jsonl"
    req = _tool_request("bash", {"cmd": "id"})
    resp = ToolMessage(content="uid=0", tool_call_id="tc1", name="bash", status="success")

    rec = RecordingMiddleware(path=rec_path)
    out = rec.wrap_tool_call(req, lambda _r: resp)
    _close(rec)
    assert out is resp

    rep = ReplayMiddleware(path=rec_path, strict=True)

    def _boom(_r):
        raise AssertionError("handler must not run on a replay hit")

    served = rep.wrap_tool_call(req, _boom)
    assert isinstance(served, ToolMessage)
    assert served.content == "uid=0"
    assert served.tool_call_id == "tc1"


def test_record_tool_non_toolmessage_is_marked_command(tmp_path: Path):
    rec_path = tmp_path / "rec.jsonl"
    rec = RecordingMiddleware(path=rec_path)
    sentinel = SimpleNamespace(foo="bar")  # e.g. a Command, not a ToolMessage
    out = rec.wrap_tool_call(_tool_request(), lambda _r: sentinel)
    _close(rec)
    assert out is sentinel
    line = json.loads(rec_path.read_text(encoding="utf-8").strip().splitlines()[0])
    assert line["response"] == {"type": "command"}


async def test_async_tool_roundtrip(tmp_path: Path):
    rec_path = tmp_path / "rec.jsonl"
    req = _tool_request("nmap", {"target": "10.0.0.1"})
    resp = ToolMessage(content="open: 22", tool_call_id="tc2", name="nmap", status="success")

    rec = RecordingMiddleware(path=rec_path)

    async def _h(_r):
        return resp

    await rec.awrap_tool_call(req, _h)
    _close(rec)

    rep = ReplayMiddleware(path=rec_path, strict=True)

    async def _boom(_r):
        raise AssertionError("handler must not run on a replay hit")

    served = await rep.awrap_tool_call(req, _boom)
    assert served.content == "open: 22"
    assert served.name == "nmap"


# ---------------------------------------------------------------- disabled (async/tool)
async def test_recording_disabled_async_and_tool_passthrough(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DECEPTICON_RUNTIME__RECORD_PATH", raising=False)
    rec = RecordingMiddleware()

    async def _m(_r):
        return AIMessage(content="M")

    async def _t(_r):
        return "T"

    assert (await rec.awrap_model_call(_model_request(), _m)).content == "M"
    assert rec.wrap_tool_call(_tool_request(), lambda _r: "S") == "S"
    assert await rec.awrap_tool_call(_tool_request(), _t) == "T"


def test_replay_disabled_async_and_tool_passthrough(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("DECEPTICON_RUNTIME__REPLAY_PATH", raising=False)
    rep = ReplayMiddleware()
    assert rep.wrap_tool_call(_tool_request(), lambda _r: "S") == "S"


# ---------------------------------------------------------------- replay miss branches
def _boom_sync(_r):
    raise AssertionError("handler must not run on a replay hit")


async def test_async_replay_strict_model_mismatch_raises(tmp_path: Path):
    rec_path = tmp_path / "rec.jsonl"
    rec = RecordingMiddleware(path=rec_path)
    rec.wrap_model_call(_model_request("hi", "m1"), lambda _r: AIMessage(content="hello"))
    _close(rec)
    rep = ReplayMiddleware(path=rec_path, strict=True)

    async def _h(_r):
        return AIMessage(content="x")

    with pytest.raises(ReplayMismatchError):
        await rep.awrap_model_call(_model_request("DIFF", "m9"), _h)


def test_replay_strict_tool_mismatch_raises(tmp_path: Path):
    rec_path = tmp_path / "rec.jsonl"
    rec = RecordingMiddleware(path=rec_path)
    resp = ToolMessage(content="r", tool_call_id="t", name="bash", status="success")
    rec.wrap_tool_call(_tool_request("bash", {"cmd": "id"}), lambda _r: resp)
    _close(rec)
    rep = ReplayMiddleware(path=rec_path, strict=True)
    with pytest.raises(ReplayMismatchError):
        rep.wrap_tool_call(_tool_request("nmap", {"x": "y"}), _boom_sync)


def test_replay_non_strict_tool_miss_falls_through(tmp_path: Path):
    rec_path = tmp_path / "rec.jsonl"
    rec = RecordingMiddleware(path=rec_path)
    resp = ToolMessage(content="r", tool_call_id="t", name="bash", status="success")
    rec.wrap_tool_call(_tool_request("bash", {"cmd": "id"}), lambda _r: resp)
    _close(rec)
    rep = ReplayMiddleware(path=rec_path, strict=False)
    live = ToolMessage(content="LIVE", tool_call_id="t2", name="nmap", status="success")
    out = rep.wrap_tool_call(_tool_request("nmap", {"x": "y"}), lambda _r: live)
    assert out.content == "LIVE"


async def test_async_replay_tool_miss_strict_raises(tmp_path: Path):
    rec_path = tmp_path / "rec.jsonl"
    rec = RecordingMiddleware(path=rec_path)
    resp = ToolMessage(content="r", tool_call_id="t", name="bash", status="success")
    rec.wrap_tool_call(_tool_request("bash", {"cmd": "id"}), lambda _r: resp)
    _close(rec)
    rep = ReplayMiddleware(path=rec_path, strict=True)

    async def _h(_r):
        return resp

    with pytest.raises(ReplayMismatchError):
        await rep.awrap_tool_call(_tool_request("nmap", {"x": "y"}), _h)


def test_replay_skips_blank_lines(tmp_path: Path):
    path = tmp_path / "in.jsonl"
    path.write_text(
        '{"kind":"model_call","req_hash":"H1","response":{}}\n'
        "\n"
        "   \n"
        '{"kind":"model_call","req_hash":"H2","response":{}}\n',
        encoding="utf-8",
    )
    replay = open_replay(path)
    assert replay.stats["model_calls"] == 2

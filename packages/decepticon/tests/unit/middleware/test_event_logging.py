# -*- coding: utf-8 -*-
"""Tests for decepticon.middleware.event_logging."""

from __future__ import annotations

import asyncio
from pathlib import Path

from langchain_core.messages import ToolMessage

from decepticon.middleware.event_logging import (
    EventLogMiddleware,
    _redact_args,
    _summarize_value,
)
from decepticon.runtime.event_log import EventType, read_events

# ── fakes mirroring the request/handler shapes used by other middleware tests ──


class _Model:
    def __init__(self, name: str) -> None:
        self.name = name


class _Runtime:
    def __init__(self, agent_name: str) -> None:
        self.agent_name = agent_name


class _ModelRequest:
    def __init__(self, workspace: Path, engagement: str, *, messages, model, agent):
        self.state = {"workspace_path": str(workspace), "engagement_name": engagement}
        self.runtime = _Runtime(agent)
        self.messages = messages
        self.model = _Model(model)


class _Tool:
    def __init__(self, name: str) -> None:
        self.name = name


class _ToolRequest:
    def __init__(self, workspace: Path, engagement: str, *, tool, args, agent):
        self.state = {"workspace_path": str(workspace), "engagement_name": engagement}
        self.runtime = _Runtime(agent)
        self.tool = _Tool(tool)
        self.tool_call_args = args


def _events_path(workspace: Path, engagement: str) -> Path:
    return workspace / "events.jsonl"


# ── helpers ────────────────────────────────────────────────────────────────


def test_summarize_value_describes_shape_without_contents():
    assert _summarize_value("hunter2") == "<str:7>"
    assert _summarize_value(b"abcd") == "<bytes:4>"
    assert _summarize_value([1, 2, 3]) == "<list:3>"
    assert _summarize_value((1, 2)) == "<list:2>"
    assert _summarize_value({"a": 1, "b": 2}) == "<dict:2 keys>"
    # Scalars are timeline-useful flags and kept verbatim.
    assert _summarize_value(True) is True
    assert _summarize_value(30) == 30
    assert _summarize_value(None) is None
    assert _summarize_value(object()) == "<object>"


def test_redact_args_never_persists_value_contents():
    command = "sshpass -p hunter2\n"
    out = _redact_args(
        {
            "command": command,
            "is_input": True,
            "timeout": 30,
            "password": "hunter2",
        }
    )
    # B2: a secret carried in a non-secret-named field leaks only its shape.
    assert out["command"] == "<str:%d>" % len(command)
    assert "hunter2" not in out["command"]
    # Scalar flags stay verbatim — useful for the timeline, not a leak risk.
    assert out["is_input"] is True
    assert out["timeout"] == 30
    # Sensitive-named keys are masked outright.
    assert out["password"] == "***REDACTED***"


# ── model round-trip ─────────────────────────────────────────────────────────


def test_model_call_writes_llm_call_then_response_pair(tmp_path: Path):
    mw = EventLogMiddleware()

    class _Resp:
        usage_metadata = {"input_tokens": 5, "output_tokens": 2}
        response_metadata = {"finish_reason": "stop"}

    resp = _Resp()
    req = _ModelRequest(
        tmp_path, "eng-1", messages=["a", "b", "c"], model="claude-opus", agent="recon"
    )

    out = mw.wrap_model_call(req, lambda _r: resp)
    assert out is resp

    events = list(read_events(_events_path(tmp_path, "eng-1")))
    assert [e.type for e in events] == [
        EventType.LLM_CALL.value,
        EventType.LLM_RESPONSE.value,
    ]
    assert events[0].payload == {"messages": 3, "model": "claude-opus"}
    assert events[0].agent == "recon"
    assert events[1].payload["usage"] == {"input_tokens": 5, "output_tokens": 2}
    assert events[1].payload["stop"] == "stop"


# ── tool round-trip ──────────────────────────────────────────────────────────


def test_tool_call_writes_call_then_result_pair(tmp_path: Path):
    mw = EventLogMiddleware()
    req = _ToolRequest(
        tmp_path, "eng-2", tool="bash", args={"command": "id", "token": "s3cr3t"}, agent="recon"
    )
    result = ToolMessage(content="uid=0(root)", tool_call_id="t1", name="bash", status="success")

    out = mw.wrap_tool_call(req, lambda _r: result)
    assert out is result

    events = list(read_events(_events_path(tmp_path, "eng-2")))
    assert [e.type for e in events] == [
        EventType.TOOL_CALL.value,
        EventType.TOOL_RESULT.value,
    ]
    assert events[0].payload["tool"] == "bash"
    assert events[0].payload["args"]["command"] == "<str:2>"
    assert events[0].payload["args"]["token"] == "***REDACTED***"
    assert events[1].payload["status"] == "success"
    assert events[1].payload["output_chars"] == len("uid=0(root)")


def test_finding_tool_writes_finding_after_successful_result(tmp_path: Path):
    mw = EventLogMiddleware()
    req = _ToolRequest(
        tmp_path, "eng-3", tool="validate_finding", args={"vuln_id": "V-1"}, agent="exploit"
    )
    result = ToolMessage(content="{}", tool_call_id="t2", name="validate_finding", status="success")

    mw.wrap_tool_call(req, lambda _r: result)

    events = list(read_events(_events_path(tmp_path, "eng-3")))
    # B3: order is tool.call -> tool.result -> finding.created (finding emitted
    # only after a successful result, never before the tool runs).
    assert [e.type for e in events] == [
        EventType.TOOL_CALL.value,
        EventType.TOOL_RESULT.value,
        EventType.FINDING_CREATED.value,
    ]
    assert events[2].payload == {"tool": "validate_finding"}


def test_failed_finding_tool_does_not_write_finding_created(tmp_path: Path):
    mw = EventLogMiddleware()
    req = _ToolRequest(
        tmp_path, "eng-3b", tool="validate_finding", args={"vuln_id": "V-1"}, agent="exploit"
    )
    # A failed validate_finding returns an error ToolMessage — no phantom finding.
    result = ToolMessage(
        content="invalid", tool_call_id="t2b", name="validate_finding", status="error"
    )

    mw.wrap_tool_call(req, lambda _r: result)

    events = list(read_events(_events_path(tmp_path, "eng-3b")))
    assert [e.type for e in events] == [
        EventType.TOOL_CALL.value,
        EventType.TOOL_RESULT.value,
    ]
    assert EventType.FINDING_CREATED.value not in [e.type for e in events]


def test_finding_tool_command_result_does_not_write_finding_created(tmp_path: Path):
    mw = EventLogMiddleware()
    req = _ToolRequest(
        tmp_path, "eng-3c", tool="validate_finding", args={"vuln_id": "V-1"}, agent="exploit"
    )
    # A Command (graph control-flow) result is not a finding-bearing ToolMessage.
    command_result = object()

    mw.wrap_tool_call(req, lambda _r: command_result)

    types = [e.type for e in read_events(_events_path(tmp_path, "eng-3c"))]
    assert types == [EventType.TOOL_CALL.value, EventType.TOOL_RESULT.value]
    assert EventType.FINDING_CREATED.value not in types


def test_non_finding_tool_does_not_write_finding_created(tmp_path: Path):
    mw = EventLogMiddleware()
    req = _ToolRequest(tmp_path, "eng-4", tool="bash", args={}, agent="recon")
    result = ToolMessage(content="ok", tool_call_id="t3", name="bash", status="success")

    mw.wrap_tool_call(req, lambda _r: result)

    types = [e.type for e in read_events(_events_path(tmp_path, "eng-4"))]
    assert EventType.FINDING_CREATED.value not in types


# ── failure is swallowed ─────────────────────────────────────────────────────


def test_append_failure_is_swallowed(tmp_path: Path):
    # Pre-create events.jsonl as a *directory* so EventLog.append's open()
    # fails. Construction (which only mkdir's the parent) still succeeds.
    bad = _events_path(tmp_path, "eng-5")
    bad.mkdir(parents=True)

    mw = EventLogMiddleware()
    req = _ToolRequest(tmp_path, "eng-5", tool="bash", args={}, agent="recon")
    sentinel = ToolMessage(content="ok", tool_call_id="t4", name="bash", status="success")

    # Must not raise, and must still return the handler's response.
    out = mw.wrap_tool_call(req, lambda _r: sentinel)
    assert out is sentinel


# ── caching + async parity ───────────────────────────────────────────────────


def test_event_log_cached_per_scope(tmp_path: Path):
    mw = EventLogMiddleware()
    req = _ModelRequest(tmp_path, "eng-6", messages=[], model="m", agent="a")
    mw.wrap_model_call(req, lambda _r: type("R", (), {})())
    first = mw._logs[(str(tmp_path), "eng-6")]
    mw.wrap_model_call(req, lambda _r: type("R", (), {})())
    assert mw._logs[(str(tmp_path), "eng-6")] is first
    assert len(mw._logs) == 1


def test_async_hooks_write_events(tmp_path: Path):
    mw = EventLogMiddleware()

    async def _model_handler(_r):
        return type("R", (), {"usage_metadata": {}, "response_metadata": {}})()

    async def _tool_handler(_r):
        return ToolMessage(content="x", tool_call_id="t5", name="bash", status="success")

    async def _drive():
        mreq = _ModelRequest(tmp_path, "eng-7", messages=["m"], model="m", agent="a")
        await mw.awrap_model_call(mreq, _model_handler)
        treq = _ToolRequest(tmp_path, "eng-7", tool="bash", args={}, agent="a")
        await mw.awrap_tool_call(treq, _tool_handler)

    asyncio.run(_drive())

    types = [e.type for e in read_events(_events_path(tmp_path, "eng-7"))]
    assert types == [
        EventType.LLM_CALL.value,
        EventType.LLM_RESPONSE.value,
        EventType.TOOL_CALL.value,
        EventType.TOOL_RESULT.value,
    ]

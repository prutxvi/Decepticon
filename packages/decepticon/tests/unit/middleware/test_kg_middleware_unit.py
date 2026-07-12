# -*- coding: utf-8 -*-
"""Unit tests for :class:`KGMiddleware` — driver-free.

Covers each hook (``before_agent``, ``wrap_model_call``,
``wrap_tool_call``, ``after_model``) and the state-update return shape.
End-to-end agent verification against live Neo4j lives in
``tests/integration/kg/test_kg_middleware_live.py``.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from langchain_core.messages import AIMessage, SystemMessage, ToolMessage

from decepticon.middleware.kg import KG_SYSTEM_PROMPT, KGMiddleware
from decepticon.middleware.kg_internal.state import KGState
from decepticon.middleware.kg_internal.store import KGStore

# ── KGStore mock ────────────────────────────────────────────────────────


def _store_mock(
    *, revision: str = "rev-acme-1", summary_text: str = "## KG STATE (engagement=acme)"
) -> MagicMock:
    store = MagicMock(spec=KGStore, name="KGStore")
    store.revision.return_value = revision
    return store


def _middleware(store: MagicMock | None = None) -> KGMiddleware:
    if store is None:
        store = _store_mock()
    return KGMiddleware(store=store)


def test_state_schema_is_kg_state() -> None:
    assert KGMiddleware.state_schema is KGState


def test_init_builds_two_tools_from_store(monkeypatch: pytest.MonkeyPatch) -> None:
    store = _store_mock()
    mw = KGMiddleware(store=store)
    names = {t.name for t in mw.tools}
    assert names == {"kg_record", "kg_ingest"}


def test_init_default_enabled_filter_can_be_overridden() -> None:
    store = _store_mock()
    mw = KGMiddleware(store=store, enabled_tools={"kg_record"})
    assert [t.name for t in mw.tools] == ["kg_record"]


# ── before_agent ────────────────────────────────────────────────────────


def test_before_agent_returns_none_when_no_engagement() -> None:
    mw = _middleware()
    out = mw.before_agent({}, runtime=None)
    assert out is None


def test_before_agent_hydrates_kg_engagement_from_engagement_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store_mock(revision="rev-acme-7")
    # Patch build_summary to return a known string without touching Neo4j.
    monkeypatch.setattr(
        "decepticon.middleware.kg.build_summary",
        lambda store, *, engagement: f"summary-for-{engagement}",
    )
    mw = KGMiddleware(store=store)
    out = mw.before_agent({"engagement_name": "acme"}, runtime=None)
    assert out is not None
    assert out["kg_engagement"] == "acme"
    assert out["kg_revision"] == "rev-acme-7"
    assert out["kg_summary"] == "summary-for-acme"


def test_before_agent_skips_summary_when_revision_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store_mock(revision="rev-acme-7")
    called: list[str] = []
    monkeypatch.setattr(
        "decepticon.middleware.kg.build_summary",
        lambda store, *, engagement: called.append(engagement) or "won't run",
    )
    mw = KGMiddleware(store=store)
    state = {
        "kg_engagement": "acme",
        "kg_revision": "rev-acme-7",  # matches what store will return
        "kg_summary": "cached",
    }
    out = mw.before_agent(state, runtime=None)
    # Nothing to update — both engagement and revision match.
    assert out is None
    assert called == []


def test_before_agent_rebuilds_summary_after_revision_advance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store_mock(revision="rev-acme-12")
    monkeypatch.setattr(
        "decepticon.middleware.kg.build_summary",
        lambda store, *, engagement: "fresh-summary",
    )
    mw = KGMiddleware(store=store)
    state = {
        "kg_engagement": "acme",
        "kg_revision": "rev-acme-7",  # stale
        "kg_summary": "old",
    }
    out = mw.before_agent(state, runtime=None)
    assert out == {"kg_revision": "rev-acme-12", "kg_summary": "fresh-summary"}


def test_before_agent_swallows_store_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    store = MagicMock(spec=KGStore)
    store.revision.side_effect = RuntimeError("neo4j down")
    mw = KGMiddleware(store=store)
    # Must not raise; agent should keep going without KG context.
    out = mw.before_agent({"engagement_name": "acme"}, runtime=None)
    assert out is None


def test_before_agent_summary_failure_records_empty_string(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = _store_mock(revision="rev-acme-1")
    monkeypatch.setattr(
        "decepticon.middleware.kg.build_summary",
        lambda store, *, engagement: (_ for _ in ()).throw(RuntimeError("query timeout")),
    )
    mw = KGMiddleware(store=store)
    out = mw.before_agent({"engagement_name": "acme"}, runtime=None)
    assert out is not None
    assert out["kg_summary"] == ""
    # The revision still advances so we don't keep retrying the broken
    # summary path on every turn.
    assert out["kg_revision"] == "rev-acme-1"


# ── wrap_model_call / _inject_kg_context ────────────────────────────────


def _fake_request(
    *, state: dict[str, Any], system_message: SystemMessage | None = None
) -> SimpleNamespace:
    """Stand-in for the langchain ModelRequest passed to wrap_model_call."""
    request = SimpleNamespace(state=state, system_message=system_message)

    def override(**kwargs: Any) -> SimpleNamespace:
        new = SimpleNamespace(**vars(request))
        for k, v in kwargs.items():
            setattr(new, k, v)
        return new

    request.override = override  # type: ignore[attr-defined]
    return request


def test_wrap_model_call_skips_when_no_kg_engagement() -> None:
    mw = _middleware()
    request = _fake_request(state={})
    captured: dict[str, Any] = {}

    def handler(req: Any) -> str:
        captured["request"] = req
        return "handler-result"

    out = mw.wrap_model_call(request, handler)
    assert out == "handler-result"
    # Handler must have received the ORIGINAL request — no system mutation.
    assert captured["request"] is request


def test_wrap_model_call_injects_static_and_dynamic_blocks() -> None:
    mw = _middleware()
    sys_msg = SystemMessage(content="base prompt")
    request = _fake_request(
        state={"kg_engagement": "acme", "kg_summary": "## KG STATE (engagement=acme)"},
        system_message=sys_msg,
    )

    def handler(req: Any) -> Any:
        return req

    out = mw.wrap_model_call(request, handler)
    new_sys = out.system_message
    blocks = new_sys.content
    # base prompt + KG_SYSTEM_PROMPT block + dynamic block
    assert len(blocks) >= 3
    static = blocks[-2]
    dynamic = blocks[-1]
    assert KG_SYSTEM_PROMPT in static["text"]
    assert static.get("cache_control") == {"type": "ephemeral"}
    assert "KG STATE (engagement=acme)" in dynamic["text"]


def test_wrap_model_call_omits_dynamic_block_when_summary_empty() -> None:
    mw = _middleware()
    sys_msg = SystemMessage(content="base prompt")
    request = _fake_request(
        state={"kg_engagement": "acme", "kg_summary": ""},
        system_message=sys_msg,
    )
    out = mw.wrap_model_call(request, lambda req: req)
    blocks = out.system_message.content
    static = blocks[-1]
    # Only the static block was appended (no empty dynamic block).
    assert KG_SYSTEM_PROMPT in static["text"]
    # No second block with empty text.
    assert all(b.get("text") for b in blocks if isinstance(b, dict))


# ── wrap_tool_call ──────────────────────────────────────────────────────


def _fake_tool_request(
    *, tool_name: str, state: dict[str, Any], tool_call_id: str = "tc-123"
) -> SimpleNamespace:
    tool = SimpleNamespace(name=tool_name)
    return SimpleNamespace(
        tool=tool,
        state=state,
        tool_call=SimpleNamespace(id=tool_call_id),
    )


def test_wrap_tool_call_passes_through_non_kg_tools() -> None:
    mw = _middleware()
    captured: list[Any] = []
    out = mw.wrap_tool_call(
        _fake_tool_request(tool_name="bash", state={}),
        lambda req: captured.append(req) or "handler-result",
    )
    assert out == "handler-result"
    assert len(captured) == 1


def test_wrap_tool_call_rejects_kg_record_when_engagement_unset() -> None:
    mw = _middleware()
    captured: list[Any] = []
    out = mw.wrap_tool_call(
        _fake_tool_request(tool_name="kg_record", state={}),
        lambda req: captured.append(req) or "handler-result",
    )
    assert isinstance(out, ToolMessage)
    payload = json.loads(out.content)
    assert "error" in payload
    assert "kg_engagement" in payload["error"]
    # Handler must NOT have been called.
    assert captured == []


def test_wrap_tool_call_rejects_kg_ingest_when_engagement_unset() -> None:
    mw = _middleware()
    out = mw.wrap_tool_call(
        _fake_tool_request(tool_name="kg_ingest", state={}),
        lambda req: "handler-result",
    )
    assert isinstance(out, ToolMessage)


def test_wrap_tool_call_allows_kg_tool_when_engagement_present() -> None:
    mw = _middleware()
    captured: list[Any] = []
    out = mw.wrap_tool_call(
        _fake_tool_request(tool_name="kg_record", state={"kg_engagement": "acme"}),
        lambda req: captured.append(req) or "handler-result",
    )
    assert out == "handler-result"
    assert len(captured) == 1


# ── after_model ─────────────────────────────────────────────────────────


def test_after_model_returns_none_when_no_messages() -> None:
    mw = _middleware()
    assert mw.after_model({}, runtime=None) is None
    assert mw.after_model({"messages": []}, runtime=None) is None


def test_after_model_returns_none_when_last_ai_has_no_kg_call() -> None:
    mw = _middleware()
    ai = AIMessage(content="thinking...", tool_calls=[{"name": "bash", "args": {}, "id": "1"}])
    out = mw.after_model({"messages": [ai]}, runtime=None)
    assert out is None


def test_after_model_marks_revision_dirty_when_kg_record_called() -> None:
    mw = _middleware()
    ai = AIMessage(
        content="", tool_calls=[{"name": "kg_record", "args": {"observations": "[]"}, "id": "tc1"}]
    )
    out = mw.after_model({"messages": [ai]}, runtime=None)
    assert out == {"kg_revision": "dirty"}


def test_after_model_marks_revision_dirty_when_kg_ingest_called() -> None:
    mw = _middleware()
    ai = AIMessage(
        content="",
        tool_calls=[
            {"name": "kg_ingest", "args": {"scanner_kind": "nmap_xml", "path": "/x"}, "id": "tc1"}
        ],
    )
    out = mw.after_model({"messages": [ai]}, runtime=None)
    assert out == {"kg_revision": "dirty"}


def test_after_model_skips_non_ai_messages() -> None:
    """The middleware checks the LAST AIMessage, not the last message."""
    mw = _middleware()
    ai = AIMessage(
        content="", tool_calls=[{"name": "kg_record", "args": {"observations": "[]"}, "id": "tc1"}]
    )
    tool_msg = ToolMessage(content="ok", tool_call_id="tc1", name="kg_record")
    out = mw.after_model({"messages": [ai, tool_msg]}, runtime=None)
    # Even though the last message is a ToolMessage, the most-recent
    # AIMessage triggered a KG tool, so the revision is dirty.
    assert out == {"kg_revision": "dirty"}

"""Tests for SkillogyMiddleware (middleware.skillogy)."""

from __future__ import annotations

import asyncio

from decepticon.middleware.skillogy import (
    SkillogyMiddleware,
    _is_enabled,
    maybe_install_skillogy,
)
from decepticon.middleware.skills import SkillsMiddleware
from decepticon.skillogy.proto import (
    SkillEnvelope,
    SkillListResponse,
    SkillMeta,
)


class _FakeSkillsMiddleware(SkillsMiddleware):
    """Test stand-in - SkillsMiddleware requires backend+sources kwargs that
    are heavyweight to construct in unit tests; we only care about its
    presence in the stack so maybe_install_skillogy can detect + swap it."""

    def __init__(self):
        from langchain.agents.middleware import AgentMiddleware

        AgentMiddleware.__init__(self)


class _FakeClient:
    def __init__(self):
        self.list_calls = []
        self.load_calls = []

    async def list_skills(self, **kwargs):
        self.list_calls.append(kwargs)
        return SkillListResponse(
            skills=[SkillMeta(name="t1", path="/skills/t1", subdomain="test")],
            next_page_token="",
            total_count=1,
        )

    async def load_skill(self, path, **kwargs):
        self.load_calls.append({"path": path, **kwargs})
        return SkillEnvelope(
            meta=SkillMeta(name="t1", path=path, subdomain="test"),
            body="# Body of " + path,
        )


def test_middleware_constructs_with_injected_client():
    client = _FakeClient()
    mw = SkillogyMiddleware(client=client)
    assert mw._client is client
    assert len(mw.tools) == 2


def test_middleware_list_skills_tool_returns_json():
    client = _FakeClient()
    mw = SkillogyMiddleware(client=client, append_policy_to_system=False)
    tool = mw.tools[0]
    result = asyncio.run(tool.ainvoke({"subdomain_filter": ["test"]}))
    import json

    payload = json.loads(result)
    assert payload["total_count"] == 1
    assert payload["skills"][0]["name"] == "t1"
    assert client.list_calls[0]["subdomain_filter"] == ["test"]


def test_middleware_load_skill_tool_returns_body():
    client = _FakeClient()
    mw = SkillogyMiddleware(client=client, append_policy_to_system=False)
    tool = mw.tools[1]
    result = asyncio.run(tool.ainvoke({"path": "/skills/ad/k"}))
    import json

    payload = json.loads(result)
    assert "# Body of /skills/ad/k" in payload["body"]
    assert client.load_calls[0]["path"] == "/skills/ad/k"


def test_middleware_load_skill_tool_returns_error_on_exception():
    class _BadClient:
        async def load_skill(self, *args, **kwargs):
            raise RuntimeError("network down")

        async def list_skills(self, **kwargs):
            return SkillListResponse()

    mw = SkillogyMiddleware(client=_BadClient(), append_policy_to_system=False)
    tool = mw.tools[1]
    result = asyncio.run(tool.ainvoke({"path": "/skills/x"}))
    import json

    payload = json.loads(result)
    assert "error" in payload
    assert "network down" in payload["error"]


def test_env_flag_recognizes_truthy_values(monkeypatch):
    for v in ("1", "true", "TRUE", "yes", "on"):
        monkeypatch.setenv("DECEPTICON_USE_SKILLOGY", v)
        assert _is_enabled() is True


def test_env_flag_recognizes_falsy_values(monkeypatch):
    for v in ("0", "false", "", "no", "off"):
        monkeypatch.setenv("DECEPTICON_USE_SKILLOGY", v)
        assert _is_enabled() is False


def test_maybe_install_skillogy_swaps_skills_middleware_when_enabled(monkeypatch):
    monkeypatch.setenv("DECEPTICON_USE_SKILLOGY", "1")
    monkeypatch.setenv("DECEPTICON_SKILLOGY_URL", "http://fake")
    base_stack = [_FakeSkillsMiddleware()]
    out = maybe_install_skillogy(base_stack)
    assert any(isinstance(mw, SkillogyMiddleware) for mw in out)
    assert not any(isinstance(mw, SkillsMiddleware) for mw in out)


def test_maybe_install_skillogy_no_op_when_disabled(monkeypatch):
    monkeypatch.setenv("DECEPTICON_USE_SKILLOGY", "0")
    base_stack = [_FakeSkillsMiddleware()]
    out = maybe_install_skillogy(base_stack)
    assert any(isinstance(mw, SkillsMiddleware) for mw in out)
    assert not any(isinstance(mw, SkillogyMiddleware) for mw in out)


def test_maybe_install_skillogy_appends_when_no_skills_present(monkeypatch):
    monkeypatch.setenv("DECEPTICON_USE_SKILLOGY", "1")
    monkeypatch.setenv("DECEPTICON_SKILLOGY_URL", "http://fake")
    out = maybe_install_skillogy([])
    assert any(isinstance(mw, SkillogyMiddleware) for mw in out)

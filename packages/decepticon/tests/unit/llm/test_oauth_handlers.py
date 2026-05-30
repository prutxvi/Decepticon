"""Unit tests for the LiteLLM custom OAuth handlers under ``config/``.

These modules live in the LiteLLM container's ``/app`` and import ``litellm``
at module level. The dev test env does not install LiteLLM (a runtime container
dep), so a minimal stub is injected before the handlers are loaded. The
handlers also do ``from oauth_token_store import ...`` by bare name, so the
``config/`` directory is placed on ``sys.path``.

Covered fixes:
  * B9  — codex refresh error must not leak raw token fields
  * B10 — copilot streaming must emit tool_calls + preserve finish_reason
  * B11 — grok streaming must emit tool_calls + preserve finish_reason
  * B13 — gemini must map ``finishReason`` instead of hardcoding ``"stop"``
"""

from __future__ import annotations

import importlib
import importlib.util
import sys
import types
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

_CONFIG_DIR = Path(__file__).resolve().parents[5] / "config"


# ── litellm stub ────────────────────────────────────────────────────────


class _StubLLMError(Exception):
    """Mimics litellm's exception API: keyword ``message`` becomes ``str()``."""

    def __init__(self, message: str = "", **kwargs: Any) -> None:
        self.message = message
        self.model = kwargs.get("model")
        self.llm_provider = kwargs.get("llm_provider")
        self.status_code = kwargs.get("status_code")
        super().__init__(message)


def _ensure_litellm_stub() -> Any:
    litellm = sys.modules.get("litellm")
    if litellm is None:
        litellm = types.ModuleType("litellm")
        sys.modules["litellm"] = litellm
    # Always (re)install the attributes the handlers need — a prior test module
    # may have registered a thinner stub.
    litellm.AuthenticationError = _StubLLMError
    litellm.RateLimitError = _StubLLMError
    litellm.APIError = _StubLLMError
    if not hasattr(litellm, "CustomLLM"):
        litellm.CustomLLM = type("CustomLLM", (object,), {})
    if not hasattr(litellm, "ModelResponse"):
        litellm.ModelResponse = type("ModelResponse", (object,), {})
    return litellm


_ensure_litellm_stub()
if str(_CONFIG_DIR) not in sys.path:
    sys.path.insert(0, str(_CONFIG_DIR))


def _ensure_real_oauth_token_store() -> None:
    # The handlers do ``from oauth_token_store import ...`` by bare name. Another
    # test module (test_claude_code_handler_cache_dedup) registers a *partial*
    # stub under that same bare name via ``sys.modules.setdefault``; under
    # ``pytest -n auto`` that stub can land in this worker first and shadow the
    # real module, so symbols like ``DEFAULT_JWT_SKEW_SECONDS`` go missing. Load
    # the real config module from file (it only needs the litellm stub above and
    # the installed httpx) so the handlers resolve against the complete module
    # regardless of collection order.
    existing = sys.modules.get("oauth_token_store")
    if existing is not None and getattr(existing, "__file__", None):
        return
    fake_httpx = sys.modules.get("httpx")
    if fake_httpx is not None and not getattr(fake_httpx, "__file__", None):
        del sys.modules["httpx"]
    spec = importlib.util.spec_from_file_location(
        "oauth_token_store", _CONFIG_DIR / "oauth_token_store.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["oauth_token_store"] = module
    spec.loader.exec_module(module)


_ensure_real_oauth_token_store()


def _load(name: str) -> Any:
    _ensure_litellm_stub()
    _ensure_real_oauth_token_store()
    return importlib.import_module(name)


codex = _load("codex_chatgpt_handler")
copilot = _load("copilot_handler")
grok = _load("grok_handler")
gemini = _load("gemini_handler")


def _response(message: dict[str, Any], finish_reason: str = "stop") -> Any:
    """Build a minimal ModelResponse-like object for ``_response_to_chunks``."""
    usage = SimpleNamespace(prompt_tokens=3, completion_tokens=5, total_tokens=8)
    choice = {"index": 0, "message": message, "finish_reason": finish_reason}
    return SimpleNamespace(choices=[choice], usage=usage)


_TOOL_CALL = {
    "id": "call_1",
    "type": "function",
    "function": {"name": "run_shell", "arguments": '{"cmd": "ls"}'},
}


# ── B9: codex refresh must not leak raw token data ──────────────────────


class TestCodexRefreshNoSecretLeak:
    def test_missing_fields_message_lists_names_not_values(self, monkeypatch) -> None:
        # Response is missing access_token / id_token but carries a secret
        # refresh_token. The error must name the missing fields only.
        secret = "SECRET-REFRESH-VALUE-do-not-leak"
        monkeypatch.setattr(
            codex,
            "oauth_refresh_request",
            lambda *a, **k: {"refresh_token": secret, "scope": "openid"},
        )
        with pytest.raises(codex.litellm.AuthenticationError) as exc:
            codex._refresh_tokens({"tokens": {"refresh_token": "old-refresh"}})
        message = exc.value.message
        assert "access_token" in message
        assert "id_token" in message
        assert secret not in message
        assert "refresh_token" not in message

    def test_partial_response_names_only_the_absent_field(self, monkeypatch) -> None:
        # access_token present, id_token missing → only id_token reported.
        monkeypatch.setattr(
            codex,
            "oauth_refresh_request",
            lambda *a, **k: {"access_token": "AT", "refresh_token": "SECRET"},
        )
        with pytest.raises(codex.litellm.AuthenticationError) as exc:
            codex._refresh_tokens({"tokens": {"refresh_token": "old"}})
        message = exc.value.message
        assert "id_token" in message
        assert "access_token" not in message
        assert "SECRET" not in message


# ── B10 / B11: streaming must preserve tool calls + finish_reason ───────


@pytest.mark.parametrize(
    "handler", [copilot.copilot_handler_instance, grok.grok_sub_handler_instance]
)
class TestStreamingToolCalls:
    def test_tool_calls_are_emitted_not_dropped(self, handler) -> None:
        resp = _response(
            {"role": "assistant", "content": "", "tool_calls": [_TOOL_CALL]},
            finish_reason="tool_calls",
        )
        chunks = handler._response_to_chunks(resp)
        tool_chunks = [c for c in chunks if c["tool_use"] is not None]
        assert len(tool_chunks) == 1
        assert tool_chunks[0]["tool_use"]["function"]["name"] == "run_shell"
        assert tool_chunks[0]["finish_reason"] == "tool_calls"
        assert tool_chunks[0]["is_finished"] is True

    def test_text_then_tool_call_ordering(self, handler) -> None:
        resp = _response(
            {"role": "assistant", "content": "thinking", "tool_calls": [_TOOL_CALL]},
            finish_reason="tool_calls",
        )
        chunks = handler._response_to_chunks(resp)
        assert chunks[0]["text"] == "thinking"
        assert chunks[0]["tool_use"] is None
        assert chunks[0]["is_finished"] is False
        assert chunks[-1]["tool_use"] is not None

    def test_finish_reason_is_preserved_for_plain_text(self, handler) -> None:
        # A truncated completion must not be reported as a clean "stop".
        resp = _response({"role": "assistant", "content": "partial"}, finish_reason="length")
        chunks = handler._response_to_chunks(resp)
        assert len(chunks) == 1
        assert chunks[0]["finish_reason"] == "length"
        assert chunks[0]["text"] == "partial"
        assert chunks[0]["tool_use"] is None


# ── B13: gemini finishReason mapping ────────────────────────────────────


class TestGeminiFinishReason:
    @pytest.mark.parametrize(
        ("reason", "expected"),
        [
            ("STOP", "stop"),
            ("MAX_TOKENS", "length"),
            ("SAFETY", "content_filter"),
            ("RECITATION", "content_filter"),
            ("OTHER", "stop"),
            (None, "stop"),
            ("", "stop"),
        ],
    )
    def test_map_finish_reason(self, reason, expected) -> None:
        assert gemini._map_finish_reason(reason) == expected

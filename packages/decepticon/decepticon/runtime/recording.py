"""Record / replay layer for deterministic engagement re-execution.

Why this exists
---------------
Decepticon's benchmark numbers (XBOW 98.08%) are not currently reproducible
on demand. A run that hit 102/104 today may hit 99/104 tomorrow because the
underlying LLM is non-deterministic and tool outputs against live targets
drift. Without a record/replay layer you cannot:

- Bisect a regression (was it the prompt change or the model change?).
- Certify a release against a fixed transcript.
- Test middleware modifications without paying the LLM cost for every run.
- Reproduce a flaky benchmark failure long enough to debug it.

Design
------
**Recording mode** wraps both ``wrap_model_call`` and ``wrap_tool_call`` to
capture (request_hash, response) pairs into a single append-only JSONL file:

  - ``model_call`` entries carry: prompt-hash, model id, response content,
    tool calls emitted, token usage.
  - ``tool_call`` entries carry: tool name, args-hash, ToolMessage content.

Hashing is over a *canonical* serialization of the request (sorted keys,
no timestamps, no run IDs) so the same prompt at different wall-clock
times hashes identically.

**Replay mode** consumes that JSONL, hashes the incoming request the same
way, and serves the recorded response without invoking the LLM or running
the tool. If a request is encountered whose hash isn't in the record, the
mode raises ``ReplayMismatchError`` — the caller decides whether to fall
through to a real LLM call (``strict=False``) or fail loudly (``strict=True``).

File format
-----------
JSONL, one event per line::

    {"kind":"model_call","seq":42,"req_hash":"sha256:...","model":"claude-opus-4-7",
     "request":{...canonical...},"response":{...content...},"usage":{...}}
    {"kind":"tool_call","seq":43,"req_hash":"sha256:...","tool":"bash",
     "request":{...},"response":{...ToolMessage...}}

The ``seq`` field is the global execution order — useful for diffing two
runs that diverged mid-execution.

What is NOT recorded
--------------------
- Real wall-clock timestamps (replay would be misleading).
- Random.* seeds — agents should not consume randomness; if they do that's
  a separate bug to fix.
- Sandbox internal state (jobs registry, tmux session IDs) — these are
  re-derived deterministically from the recorded tool messages.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, ClassVar

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import AIMessage, ToolMessage
from typing_extensions import override

log = logging.getLogger(__name__)


class ReplayMismatchError(RuntimeError):
    """Raised when replay encounters a request not present in the record."""

    def __init__(self, kind: str, req_hash: str, *, available_hashes: int) -> None:
        self.kind = kind
        self.req_hash = req_hash
        self.available_hashes = available_hashes
        super().__init__(
            f"replay miss: kind={kind} req_hash={req_hash[:16]}… "
            f"({available_hashes} hashes recorded)"
        )


def _canonicalize(obj: Any) -> Any:
    """Drop fields that vary across otherwise-identical runs (timestamps, run IDs)."""
    if isinstance(obj, dict):
        out = {}
        for k, v in sorted(obj.items()):
            if k in {"id", "run_id", "thread_id", "timestamp", "created_at"}:
                continue
            out[k] = _canonicalize(v)
        return out
    if isinstance(obj, list):
        return [_canonicalize(v) for v in obj]
    return obj


def _hash_request(payload: Any) -> str:
    canonical = _canonicalize(payload)
    encoded = json.dumps(canonical, sort_keys=True, default=str).encode("utf-8")
    return "sha256:" + hashlib.sha256(encoded).hexdigest()


def _serialize_messages(messages: list[Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for msg in messages or []:
        entry: dict[str, Any] = {
            "type": getattr(msg, "type", msg.__class__.__name__),
            "content": getattr(msg, "content", ""),
        }
        for attr in ("name", "tool_call_id", "tool_calls", "additional_kwargs"):
            if hasattr(msg, attr):
                value = getattr(msg, attr)
                if value:
                    entry[attr] = value
        out.append(entry)
    return out


def _serialize_model_request(request: Any) -> dict[str, Any]:
    system = request.system_message
    model = getattr(request, "model", None)
    return {
        "model": getattr(model, "model_name", None) or getattr(model, "name", "") or "",
        "system": getattr(system, "content", "") if system is not None else "",
        "messages": _serialize_messages(getattr(request, "messages", []) or []),
        "tools": [getattr(t, "name", "") for t in (getattr(request, "tools", []) or [])],
    }


def _serialize_tool_request(request: Any) -> dict[str, Any]:
    tool = getattr(request, "tool", None)
    tc = getattr(request, "tool_call", None) or {}
    args = tc.get("args", {}) if isinstance(tc, dict) else {}
    return {
        "tool": getattr(tool, "name", "") if tool else "",
        "args": args or {},
    }


def _serialize_ai_response(message: Any) -> dict[str, Any]:
    return {
        "type": getattr(message, "type", "ai"),
        "content": getattr(message, "content", ""),
        "tool_calls": getattr(message, "tool_calls", []) or [],
        "usage_metadata": getattr(message, "usage_metadata", {}) or {},
        "additional_kwargs": getattr(message, "additional_kwargs", {}) or {},
    }


def _serialize_tool_response(message: Any) -> dict[str, Any]:
    return {
        "type": "tool",
        "content": getattr(message, "content", ""),
        "tool_call_id": getattr(message, "tool_call_id", ""),
        "name": getattr(message, "name", ""),
        "status": getattr(message, "status", ""),
        "artifact": getattr(message, "artifact", None),
    }


class _Sink:
    """Append-only JSONL writer with monotonic seq counter and file rotation hint."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._seq = 0
        self._fh = path.open("a", encoding="utf-8")

    def write(self, entry: dict[str, Any]) -> None:
        entry["seq"] = self._seq
        self._seq += 1
        self._fh.write(json.dumps(entry, default=str) + "\n")
        self._fh.flush()

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:  # noqa: BLE001
            log.warning("failed to close record sink at %s", self._path, exc_info=True)


def open_record(path: str | Path) -> _Sink:
    """Open ``path`` for appending recording events."""
    return _Sink(Path(path))


class _Replay:
    """Read-only JSONL replayer indexed by req_hash."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._model: dict[str, dict[str, Any]] = {}
        self._tools: dict[str, dict[str, Any]] = {}
        if not path.exists():
            raise FileNotFoundError(f"replay file not found: {path}")
        with path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    log.warning("malformed replay line skipped in %s", path)
                    continue
                kind = entry.get("kind")
                req_hash = entry.get("req_hash")
                if not kind or not req_hash:
                    continue
                if kind == "model_call":
                    self._model[req_hash] = entry
                elif kind == "tool_call":
                    self._tools[req_hash] = entry

    def lookup_model(self, req_hash: str) -> dict[str, Any] | None:
        return self._model.get(req_hash)

    def lookup_tool(self, req_hash: str) -> dict[str, Any] | None:
        return self._tools.get(req_hash)

    @property
    def stats(self) -> dict[str, int]:
        return {"model_calls": len(self._model), "tool_calls": len(self._tools)}


def open_replay(path: str | Path) -> _Replay:
    """Open ``path`` for replay lookups."""
    return _Replay(Path(path))


class RecordingMiddleware(AgentMiddleware):
    """Capture every model + tool round-trip to a JSONL record file.

    Construct once per engagement with the desired output path. The sink
    is opened in append mode so re-runs onto the same file accumulate
    events (with monotonically-increasing seq numbers).

    Place this middleware *closest to the inner runtime* (last in the stack)
    so it observes the request/response shapes that actually hit the LLM
    after all other middleware has had its chance to mutate them.
    """

    def __init__(self, *, path: str | Path | None = None) -> None:
        super().__init__()
        record_path = path or os.environ.get("DECEPTICON_RUNTIME__RECORD_PATH", "")
        if not record_path:
            self._sink: _Sink | None = None
        else:
            self._sink = open_record(Path(record_path))

    @override
    def wrap_model_call(self, request, handler):
        if self._sink is None:
            return handler(request)
        req_dict = _serialize_model_request(request)
        req_hash = _hash_request(req_dict)
        response = handler(request)
        self._sink.write(
            {
                "kind": "model_call",
                "req_hash": req_hash,
                "request": req_dict,
                "response": _serialize_ai_response(response),
            }
        )
        return response

    @override
    async def awrap_model_call(self, request, handler):
        if self._sink is None:
            return await handler(request)
        req_dict = _serialize_model_request(request)
        req_hash = _hash_request(req_dict)
        response = await handler(request)
        self._sink.write(
            {
                "kind": "model_call",
                "req_hash": req_hash,
                "request": req_dict,
                "response": _serialize_ai_response(response),
            }
        )
        return response

    @override
    def wrap_tool_call(self, request, handler):
        if self._sink is None:
            return handler(request)
        req_dict = _serialize_tool_request(request)
        req_hash = _hash_request(req_dict)
        response = handler(request)
        self._sink.write(
            {
                "kind": "tool_call",
                "req_hash": req_hash,
                "request": req_dict,
                "response": _serialize_tool_response(response)
                if isinstance(response, ToolMessage)
                else {"type": "command"},
            }
        )
        return response

    @override
    async def awrap_tool_call(self, request, handler):
        if self._sink is None:
            return await handler(request)
        req_dict = _serialize_tool_request(request)
        req_hash = _hash_request(req_dict)
        response = await handler(request)
        self._sink.write(
            {
                "kind": "tool_call",
                "req_hash": req_hash,
                "request": req_dict,
                "response": _serialize_tool_response(response)
                if isinstance(response, ToolMessage)
                else {"type": "command"},
            }
        )
        return response


class ReplayMiddleware(AgentMiddleware):
    """Serve recorded responses for matching model/tool requests; bypass the runtime.

    Construct with the path to a JSONL produced by :class:`RecordingMiddleware`
    and a strictness flag:

    - ``strict=True`` (default): a request whose hash is not in the record
      raises :class:`ReplayMismatchError`. Use for CI / certification runs.
    - ``strict=False``: misses fall through to the real handler. Use for
      "partial replay" — re-run with deltas; freshly-needed answers hit
      the live LLM and the replay stays current for the rest.
    """

    _ATTR_RESPONSE: ClassVar[str] = "response"

    def __init__(self, *, path: str | Path | None = None, strict: bool = True) -> None:
        super().__init__()
        replay_path = path or os.environ.get("DECEPTICON_RUNTIME__REPLAY_PATH", "")
        if not replay_path:
            self._replay: _Replay | None = None
        else:
            self._replay = open_replay(Path(replay_path))
        self._strict = strict

    def _model_response(self, entry: dict[str, Any]) -> Any:
        payload = entry.get(self._ATTR_RESPONSE) or {}
        return AIMessage(
            content=payload.get("content", ""),
            tool_calls=payload.get("tool_calls", []) or [],
            additional_kwargs=payload.get("additional_kwargs") or {},
            usage_metadata=payload.get("usage_metadata") or None,
        )

    def _tool_response(self, entry: dict[str, Any]) -> Any:
        payload = entry.get(self._ATTR_RESPONSE) or {}
        return ToolMessage(
            content=payload.get("content", ""),
            tool_call_id=payload.get("tool_call_id", "") or "",
            name=payload.get("name", "") or "",
            status=payload.get("status", "success") or "success",
            artifact=payload.get("artifact"),
        )

    @override
    def wrap_model_call(self, request, handler):
        if self._replay is None:
            return handler(request)
        req_dict = _serialize_model_request(request)
        req_hash = _hash_request(req_dict)
        entry = self._replay.lookup_model(req_hash)
        if entry is None:
            if self._strict:
                raise ReplayMismatchError(
                    "model_call",
                    req_hash,
                    available_hashes=self._replay.stats["model_calls"],
                )
            return handler(request)
        return self._model_response(entry)

    @override
    async def awrap_model_call(self, request, handler):
        if self._replay is None:
            return await handler(request)
        req_dict = _serialize_model_request(request)
        req_hash = _hash_request(req_dict)
        entry = self._replay.lookup_model(req_hash)
        if entry is None:
            if self._strict:
                raise ReplayMismatchError(
                    "model_call",
                    req_hash,
                    available_hashes=self._replay.stats["model_calls"],
                )
            return await handler(request)
        return self._model_response(entry)

    @override
    def wrap_tool_call(self, request, handler):
        if self._replay is None:
            return handler(request)
        req_dict = _serialize_tool_request(request)
        req_hash = _hash_request(req_dict)
        entry = self._replay.lookup_tool(req_hash)
        if entry is None:
            if self._strict:
                raise ReplayMismatchError(
                    "tool_call",
                    req_hash,
                    available_hashes=self._replay.stats["tool_calls"],
                )
            return handler(request)
        return self._tool_response(entry)

    @override
    async def awrap_tool_call(self, request, handler):
        if self._replay is None:
            return await handler(request)
        req_dict = _serialize_tool_request(request)
        req_hash = _hash_request(req_dict)
        entry = self._replay.lookup_tool(req_hash)
        if entry is None:
            if self._strict:
                raise ReplayMismatchError(
                    "tool_call",
                    req_hash,
                    available_hashes=self._replay.stats["tool_calls"],
                )
            return await handler(request)
        return self._tool_response(entry)

# -*- coding: utf-8 -*-
"""KGMiddleware — owner of the Neo4j-backed attack graph for an agent run.

Mirrors :class:`OPPLANMiddleware` (decepticon/middleware/opplan.py): state
schema + tools-on-init + lifecycle hooks. Once attached to an agent via
``langchain.agents.create_agent(... middleware=[KGMiddleware(), ...])``
the agent gains the ``kg_record`` and ``kg_ingest`` tools and sees a
current graph summary in every system prompt.

Hooks:

  * ``before_agent``    — hydrate ``kg_engagement`` from upstream state,
                          fetch the current revision from the store,
                          rebuild the summary block when the revision
                          advances or this is the first turn.
  * ``wrap_model_call`` — inject the cached summary block into the
                          system message as a cache-friendly two-block
                          insertion (static prompt-cache breakpoint +
                          dynamic stats).
  * ``wrap_tool_call``  — defense-in-depth refusal of ``kg_record`` /
                          ``kg_ingest`` when ``kg_engagement`` is unset.
                          The tools themselves enforce the same rule;
                          this layer fires earlier and surfaces the
                          error before the adapter even runs.
  * ``after_model``     — when a KG write tool ran in the last AI step,
                          mark ``kg_revision`` dirty so the next
                          ``before_agent`` re-fetches it and rebuilds
                          the summary.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from typing import Any, cast

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import AIMessage, SystemMessage, ToolMessage
from typing_extensions import override

from decepticon.middleware.kg_internal.state import KGState
from decepticon.middleware.kg_internal.store import KGStore
from decepticon.middleware.kg_internal.summary import build_summary
from decepticon.middleware.kg_internal.tools import build_kg_tools

log = logging.getLogger(__name__)


# System prompt content the middleware injects with prompt-cache marker.
# Kept short — the dynamic summary block (see :mod:`kg_internal.summary`)
# is what changes each turn; this block tells the LLM what the surface
# is and is cache-eligible.
KG_SYSTEM_PROMPT = (
    "## Knowledge graph (KGMiddleware-owned)\n"
    "You have access to a persistent attack graph for this engagement.\n"
    "Write observations with `kg_record(observations)` — pass a JSON list\n"
    "of node + edge dicts; the middleware injects provenance.\n"
    "Bulk-ingest scanner outputs with `kg_ingest(scanner_kind, path)`.\n"
    "Do not pass `engagement`, `firstseen`, `lastupdated`, `created_by`,\n"
    "or `source_episode_id` in props — they are reserved for the\n"
    "middleware to set.\n"
    "Current graph state appears below; lean on it for next-move\n"
    "decisions. Use `grep findings/` or `bash('cypher-shell ...')` for\n"
    "ad-hoc deep dives instead of read tools — the graph state below\n"
    "covers the common cases."
)


# Marker the middleware writes into ``kg_revision`` when a write tool
# ran. Forces the next ``before_agent`` to re-fetch the real revision
# and rebuild the summary. Any non-empty string different from the
# real ``rev-<engagement>-<update_tag>`` works; ``dirty`` is the
# convention.
_REVISION_DIRTY_MARKER = "dirty"


class KGMiddleware(AgentMiddleware):
    """Attach the KG to an agent.

    Parameters
    ----------
    store
        ``KGStore`` instance to bind tools and summary queries to. When
        ``None``, constructs one via ``KGStore.from_env()`` so unit /
        integration tests can inject a test store while production
        works out-of-the-box.
    enabled_tools
        Override the tool surface. Defaults to ``{"kg_record",
        "kg_ingest"}`` (see ``DEFAULT_KG_TOOLS`` in
        ``kg_internal.tools``).
    """

    state_schema = KGState

    def __init__(
        self,
        *,
        store: KGStore | None = None,
        enabled_tools: Iterable[str] | None = None,
    ) -> None:
        super().__init__()
        self._store = store if store is not None else KGStore.from_env()
        self.tools = build_kg_tools(self._store, enabled=enabled_tools)
        self._kg_tool_names = {getattr(t, "name", "") for t in self.tools}

    @property
    def store(self) -> KGStore:
        """The store this middleware was built against."""
        return self._store

    # ── before_agent ──────────────────────────────────────────────────

    @override
    def before_agent(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        return self._hydrate_kg_state(state)

    @override
    async def abefore_agent(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        return self._hydrate_kg_state(state)

    def _hydrate_kg_state(self, state: Any) -> dict[str, Any] | None:
        """Set ``kg_engagement`` / ``kg_revision`` / ``kg_summary`` from store."""
        get = state.get if hasattr(state, "get") else (lambda _k, _d=None: None)
        engagement = str(get("kg_engagement") or get("engagement_name") or "").strip()
        if not engagement:
            return None

        try:
            revision = self._store.revision(engagement=engagement)
        except Exception as exc:
            log.warning("KGMiddleware revision fetch failed (engagement=%s): %s", engagement, exc)
            return None

        updates: dict[str, Any] = {}
        if get("kg_engagement") != engagement:
            updates["kg_engagement"] = engagement

        prior_revision = get("kg_revision")
        if revision != prior_revision:
            updates["kg_revision"] = revision
            try:
                updates["kg_summary"] = build_summary(self._store, engagement=engagement)
            except Exception as exc:
                log.warning("KGMiddleware summary build failed: %s", exc)
                updates["kg_summary"] = ""
        return updates or None

    # ── wrap_model_call ───────────────────────────────────────────────

    @override
    def wrap_model_call(self, request: Any, handler: Any) -> Any:
        return handler(self._inject_kg_context(request))

    @override
    async def awrap_model_call(self, request: Any, handler: Any) -> Any:
        return await handler(self._inject_kg_context(request))

    def _inject_kg_context(self, request: Any) -> Any:
        """Append the KG static prompt + dynamic summary to the system
        message. Two content blocks so the Anthropic prompt cache can
        re-use the static prefix across turns (same pattern as
        ``OPPLANMiddleware._inject_opplan_context`` at
        ``middleware/opplan.py:350``)."""
        state = request.state or {}
        get = state.get if hasattr(state, "get") else (lambda _k, _d=None: None)
        summary = str(get("kg_summary") or "")

        # No engagement / no summary yet — pass the request through.
        if not get("kg_engagement"):
            return request

        static_block: dict[str, Any] = {
            "type": "text",
            "text": "\n\n" + KG_SYSTEM_PROMPT,
            "cache_control": {"type": "ephemeral"},
        }
        injected_blocks: list[dict[str, Any]] = [static_block]
        if summary:
            injected_blocks.append({"type": "text", "text": "\n\n" + summary})

        if request.system_message is not None:
            new_content = [
                *request.system_message.content_blocks,
                *injected_blocks,
            ]
        else:
            new_content = injected_blocks

        new_system = SystemMessage(content=cast("list[str | dict[str, str]]", new_content))
        return request.override(system_message=new_system)

    # ── wrap_tool_call ────────────────────────────────────────────────

    @override
    def wrap_tool_call(self, request: Any, handler: Any) -> Any:
        rejection = self._maybe_reject_unscoped(request)
        if rejection is not None:
            return rejection
        return handler(request)

    @override
    async def awrap_tool_call(self, request: Any, handler: Any) -> Any:
        rejection = self._maybe_reject_unscoped(request)
        if rejection is not None:
            return rejection
        return await handler(request)

    def _maybe_reject_unscoped(self, request: Any) -> ToolMessage | None:
        """Return a ``ToolMessage`` rejection when a KG tool is invoked
        without an engagement on state. Otherwise return ``None`` so the
        wrap proceeds to the handler."""
        tool = getattr(request, "tool", None)
        if tool is None or getattr(tool, "name", "") not in self._kg_tool_names:
            return None
        state = getattr(request, "state", None) or {}
        get = state.get if hasattr(state, "get") else (lambda _k, _d=None: None)
        if get("kg_engagement"):
            return None
        tool_call = getattr(request, "tool_call", None)
        tool_call_id = (
            getattr(tool_call, "id", None)
            if tool_call is not None
            else (
                request.tool_call.get("id")
                if isinstance(getattr(request, "tool_call", None), dict)
                else None
            )
        ) or "kg-middleware-rejection"
        return ToolMessage(
            content=json.dumps(
                {
                    "error": (
                        "kg_engagement not on state — KGMiddleware refused the call. "
                        "Hydrate engagement_name via EngagementContextMiddleware first."
                    )
                }
            ),
            tool_call_id=tool_call_id,
            name=getattr(tool, "name", "kg_tool"),
        )

    # ── after_model ───────────────────────────────────────────────────

    @override
    def after_model(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        return self._maybe_invalidate_revision(state)

    @override
    async def aafter_model(self, state: Any, runtime: Any) -> dict[str, Any] | None:
        return self._maybe_invalidate_revision(state)

    def _maybe_invalidate_revision(self, state: Any) -> dict[str, Any] | None:
        """When the most recent AI message issued a kg_record / kg_ingest
        call, mark ``kg_revision`` dirty so the next ``before_agent``
        rebuilds the summary."""
        messages = state.get("messages") if hasattr(state, "get") else None
        if not messages:
            return None
        last_ai = next((m for m in reversed(messages) if isinstance(m, AIMessage)), None)
        if last_ai is None:
            return None
        tool_calls = getattr(last_ai, "tool_calls", None) or []
        kg_write_invoked = False
        for tc in tool_calls:
            if isinstance(tc, dict):
                name = tc.get("name")
            else:
                name = getattr(tc, "name", None)
            if name in self._kg_tool_names:
                kg_write_invoked = True
                break
        if not kg_write_invoked:
            return None
        return {"kg_revision": _REVISION_DIRTY_MARKER}


__all__ = ["KGMiddleware", "KG_SYSTEM_PROMPT"]

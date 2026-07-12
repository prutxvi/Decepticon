# -*- coding: utf-8 -*-
"""SubagentTranscriptState — durable sub-agent transcript channel.

Sub-agent activity (start / message / tool_call / tool_result / end) is
emitted live by :class:`decepticon.core.subagent_streaming.StreamingRunnable`
as transient LangGraph custom events. Those events are great for an attached
SSE client, but they are lost the instant the client disconnects: a reconnect
or a poll of a *completed* run sees none of the sub-agent detail, because
nothing about it was ever written to the checkpoint.

This schema adds one accumulating channel, ``subagent_transcripts``, to the
orchestrator graph's THREAD state. ``StreamingRunnable`` appends a copy of
every event it streams into the sub-agent's returned state dict; deepagents'
``task``/``atask`` tool forwards that key to the parent graph (it is not in
``_EXCLUDED_STATE_KEYS``), and this channel's reducer merges it into the
checkpoint. The result is durable, client-independent observability: the full
transcript is returned by ``client.threads.getState`` in every scenario —
live, after reconnect, and after the run completes.

The schema EXTENDS ``AgentState`` — the same base that
``deepagents.middleware.subagents.SubAgentMiddleware`` inherits for its
``state_schema`` (it does not override the ``AgentMiddleware`` default, which
is ``AgentState``). Extending (rather than replacing) keeps deepagents' own
channels (``messages``, ``jump_to``, ``structured_response``) intact when this
schema is registered on the orchestrator at ``create_agent`` compile time.

This is a generic OSS observability channel: each entry is an opaque event
dict and the schema carries no SaaS-specific types.
"""

from __future__ import annotations

from typing import Annotated, NotRequired

from langchain.agents import AgentState

from decepticon.middleware.state_reducers import reduce_concat_transcript


class SubagentTranscriptState(AgentState):
    """State extension carrying the durable sub-agent transcript channel.

    The single ``NotRequired`` field keeps the schema non-invasive: an agent
    built without this slot retains its original state surface.

    The channel carries :func:`reduce_concat_transcript` because the
    orchestrator may dispatch several ``task()`` calls in one superstep
    (parallel fan-out). Each sub-agent branch returns its own slice of the
    transcript, so concurrent writes must accumulate rather than collide —
    without an accumulating reducer LangGraph trips
    ``INVALID_CONCURRENT_GRAPH_UPDATE`` (and last-write-wins would silently
    drop a branch's events). Append-only and idempotent on ``None``.
    """

    subagent_transcripts: NotRequired[
        Annotated[
            list,
            (
                "Durable, append-only log of sub-agent events "
                "(subagent_start / subagent_message / subagent_tool_call / "
                "subagent_tool_result / subagent_end). Each entry is an opaque "
                "event dict byte-identical to the streamed custom event, so a "
                "reconnecting or post-completion client reconstructs the same "
                "view the live SSE stream produced."
            ),
            reduce_concat_transcript,
        ]
    ]

# -*- coding: utf-8 -*-
"""Tests for ``decepticon.runtime.event_log`` — append-only engagement log."""

from __future__ import annotations

import concurrent.futures
import json
import time
from pathlib import Path

from decepticon.runtime.event_log import (
    EngagementEvent,
    EventLog,
    EventType,
    read_events,
)


def test_append_writes_one_jsonl_line_per_event(tmp_path: Path) -> None:
    log = EventLog(workspace_root=tmp_path, engagement_id="eng-1")
    log.append(EventType.ENGAGEMENT_START, {"name": "demo"})
    log.append(EventType.AGENT_TURN, {"turn": 1}, agent="decepticon")
    log.append(EventType.ENGAGEMENT_END, {})

    lines = log.path.read_text(encoding="utf-8").splitlines()
    assert len(lines) == 3
    parsed = [json.loads(ln) for ln in lines]
    assert parsed[0]["type"] == "engagement.start"
    assert parsed[1]["type"] == "agent.turn"
    assert parsed[1]["agent"] == "decepticon"
    assert parsed[2]["type"] == "engagement.end"


def test_read_returns_events_in_order(tmp_path: Path) -> None:
    log = EventLog(workspace_root=tmp_path, engagement_id="eng-2")
    log.append(EventType.ENGAGEMENT_START, {"i": 0})
    log.append(EventType.TOOL_CALL, {"i": 1}, agent="recon")
    log.append(EventType.TOOL_RESULT, {"i": 2}, agent="recon")
    log.append(EventType.ENGAGEMENT_END, {"i": 3})

    events = list(log.read())
    assert [e.payload["i"] for e in events] == [0, 1, 2, 3]
    assert events[1].agent == "recon"
    assert events[2].type == "tool.result"


def test_append_returns_rendered_event(tmp_path: Path) -> None:
    log = EventLog(workspace_root=tmp_path, engagement_id="eng-3")
    before = time.time()
    event = log.append(EventType.FINDING_CREATED, {"id": "FIND-001"}, agent="exploit")
    after = time.time()
    assert event.type == "finding.created"
    assert event.agent == "exploit"
    assert event.payload == {"id": "FIND-001"}
    assert before <= event.ts <= after


def test_event_type_accepts_str(tmp_path: Path) -> None:
    log = EventLog(workspace_root=tmp_path, engagement_id="eng-4")
    log.append("custom.event", {"x": 1})
    events = list(log.read())
    assert events[0].type == "custom.event"


def test_read_events_skips_malformed_lines(tmp_path: Path) -> None:
    path = tmp_path / "events.jsonl"
    path.write_text(
        '{"ts": 1.0, "type": "agent.turn", "payload": {}}\n'
        "not valid json\n"
        '{"ts": 2.0, "type": "tool.call", "payload": {"a": 1}}\n'
        "\n"
        '{"ts": 3.0, "type": "finding.created", "payload": {"id": "FIND-001"}}\n',
        encoding="utf-8",
    )
    events = list(read_events(path))
    assert len(events) == 3
    assert [e.type for e in events] == ["agent.turn", "tool.call", "finding.created"]


def test_read_events_handles_missing_file(tmp_path: Path) -> None:
    assert list(read_events(tmp_path / "nope.jsonl")) == []


def test_engagement_event_from_json_line_round_trips(tmp_path: Path) -> None:
    event = EngagementEvent(ts=1.5, type="agent.turn", agent="decepticon", payload={"k": "v"})
    line = event.to_json_line()
    parsed = EngagementEvent.from_json_line(line)
    assert parsed is not None
    assert parsed.ts == 1.5
    assert parsed.type == "agent.turn"
    assert parsed.agent == "decepticon"
    assert parsed.payload == {"k": "v"}


def test_engagement_event_from_invalid_json_returns_none() -> None:
    assert EngagementEvent.from_json_line("not json") is None
    assert EngagementEvent.from_json_line("") is None
    assert EngagementEvent.from_json_line("   ") is None
    assert EngagementEvent.from_json_line("123") is None


def test_path_lives_under_engagement_id(tmp_path: Path) -> None:
    log = EventLog(workspace_root=tmp_path, engagement_id="eng-A")
    expected = tmp_path / "engagements" / "eng-A" / "events.jsonl"
    assert log.path == expected


def test_concurrent_threads_do_not_interleave(tmp_path: Path) -> None:
    """Atomicity smoke test: many threads appending must produce intact JSON lines."""
    log = EventLog(workspace_root=tmp_path, engagement_id="concurrent")
    total = 200

    def _worker(i: int) -> None:
        log.append(EventType.TOOL_CALL, {"i": i, "blob": "x" * 200})

    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as ex:
        list(ex.map(_worker, range(total)))

    events = list(log.read())
    assert len(events) == total
    assert sorted(e.payload["i"] for e in events) == list(range(total))


def test_event_log_appends_to_existing_file(tmp_path: Path) -> None:
    log_a = EventLog(workspace_root=tmp_path, engagement_id="eng-X")
    log_a.append(EventType.ENGAGEMENT_START, {})
    log_a.append(EventType.AGENT_TURN, {"turn": 1})

    log_b = EventLog(workspace_root=tmp_path, engagement_id="eng-X")
    log_b.append(EventType.AGENT_TURN, {"turn": 2})
    log_b.append(EventType.ENGAGEMENT_END, {})

    events = list(log_b.read())
    assert len(events) == 4
    assert events[0].type == "engagement.start"
    assert events[1].payload["turn"] == 1
    assert events[2].payload["turn"] == 2
    assert events[3].type == "engagement.end"


def test_for_workspace_writes_at_workspace_root(tmp_path: Path) -> None:
    log = EventLog.for_workspace(tmp_path, engagement_id="eng-root")
    assert log.path == tmp_path / "events.jsonl"
    assert log.engagement_id == "eng-root"

    log.append(EventType.ENGAGEMENT_START, {"name": "demo"})
    log.append(EventType.AGENT_TURN, {"turn": 1}, agent="decepticon")

    events = list(read_events(tmp_path / "events.jsonl"))
    assert [e.type for e in events] == ["engagement.start", "agent.turn"]
    assert events[1].agent == "decepticon"


def test_for_workspace_defaults_engagement_id_to_empty(tmp_path: Path) -> None:
    log = EventLog.for_workspace(tmp_path)
    assert log.engagement_id == ""
    assert log.path == tmp_path / "events.jsonl"

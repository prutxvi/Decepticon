# -*- coding: utf-8 -*-
"""Tests for decepticon.blue_cell.tap — pure transforms and BlueCellTap batch reads.

All filesystem IO uses tmp_path. No network, no docker, no credentials required.
"""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from decepticon.blue_cell.tap import (
    BlueCellTap,
    TapEvent,
    _parse_line_to_event,
    _strip_ansi,
)

# ── _strip_ansi ─────────────────────────────────────────────────────────────


class TestStripAnsi:
    def test_removes_sgr_sequence(self) -> None:
        assert _strip_ansi("\x1b[32mhello\x1b[0m") == "hello"

    def test_removes_osc_sequence(self) -> None:
        # OSC sequences end with BEL (\x07)
        assert _strip_ansi("\x1b]0;title\x07text") == "text"

    def test_removes_designate_charset(self) -> None:
        # ESC ( A type sequences
        assert _strip_ansi("\x1b(Bsome text") == "some text"

    def test_plain_text_unchanged(self) -> None:
        assert _strip_ansi("plain text with no escapes") == "plain text with no escapes"

    def test_empty_string(self) -> None:
        assert _strip_ansi("") == ""

    def test_mixed_ansi_and_text(self) -> None:
        result = _strip_ansi("\x1b[1;31mERROR\x1b[0m: file not found")
        assert result == "ERROR: file not found"

    def test_multiple_sgr_sequences(self) -> None:
        result = _strip_ansi("\x1b[33m\x1b[1mwarn\x1b[0m\x1b[0m")
        assert result == "warn"


# ── _parse_line_to_event ────────────────────────────────────────────────────


class TestParseLineToEvent:
    def test_blank_line_returns_none(self) -> None:
        assert _parse_line_to_event("   \n", "sandbox.tmux.main", 1000.0) is None

    def test_returns_tap_event(self) -> None:
        ev = _parse_line_to_event("ls -la /tmp", "sandbox.tmux.main", 1000.0)
        assert isinstance(ev, TapEvent)

    def test_fallback_ts_used_when_no_timestamp(self) -> None:
        ev = _parse_line_to_event("plain command", "src", 9999.0)
        assert ev is not None
        assert ev.ts == pytest.approx(9999.0)

    def test_iso_timestamp_parsed_from_line(self) -> None:
        line = "2024-01-15 10:20:30 some event"
        ev = _parse_line_to_event(line, "src", 0.0)
        assert ev is not None
        # timestamp should be a valid epoch float (not the fallback 0.0)
        assert ev.ts > 0.0
        assert ev.ts != 0.0

    def test_iso_timestamp_with_t_separator(self) -> None:
        line = "2024-06-01T12:00:00 some event"
        ev = _parse_line_to_event(line, "src", 0.0)
        assert ev is not None
        assert ev.ts > 0.0

    def test_bracketed_timestamp_parsed(self) -> None:
        line = "[2024-03-10 08:15:00] system event"
        ev = _parse_line_to_event(line, "src", 0.0)
        assert ev is not None
        assert ev.ts > 0.0

    def test_source_preserved(self) -> None:
        ev = _parse_line_to_event("some line", "sandbox.tmux.mysession", 1.0)
        assert ev is not None
        assert ev.source == "sandbox.tmux.mysession"

    def test_actor_process_extracted_from_shell_prompt(self) -> None:
        ev = _parse_line_to_event("$ nmap 10.0.0.5", "src", 1.0)
        assert ev is not None
        assert ev.actor_process == "nmap"

    def test_actor_process_extracted_from_leading_word(self) -> None:
        ev = _parse_line_to_event("curl https://example.com/", "src", 1.0)
        assert ev is not None
        assert ev.actor_process == "curl"

    def test_ansi_stripped_from_command_line(self) -> None:
        ev = _parse_line_to_event("\x1b[1mnmap\x1b[0m 10.0.0.1", "src", 1.0)
        assert ev is not None
        assert "\x1b" not in ev.actor_command_line
        assert "nmap" in ev.actor_command_line

    def test_event_outcome_always_unknown(self) -> None:
        ev = _parse_line_to_event("whatever", "src", 1.0)
        assert ev is not None
        assert ev.event_outcome == "unknown"

    def test_raw_field_equals_sanitized_line(self) -> None:
        ev = _parse_line_to_event("  ls -la  ", "src", 1.0)
        assert ev is not None
        assert ev.raw == ev.actor_command_line

    def test_network_destinations_extracted_from_ip(self) -> None:
        ev = _parse_line_to_event("nmap 192.168.1.100", "src", 1.0)
        assert ev is not None
        assert "192.168.1.100" in ev.network_destinations

    def test_network_destinations_empty_for_local_cmd(self) -> None:
        ev = _parse_line_to_event("ls /etc/passwd", "src", 1.0)
        assert ev is not None
        # No network destination in a local ls command
        assert "192.168" not in " ".join(ev.network_destinations)

    def test_malformed_timestamp_falls_back_to_default(self) -> None:
        line = "2024-99-99 99:99:99 bad date"
        ev = _parse_line_to_event(line, "src", 42.0)
        assert ev is not None
        assert ev.ts == pytest.approx(42.0)

    def test_network_destinations_is_tuple(self) -> None:
        ev = _parse_line_to_event("ping 8.8.8.8", "src", 1.0)
        assert ev is not None
        assert isinstance(ev.network_destinations, tuple)


# ── TapEvent.to_dict ────────────────────────────────────────────────────────


class TestTapEventToDict:
    def test_to_dict_shape(self) -> None:
        ev = TapEvent(
            ts=1234.5,
            source="sandbox.tmux.alpha",
            actor_process="curl",
            actor_command_line="curl https://evil.com/",
            network_destinations=("evil.com",),
            event_outcome="unknown",
            raw="curl https://evil.com/",
        )
        d = ev.to_dict()
        assert d["ts"] == 1234.5
        assert d["source"] == "sandbox.tmux.alpha"
        assert d["actor"]["process"] == "curl"
        assert d["actor"]["command_line"] == "curl https://evil.com/"
        assert d["network"]["destinations"] == ["evil.com"]
        assert d["event"]["outcome"] == "unknown"
        assert d["raw"] == "curl https://evil.com/"

    def test_to_dict_empty_destinations(self) -> None:
        ev = TapEvent(ts=1.0, source="src")
        d = ev.to_dict()
        assert d["network"]["destinations"] == []

    def test_to_dict_multiple_destinations(self) -> None:
        ev = TapEvent(ts=1.0, source="src", network_destinations=("10.0.0.1", "10.0.0.2"))
        d = ev.to_dict()
        assert len(d["network"]["destinations"]) == 2


# ── BlueCellTap ─────────────────────────────────────────────────────────────


class TestBlueCellTapInit:
    def test_accepts_string_path(self, tmp_path: Path) -> None:
        tap = BlueCellTap(str(tmp_path))
        assert tap.workspace_path == tmp_path

    def test_accepts_path_object(self, tmp_path: Path) -> None:
        tap = BlueCellTap(tmp_path)
        assert tap.workspace_path == tmp_path

    def test_stop_sets_flag(self, tmp_path: Path) -> None:
        tap = BlueCellTap(tmp_path)
        assert not tap._stop
        tap.stop()
        assert tap._stop


class TestBlueCellTapSourceFor:
    def test_target_dir_yields_target_source(self, tmp_path: Path) -> None:
        tap = BlueCellTap(tmp_path)
        path = tmp_path / ".sessions" / "_target" / "host1.log"
        assert tap._source_for(path) == "target.host1"

    def test_sessions_dir_yields_sandbox_source(self, tmp_path: Path) -> None:
        tap = BlueCellTap(tmp_path)
        path = tmp_path / ".sessions" / "main.log"
        assert tap._source_for(path) == "sandbox.tmux.main"


class TestBlueCellTapReadBatch:
    def test_no_sessions_dir_returns_empty(self, tmp_path: Path) -> None:
        tap = BlueCellTap(tmp_path)
        assert tap.read_batch() == []

    def test_reads_log_from_sessions(self, tmp_path: Path) -> None:
        sessions = tmp_path / ".sessions"
        sessions.mkdir()
        (sessions / "main.log").write_text("nmap 10.0.0.5\n", encoding="utf-8")

        tap = BlueCellTap(tmp_path)
        events = tap.read_batch()
        assert len(events) == 1
        assert events[0].source == "sandbox.tmux.main"
        assert "nmap" in events[0].actor_command_line

    def test_reads_log_from_target_dir(self, tmp_path: Path) -> None:
        target_dir = tmp_path / ".sessions" / "_target"
        target_dir.mkdir(parents=True)
        (target_dir / "webserver.log").write_text("suspicious_cmd --arg\n", encoding="utf-8")

        tap = BlueCellTap(tmp_path)
        events = tap.read_batch()
        assert len(events) == 1
        assert events[0].source == "target.webserver"

    def test_skips_non_log_files(self, tmp_path: Path) -> None:
        sessions = tmp_path / ".sessions"
        sessions.mkdir()
        (sessions / "main.log").write_text("cmd\n", encoding="utf-8")
        (sessions / "notes.txt").write_text("should be ignored\n", encoding="utf-8")

        tap = BlueCellTap(tmp_path)
        events = tap.read_batch()
        assert len(events) == 1

    def test_reads_jsonl_file(self, tmp_path: Path) -> None:
        sessions = tmp_path / ".sessions"
        sessions.mkdir()
        (sessions / "events.jsonl").write_text("ls -la /etc\n", encoding="utf-8")

        tap = BlueCellTap(tmp_path)
        events = tap.read_batch()
        assert len(events) == 1

    def test_blank_lines_filtered_out(self, tmp_path: Path) -> None:
        sessions = tmp_path / ".sessions"
        sessions.mkdir()
        (sessions / "main.log").write_text("\n\n  \ncmd1\n\ncmd2\n", encoding="utf-8")

        tap = BlueCellTap(tmp_path)
        events = tap.read_batch()
        assert len(events) == 2

    def test_events_sorted_by_ts(self, tmp_path: Path) -> None:
        sessions = tmp_path / ".sessions"
        sessions.mkdir()
        # Two lines with parseable timestamps in reverse order
        content = "2024-06-01 12:00:02 second cmd\n2024-06-01 12:00:01 first cmd\n"
        (sessions / "main.log").write_text(content, encoding="utf-8")

        tap = BlueCellTap(tmp_path)
        events = tap.read_batch()
        assert len(events) == 2
        assert events[0].ts <= events[1].ts

    def test_read_batch_resets_offsets(self, tmp_path: Path) -> None:
        sessions = tmp_path / ".sessions"
        sessions.mkdir()
        (sessions / "main.log").write_text("first batch line\n", encoding="utf-8")

        tap = BlueCellTap(tmp_path)
        tap.read_batch()
        # Offsets were set after first batch
        assert len(tap._offsets) > 0
        # Second read_batch resets offsets and reads from beginning
        events2 = tap.read_batch()
        assert len(events2) == 1

    def test_multiple_sessions_combined(self, tmp_path: Path) -> None:
        sessions = tmp_path / ".sessions"
        sessions.mkdir()
        (sessions / "sess1.log").write_text("cmd_a\n", encoding="utf-8")
        (sessions / "sess2.log").write_text("cmd_b\n", encoding="utf-8")

        tap = BlueCellTap(tmp_path)
        events = tap.read_batch()
        assert len(events) == 2
        sources = {e.source for e in events}
        assert "sandbox.tmux.sess1" in sources
        assert "sandbox.tmux.sess2" in sources

    def test_sessions_dir_missing_does_not_raise(self, tmp_path: Path) -> None:
        tap = BlueCellTap(tmp_path)
        # No .sessions dir exists — should return [] without raising
        result = tap.read_batch()
        assert result == []


class TestBlueCellTapFollow:
    def test_follow_stops_after_stop_called(self, tmp_path: Path) -> None:
        """Calling stop() inside the loop causes follow() to finish after the iteration."""
        sessions = tmp_path / ".sessions"
        sessions.mkdir()
        log = sessions / "main.log"
        log.write_text("event_one\nevent_two\nevent_three\n", encoding="utf-8")

        tap = BlueCellTap(tmp_path)

        collected: list[TapEvent] = []
        for ev in tap.follow(poll_seconds=0.001):
            collected.append(ev)
            tap.stop()  # signal stop after first batch

        # At least one event collected; generator terminated after stop()
        assert len(collected) >= 1

    def test_follow_yields_events_from_new_lines(self, tmp_path: Path) -> None:
        sessions = tmp_path / ".sessions"
        sessions.mkdir()
        log = sessions / "main.log"
        log.write_text("", encoding="utf-8")

        tap = BlueCellTap(tmp_path)
        # First do a dummy poll to set offsets
        tap._offsets[log] = 0

        # Write a line THEN collect one event
        log.write_text("new event line\n", encoding="utf-8")

        collected: list[TapEvent] = []
        for ev in tap.follow(poll_seconds=0.001):
            collected.append(ev)
            tap.stop()

        assert len(collected) >= 1
        assert any("new event" in e.actor_command_line for e in collected)

    def test_heartbeat_emitted_after_inactivity(self, tmp_path: Path) -> None:
        """Heartbeat fires when no events are seen for > poll_seconds * 10."""
        sessions = tmp_path / ".sessions"
        sessions.mkdir()

        tap = BlueCellTap(tmp_path)
        # Force last_heartbeat to be in the past so heartbeat fires immediately
        # We do this by patching time.time inside follow — simpler: use a very
        # short poll interval and collect with a tight generator
        heartbeats: list[TapEvent] = []

        # We'll collect from follow with a very short poll and stop after
        # the first heartbeat. Force the timing by starting with no events.
        start = time.time()
        for ev in tap.follow(poll_seconds=0.01):
            if ev.source == "_meta.heartbeat":
                heartbeats.append(ev)
                tap.stop()
                break
            if time.time() - start > 5.0:
                tap.stop()
                break

        assert len(heartbeats) >= 1
        assert heartbeats[0].raw == "<heartbeat>"

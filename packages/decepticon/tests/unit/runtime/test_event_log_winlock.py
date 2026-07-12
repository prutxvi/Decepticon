# -*- coding: utf-8 -*-
"""test_event_log_winlock module."""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock, call, patch

import pytest

from decepticon.runtime.event_log import EventLog, EventType, _acquire_lock, _release_lock


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only locking path")
def test_release_lock_seeks_to_byte_zero_before_unlock(tmp_path: Path) -> None:
    target = tmp_path / "lock_test.bin"
    target.write_bytes(b"existing content here")

    mock_msvcrt = MagicMock()
    mock_msvcrt.LK_LOCK = 2
    mock_msvcrt.LK_UNLCK = 0

    with patch.dict("sys.modules", {"msvcrt": mock_msvcrt}):
        with open(target, "ab") as fh:
            fd = fh.fileno()
            _acquire_lock(fd)
            fh.write(b"new line\n")
            fh.flush()
            position_after_write = os.lseek(fd, 0, os.SEEK_CUR)
            assert position_after_write > 0
            _release_lock(fd)
            position_after_release = os.lseek(fd, 0, os.SEEK_CUR)

    assert position_after_release == 0

    lock_calls = [c for c in mock_msvcrt.mock_calls if "locking" in str(c)]
    assert len(lock_calls) == 2
    assert lock_calls[0] == call.locking(fd, mock_msvcrt.LK_LOCK, 1)
    assert lock_calls[1] == call.locking(fd, mock_msvcrt.LK_UNLCK, 1)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only locking path")
def test_acquire_lock_seeks_to_byte_zero_before_locking(tmp_path: Path) -> None:
    target = tmp_path / "seek_test.bin"
    target.write_bytes(b"preexisting bytes to push EOF forward")

    mock_msvcrt = MagicMock()
    mock_msvcrt.LK_LOCK = 2
    mock_msvcrt.LK_UNLCK = 0

    with patch.dict("sys.modules", {"msvcrt": mock_msvcrt}):
        with open(target, "ab") as fh:
            fd = fh.fileno()
            initial_pos = os.lseek(fd, 0, os.SEEK_CUR)
            assert initial_pos > 0
            _acquire_lock(fd)
            pos_after_acquire = os.lseek(fd, 0, os.SEEK_CUR)
            assert pos_after_acquire == 0
            _release_lock(fd)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows-only locking path")
def test_acquire_and_release_same_fixed_offset_repeated(tmp_path: Path) -> None:
    target = tmp_path / "multi_cycle.bin"

    mock_msvcrt = MagicMock()
    mock_msvcrt.LK_LOCK = 2
    mock_msvcrt.LK_UNLCK = 0

    with patch.dict("sys.modules", {"msvcrt": mock_msvcrt}):
        with open(target, "ab") as fh:
            fd = fh.fileno()
            for _ in range(3):
                _acquire_lock(fd)
                fh.write(b"x" * 50)
                fh.flush()
                _release_lock(fd)

    all_locking_calls = [c for c in mock_msvcrt.mock_calls if "locking" in str(c)]
    assert len(all_locking_calls) == 6
    for i, c in enumerate(all_locking_calls):
        expected_mode = mock_msvcrt.LK_LOCK if i % 2 == 0 else mock_msvcrt.LK_UNLCK
        assert c == call.locking(fd, expected_mode, 1)


def test_append_is_atomic_across_multiple_eventlog_instances(tmp_path: Path) -> None:
    total = 100
    barrier = threading.Barrier(4)

    def _writer(worker_id: int) -> None:
        log = EventLog(workspace_root=tmp_path, engagement_id="shared-eng")
        barrier.wait()
        for i in range(total // 4):
            log.append(EventType.TOOL_CALL, {"worker": worker_id, "i": i})

    threads = [threading.Thread(target=_writer, args=(w,)) for w in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    log = EventLog(workspace_root=tmp_path, engagement_id="shared-eng")
    events = list(log.read())
    assert len(events) == total
    for e in events:
        assert e.type == "tool.call"
        assert "worker" in e.payload
        assert "i" in e.payload

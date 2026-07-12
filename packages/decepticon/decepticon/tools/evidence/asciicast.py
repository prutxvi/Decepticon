# -*- coding: utf-8 -*-
"""Tmux pipe-pane log → asciicast v2 converter.

Asciicast v2 spec: https://docs.asciinema.org/manual/asciicast/v2/

Format (JSON Lines):

  Line 1: header object
    {"version": 2, "width": 120, "height": 30, "timestamp": 1716832800,
     "title": "...", "env": {"SHELL":"...", "TERM":"..."}}

  Line 2+: event tuples
    [<elapsed-seconds>, "o", "<output bytes>"]
    [<elapsed-seconds>, "i", "<input bytes>"]

Decepticon's pipe-pane log is raw terminal output (escape sequences and
all) with no embedded timing information. The reconstruction strategy:

1. Read the pipe-pane log as raw bytes.
2. Read the session's command-history sidecar (when present) to recover
   approximate per-command timing. Sidecar lives at
   ``<log_path>.events`` and contains ``<ts> <event-kind> <command>``
   lines emitted by the sandbox daemon when it dispatches commands.
3. If a sidecar isn't present, split the log on PS1-marker boundaries
   (the same markers TmuxSessionManager uses for completion detection)
   and assign uniform spacing.

The output is a single ``.cast`` file plus a tiny ``.json`` companion that
records the engagement slug, session name, original log path, and a
heuristic confidence score (``timing_quality``: ``measured`` when a sidecar
was available, ``synthetic`` when uniform spacing was used).
"""

from __future__ import annotations

import json
import logging
import re
import time
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


_PS1_MARKER = re.compile(r"DECEPTICON_PROMPT_END_\w+")
_DEFAULT_WIDTH = 120
_DEFAULT_HEIGHT = 30
_SYNTHETIC_INTERVAL_SECONDS = 0.5


class AsciicastExportError(RuntimeError):
    """Raised when conversion can't proceed (missing log, malformed sidecar)."""


def _load_sidecar(log_path: Path) -> list[tuple[float, str]] | None:
    """Return a list of (relative_seconds, marker) tuples, or None if absent.

    Sidecar format: lines of ``<unix-timestamp-with-decimals> <event>``.
    ``event`` is unused here; we keep it for future provenance.
    """
    sidecar = log_path.with_suffix(log_path.suffix + ".events")
    if not sidecar.exists():
        return None
    try:
        raw = sidecar.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        log.warning("sidecar read failed: %s", exc)
        return None
    parsed: list[tuple[float, str]] = []
    base_ts: float | None = None
    for line_idx, line in enumerate(raw.splitlines()):
        parts = line.strip().split(maxsplit=1)
        if not parts:
            continue
        try:
            ts = float(parts[0])
        except ValueError:
            log.warning("sidecar line %d: malformed timestamp %r", line_idx, parts[0])
            continue
        kind = parts[1] if len(parts) > 1 else ""
        if base_ts is None:
            base_ts = ts
        parsed.append((ts - base_ts, kind))
    return parsed if parsed else None


def _segments_from_markers(content: str) -> list[str]:
    """Split log content on PS1 markers and return per-command segments.

    Empty segments are dropped. Trailing partial output (no closing marker)
    is preserved as the last segment so we don't lose final command output.
    """
    parts = _PS1_MARKER.split(content)
    return [p for p in parts if p.strip()]


def export_asciicast(
    log_path: str | Path,
    output_path: str | Path,
    *,
    session_name: str = "",
    width: int = _DEFAULT_WIDTH,
    height: int = _DEFAULT_HEIGHT,
    title: str = "",
) -> dict[str, Any]:
    """Convert a tmux pipe-pane log to an asciicast v2 file.

    Returns a manifest dict describing the export (paths, sizes, timing
    quality). Use this dict in the engagement reporter to render the
    artifact bundle.
    """
    log_p = Path(log_path)
    out_p = Path(output_path)

    if not log_p.exists():
        raise AsciicastExportError(f"pipe-pane log not found: {log_p}")
    try:
        content = log_p.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise AsciicastExportError(f"failed to read log {log_p}: {exc}") from exc

    sidecar = _load_sidecar(log_p)
    timing_quality = "measured" if sidecar else "synthetic"

    segments = _segments_from_markers(content)
    if not segments:
        segments = [content] if content else []

    if sidecar and len(sidecar) >= len(segments):
        timestamps = [sidecar[i][0] for i in range(len(segments))]
    else:
        timestamps = [i * _SYNTHETIC_INTERVAL_SECONDS for i in range(len(segments))]
        if sidecar:
            timing_quality = "synthetic-fallback"

    header = {
        "version": 2,
        "width": width,
        "height": height,
        "timestamp": int(time.time()),
        "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"},
    }
    if title or session_name:
        header["title"] = title or f"Decepticon session {session_name}"

    out_p.parent.mkdir(parents=True, exist_ok=True)
    with out_p.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps(header) + "\n")
        for ts, segment in zip(timestamps, segments, strict=False):
            event = [round(ts, 3), "o", segment]
            fh.write(json.dumps(event, ensure_ascii=False) + "\n")

    manifest_path = out_p.with_suffix(out_p.suffix + ".manifest.json")
    manifest = {
        "session_name": session_name,
        "source_log": str(log_p),
        "asciicast_path": str(out_p),
        "timing_quality": timing_quality,
        "segments": len(segments),
        "duration_seconds": round(timestamps[-1] if timestamps else 0.0, 3),
        "bytes_in_log": len(content),
        "bytes_in_cast": out_p.stat().st_size,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False), encoding="utf-8")
    return manifest


def list_recordings(evidence_dir: str | Path) -> list[dict[str, Any]]:
    """Return manifests for every ``.cast.manifest.json`` under ``evidence_dir``."""
    base = Path(evidence_dir)
    if not base.exists():
        return []
    manifests: list[dict[str, Any]] = []
    for path in sorted(base.rglob("*.cast.manifest.json")):
        try:
            manifests.append(json.loads(path.read_text(encoding="utf-8")))
        except (json.JSONDecodeError, OSError) as exc:
            log.warning("failed to read manifest %s: %s", path, exc)
    return manifests

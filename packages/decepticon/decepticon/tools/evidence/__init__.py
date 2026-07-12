# -*- coding: utf-8 -*-
from __future__ import annotations
"""Engagement evidence tools — capture, bundle, and export operational artifacts.

The Decepticon sandbox already captures every tmux session's full stream
via ``pipe-pane`` (see decepticon.middleware.notifications). These tools
turn that captured stream into deliverable artifacts the operator can hand
to the client at out-brief: asciicast v2 recordings for browser playback,
plain-text transcripts, and bundling metadata.

Tool inventory
--------------
- ``export_session_asciicast`` — convert a tmux pipe-pane log to an
  asciicast v2 file (``.cast``) for asciinema-player playback in a browser.
- ``list_session_recordings`` — enumerate all captured sessions in the
  engagement's evidence directory.
"""

from decepticon.tools.evidence.tools import EVIDENCE_TOOLS

__all__ = ["EVIDENCE_TOOLS"]

from __future__ import annotations
"""Decepticon Python CLI surface — invoked as ``python -m decepticon.cli``.

The CLI lives here (rather than in ``clients/launcher/``) for two reasons:

1. The Go launcher is for the interactive desktop experience; the CLI in
   this module is the headless / CI / scripted entry. CI environments
   should not need a compiled Go binary just to run a security scan.
2. The CLI talks directly to the LangGraph SDK and the in-process
   ``decepticon`` agents, with no Docker dependency. The Go launcher's
   role of "bring up the whole stack" doesn't apply to remote-LangGraph
   or in-container CI runs.

Subcommands
-----------
- ``scan`` — run a one-shot security scan against a target (filesystem
  path, git URL, or HTTP URL); emit findings as SARIF v2.1.0; exit
  non-zero when severity threshold is breached.
"""

from decepticon.cli.scan import main as scan_main

__all__ = ["scan_main"]

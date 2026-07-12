# -*- coding: utf-8 -*-
"""``decepticon-cli scan`` — headless / CI security scan entry.

Modeled after Strix's CLI for surface familiarity, with Decepticon's
engagement / OPPLAN / RoE discipline preserved:

  decepticon-cli scan --target ./ --scan-mode quick \
      --sarif-output decepticon.sarif --fail-on high

Modes
-----
- ``quick`` — short timeout, scoped to the diff against ``--diff-base``
  when run inside a git repository; ideal for PR-time CI gates.
- ``standard`` — full source-aware scan with no time cap.
- ``deep`` — long-running; includes dynamic analysis where supported.

Outputs
-------
- A SARIF v2.1.0 document at ``--sarif-output`` (default: skipped).
- A line-buffered JSONL of findings to stdout when ``--non-interactive``
  is set (so CI logs are useful even when the SARIF write fails).
- Exit code: 0 = no findings; 1 = findings ≥ ``--fail-on`` severity
  (default ``high``); 2 = config / invocation error; 3 = scan internal error.

The actual scan is driven by the existing ``decepticon`` orchestrator via
the LangGraph SDK. This module is a thin shell: argument parsing, scope
resolution (git diff base, target validation), one-shot run dispatch,
SARIF export, threshold gating.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

log = logging.getLogger(__name__)


EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_CONFIG = 2
EXIT_INTERNAL = 3


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="decepticon-cli scan",
        description="Run a Decepticon security scan and emit SARIF for CI.",
    )
    p.add_argument(
        "--target",
        "-t",
        action="append",
        required=False,
        default=[],
        help="Target to scan (filesystem path, git URL, or HTTP URL). Repeatable.",
    )
    p.add_argument(
        "--scan-mode",
        choices=["quick", "standard", "deep"],
        default="standard",
        help="Scan depth/timeout profile.",
    )
    p.add_argument(
        "--scope-mode",
        choices=["full", "diff"],
        default="full",
        help="``diff`` restricts the scan to files changed against --diff-base.",
    )
    p.add_argument(
        "--diff-base",
        default="origin/main",
        help="Git ref to diff against when --scope-mode=diff.",
    )
    p.add_argument(
        "--instruction",
        default="",
        help="Free-form scope or focus instruction passed to the orchestrator.",
    )
    p.add_argument(
        "--instruction-file",
        type=Path,
        default=None,
        help="Path to a file containing rules of engagement / scope notes.",
    )
    p.add_argument(
        "--non-interactive",
        "-n",
        action="store_true",
        help="Disable interactive UI; print JSONL events to stdout instead.",
    )
    p.add_argument(
        "--sarif-output",
        type=Path,
        default=None,
        help="Path to write SARIF v2.1.0 findings (skipped when unset).",
    )
    p.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="high",
        help="Minimum severity that triggers a non-zero exit.",
    )
    p.add_argument(
        "--langgraph-url",
        default=os.environ.get("DECEPTICON_API_URL", "http://localhost:2024"),
        help="LangGraph platform API URL (default: $DECEPTICON_API_URL).",
    )
    p.add_argument(
        "--assistant",
        default="decepticon",
        help="LangGraph assistant graph name (default: decepticon).",
    )
    p.add_argument(
        "--engagement-name",
        default=None,
        help="Override engagement slug; defaults to a timestamped scan name.",
    )
    p.add_argument(
        "--timeout",
        type=int,
        default=None,
        help="Per-scan wall-clock timeout in seconds; mode default if unset.",
    )
    p.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable debug logging to stderr.",
    )
    return p


_MODE_DEFAULTS = {
    "quick": {"timeout": 600, "reasoning_effort": "medium"},
    "standard": {"timeout": 3600, "reasoning_effort": "high"},
    "deep": {"timeout": 14400, "reasoning_effort": "high"},
}


def _validate_targets(targets: list[str]) -> str | None:
    if not targets:
        return "at least one --target is required"
    for t in targets:
        if t.startswith(("http://", "https://", "git@", "git+", "ssh://")):
            continue
        path = Path(t)
        if not path.exists():
            return f"--target {t!r} does not exist on disk"
    return None


def _git_diff_files(base: str, cwd: Path) -> list[str] | None:
    """Run ``git diff --name-only <base>...HEAD`` and return changed paths.

    Returns None on any git failure — caller should fall back to full scope.
    """
    try:
        result = subprocess.run(
            ["git", "diff", "--name-only", f"{base}...HEAD"],
            cwd=cwd,
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.warning("git diff failed: %s", exc)
        return None
    if result.returncode != 0:
        log.warning("git diff returned %d: %s", result.returncode, result.stderr.strip())
        return None
    files = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    return files


def _resolve_engagement_name(supplied: str | None) -> str:
    if supplied:
        return supplied
    import datetime  # noqa: PLC0415

    stamp = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    return f"scan-{stamp}"


def _emit_jsonl_event(event: dict[str, Any]) -> None:
    print(json.dumps(event, default=str, ensure_ascii=False), flush=True)


def _instruction_text(args: argparse.Namespace) -> str:
    pieces: list[str] = []
    if args.instruction:
        pieces.append(args.instruction.strip())
    if args.instruction_file:
        try:
            pieces.append(args.instruction_file.read_text(encoding="utf-8").strip())
        except OSError as exc:
            raise RuntimeError(
                f"failed to read --instruction-file {args.instruction_file}: {exc}"
            ) from exc
    return "\n\n".join(pieces)


def _dispatch_scan_via_sdk(
    *,
    langgraph_url: str,
    assistant: str,
    engagement_name: str,
    targets: list[str],
    diff_files: list[str] | None,
    instruction: str,
    scan_mode: str,
    timeout_seconds: int,
    non_interactive: bool,
) -> dict[str, Any]:
    """Drive a one-shot scan through the LangGraph SDK; return a result envelope.

    Wraps the SDK in a defensive import so a missing langgraph-sdk yields
    EXIT_CONFIG rather than a Python traceback in CI logs.
    """
    try:
        from langgraph_sdk import get_client  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "langgraph-sdk is not installed in this Python environment. "
            "Install with: pip install langgraph-sdk"
        ) from exc

    client = get_client(url=langgraph_url)

    scope_payload = {
        "targets": targets,
        "scope_mode": "diff" if diff_files is not None else "full",
        "diff_files": diff_files or [],
        "scan_mode": scan_mode,
        "instruction": instruction,
    }
    state_input = {
        "messages": [
            {
                "role": "user",
                "content": (
                    "Run a one-shot security scan. Scope and instructions "
                    f"are attached as JSON:\n\n{json.dumps(scope_payload, indent=2)}"
                ),
            }
        ],
        "engagement_name": engagement_name,
        "scan_scope": scope_payload,
    }
    config = {
        "configurable": {
            "engagement_name": engagement_name,
            "scan_mode": scan_mode,
        }
    }

    import asyncio  # noqa: PLC0415

    async def _run() -> dict[str, Any]:
        thread = await client.threads.create()
        events_collected: list[dict[str, Any]] = []
        last_event_kind = ""
        async for chunk in client.runs.stream(
            thread["thread_id"],
            assistant_id=assistant,
            input=state_input,
            config=config,
            stream_mode=["values", "updates", "custom"],
        ):
            event = {
                "event": chunk.event,
                "data": chunk.data,
            }
            events_collected.append(event)
            last_event_kind = chunk.event
            if non_interactive:
                _emit_jsonl_event({"type": chunk.event, "data": chunk.data})
        return {
            "thread_id": thread["thread_id"],
            "last_event": last_event_kind,
            "event_count": len(events_collected),
        }

    return asyncio.run(asyncio.wait_for(_run(), timeout=timeout_seconds))


def _load_findings_graph(engagement_name: str) -> Any | None:
    """Read the engagement's KnowledgeGraph from the conventional location.

    Returns None when the graph isn't present (e.g. the orchestrator never
    persisted findings). Caller treats absent graph as "zero findings".
    """
    workspace = Path(
        os.environ.get("DECEPTICON_ENGAGEMENT_WORKSPACE")
        or (Path.home() / ".decepticon" / "workspace" / engagement_name)
    )
    graph_path = workspace / "graph.json"
    if not graph_path.exists():
        log.info("no graph.json at %s; treating as zero findings", graph_path)
        return None
    try:
        from decepticon_core.types.kg import KnowledgeGraph  # noqa: PLC0415

        return KnowledgeGraph.from_json(graph_path.read_text(encoding="utf-8"))
    except Exception as exc:  # noqa: BLE001
        log.warning("failed to load graph at %s: %s", graph_path, exc)
        return None


def _write_sarif_and_gate(
    graph: Any | None,
    sarif_output: Path | None,
    fail_on: str,
    engagement_name: str,
) -> int:
    """Emit SARIF (if requested) and return the exit code dictated by the severity gate."""
    if graph is None:
        if sarif_output:
            sarif_output.parent.mkdir(parents=True, exist_ok=True)
            sarif_output.write_text(
                json.dumps(
                    {
                        "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
                        "version": "2.1.0",
                        "runs": [
                            {
                                "tool": {
                                    "driver": {
                                        "name": "Decepticon",
                                        "version": "0.0.0",
                                    }
                                },
                                "results": [],
                            }
                        ],
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        return EXIT_OK

    from decepticon.tools.research.sarif_export import (  # noqa: PLC0415
        export_findings_to_sarif,
        severity_threshold_breach,
    )

    doc = export_findings_to_sarif(graph, engagement_name=engagement_name)
    if sarif_output:
        sarif_output.parent.mkdir(parents=True, exist_ok=True)
        sarif_output.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    return EXIT_FINDINGS if severity_threshold_breach(doc, fail_on=fail_on) else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )

    if err := _validate_targets(args.target):
        print(f"error: {err}", file=sys.stderr)
        return EXIT_CONFIG

    try:
        instruction = _instruction_text(args)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG

    diff_files: list[str] | None = None
    if args.scope_mode == "diff":
        first_target = args.target[0]
        diff_root = Path(first_target) if Path(first_target).exists() else Path.cwd()
        diff_files = _git_diff_files(args.diff_base, diff_root)
        if diff_files is None:
            print(
                f"warning: diff-scope requested but git diff against "
                f"{args.diff_base!r} failed; falling back to full scope",
                file=sys.stderr,
            )

    engagement_name = _resolve_engagement_name(args.engagement_name)
    mode_cfg = _MODE_DEFAULTS[args.scan_mode]
    timeout = args.timeout or mode_cfg["timeout"]

    try:
        result = _dispatch_scan_via_sdk(
            langgraph_url=args.langgraph_url,
            assistant=args.assistant,
            engagement_name=engagement_name,
            targets=args.target,
            diff_files=diff_files,
            instruction=instruction,
            scan_mode=args.scan_mode,
            timeout_seconds=timeout,
            non_interactive=args.non_interactive,
        )
        log.info("scan complete: %s", result)
    except RuntimeError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_CONFIG
    except Exception as exc:  # noqa: BLE001
        print(f"scan failed: {exc}", file=sys.stderr)
        return EXIT_INTERNAL

    graph = _load_findings_graph(engagement_name)
    return _write_sarif_and_gate(
        graph=graph,
        sarif_output=args.sarif_output,
        fail_on=args.fail_on,
        engagement_name=engagement_name,
    )

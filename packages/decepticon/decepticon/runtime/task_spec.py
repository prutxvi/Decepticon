# -*- coding: utf-8 -*-
"""Per-dispatch task spec for CART live-replay.

When :class:`decepticon.runtime.cart.ReplayRunner` flips from dry-run to
live mode it must hand the engagement orchestrator a self-contained
description of *one* sub-agent dispatch: which role to run, the objective
text, the OPPLAN objectives and ATT&CK techniques the dispatch covers, and
(optionally) the recording the sub-run should replay so the re-execution is
deterministic.

:class:`SubAgentTaskSpec` is that contract. It is the data PR #301 referenced
from ``cart.py`` (see :meth:`ReplayRunner.execute`). The static
``SubAgentSpec`` registration type is unrelated: that describes how a
sub-agent role is *registered*, this describes a single *dispatch* of one.

The :class:`Dispatcher` protocol is the seam the orchestrator implements:
given a spec, it runs the sub-agent (installing
``ReplayMiddleware(open_replay(replay_record_path))`` when a record path is
set) and returns the run result dict.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

__all__ = ["Dispatcher", "SubAgentTaskSpec"]


@dataclass(frozen=True, slots=True)
class SubAgentTaskSpec:
    """One CART replay dispatch handed to a :class:`Dispatcher`.

    Fields:

    * ``agent_name`` — which sub-agent role to run (e.g. ``"recon"``).
    * ``prompt`` — the task instruction / objective text for the sub-run.
    * ``objective_ids`` — OPPLAN objective ids this dispatch covers.
    * ``technique_tags`` — ATT&CK technique tags that drove the selection.
    * ``replay_record_path`` — path to a recording JSONL. When set, the
      dispatcher installs
      ``ReplayMiddleware(open_replay(replay_record_path))`` so the sub-run
      is deterministic; when ``None`` the dispatch runs live.
    * ``dry_run`` — when ``True`` the dispatcher must not execute actions,
      only describe what it would do.
    """

    agent_name: str
    prompt: str
    objective_ids: tuple[str, ...] = ()
    technique_tags: tuple[str, ...] = ()
    replay_record_path: str | None = None
    dry_run: bool = False

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict (tuples rendered as lists)."""
        return {
            "agent_name": self.agent_name,
            "prompt": self.prompt,
            "objective_ids": list(self.objective_ids),
            "technique_tags": list(self.technique_tags),
            "replay_record_path": self.replay_record_path,
            "dry_run": self.dry_run,
        }

    @classmethod
    def from_dict(cls, obj: dict[str, Any]) -> SubAgentTaskSpec:
        """Rebuild a spec from :meth:`to_dict` output (lists -> tuples)."""
        return cls(
            agent_name=str(obj["agent_name"]),
            prompt=str(obj["prompt"]),
            objective_ids=tuple(obj.get("objective_ids") or ()),
            technique_tags=tuple(obj.get("technique_tags") or ()),
            replay_record_path=obj.get("replay_record_path"),
            dry_run=bool(obj.get("dry_run", False)),
        )


@runtime_checkable
class Dispatcher(Protocol):
    """Seam the orchestrator implements to run one :class:`SubAgentTaskSpec`.

    CART consumes only this contract: given a spec, the dispatcher runs the
    sub-agent (installing replay middleware when ``replay_record_path`` is
    set) and returns the run-result dict.
    """

    def __call__(self, spec: SubAgentTaskSpec) -> dict[str, Any]:
        raise NotImplementedError

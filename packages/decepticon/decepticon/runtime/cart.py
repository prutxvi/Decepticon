# -*- coding: utf-8 -*-
"""CART — Continuous Automated Red Teaming.

CART is the loop that turns a one-shot engagement into infrastructure-as-code:
the customer's infra changes, Decepticon replays the last successful kill
chain against the new state, and alerts on delta. The competitive moat
versus Strix, XBOW, and AIxCC entries — all of which do point-in-time scans.

Pieces in this module
---------------------
- :class:`Watcher` — read-only agent skeleton that subscribes to
  infrastructure change feeds (CloudTrail, Azure Activity Log, K8s audit
  log, Terraform apply webhooks, GitHub Actions deploy events). On a
  match against the engagement's scope, it enqueues a replay run.

- :class:`EngagementSnapshot` — stable, hashable view of the engagement's
  attack graph. Two snapshots produce a :class:`SnapshotDelta` with
  added/removed/changed nodes and edges, keyed by ATT&CK technique tag.

- :class:`ReplayRunner` — orchestrates a replay using the existing
  :class:`decepticon.runtime.recording.ReplayMiddleware`. When a snapshot
  shows new attack surface in a technique-tagged region, the runner
  re-executes only the objectives mapped to that technique.

- :class:`OPPLANAdapter` — pluggable seam between this module and the
  current (linear) vs future (ATT&CK matrix) OPPLAN. Today: returns
  objectives in declaration order. Post-redesign: returns objectives
  filtered by technique tag. CART code consumes the adapter contract,
  not the OPPLAN internals.

What this module deliberately does NOT do
-----------------------------------------
- It does not own the webhook receiver. That's an HTTP endpoint that lives
  on the langgraph service and translates inbound events to
  :class:`ChangeEvent` records dispatched here.
- It does not write to Neo4j directly. The Δ subgraph emission is a
  contract on :class:`AttackGraphProtocol`; Neo4j-backed graphs implement it.
- It does not gate any actions. CART is read-mostly; only ReplayRunner's
  invocations of the orchestrator can ever execute commands, and those go
  through the same HITL / SafeCommand / PromptInjection stack as a fresh
  engagement.

TODO markers flag the OPPLAN-matrix migration touch-points (see
``OPPLANAdapter`` and ``_select_objectives_for_techniques``).
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from decepticon.runtime.recording import ReplayMiddleware
from decepticon.runtime.task_spec import Dispatcher, SubAgentTaskSpec

log = logging.getLogger(__name__)


@dataclass
class ChangeEvent:
    """A single infrastructure-change event from an external feed."""

    source: str
    event_type: str
    resource_id: str
    resource_kind: str
    technique_tags: list[str] = field(default_factory=list)
    raw_payload: dict[str, Any] = field(default_factory=dict)
    observed_at: float = 0.0


@dataclass(frozen=True)
class SnapshotNodeKey:
    """Stable identity for a node across two snapshots."""

    kind: str
    label: str


@dataclass
class EngagementSnapshot:
    """A read-only, hashable view of an attack graph at a point in time."""

    snapshot_id: str
    captured_at: float
    nodes: dict[SnapshotNodeKey, dict[str, Any]]
    edges: dict[tuple[SnapshotNodeKey, SnapshotNodeKey, str], dict[str, Any]]

    @staticmethod
    def from_graph(graph: Any) -> EngagementSnapshot:
        node_iter = getattr(graph, "nodes", None)
        if node_iter is None:
            nodes_dict: dict[SnapshotNodeKey, dict[str, Any]] = {}
            edges_dict: dict[tuple[SnapshotNodeKey, SnapshotNodeKey, str], dict[str, Any]] = {}
        else:
            iterable = node_iter.values() if hasattr(node_iter, "values") else node_iter
            nodes_dict = {}
            id_to_key: dict[Any, SnapshotNodeKey] = {}
            for n in iterable:
                key = SnapshotNodeKey(
                    kind=str(getattr(n, "kind", "") or "").lower(),
                    label=str(getattr(n, "label", "") or ""),
                )
                nodes_dict[key] = dict(getattr(n, "properties", {}) or {})
                id_to_key[getattr(n, "id", id(n))] = key

            edge_iter = getattr(graph, "edges", None) or []
            edge_iterable = edge_iter.values() if hasattr(edge_iter, "values") else edge_iter
            edges_dict = {}
            for e in edge_iterable:
                src = id_to_key.get(getattr(e, "source", None))
                dst = id_to_key.get(getattr(e, "target", None))
                if src is None or dst is None:
                    continue
                kind = str(getattr(e, "kind", "") or "").lower()
                edges_dict[(src, dst, kind)] = dict(getattr(e, "properties", {}) or {})

        return EngagementSnapshot(
            snapshot_id=_hash_snapshot(nodes_dict, edges_dict),
            captured_at=time.time(),
            nodes=nodes_dict,
            edges=edges_dict,
        )


@dataclass
class SnapshotDelta:
    """Two-snapshot diff result, keyed by ATT&CK technique tag when present."""

    snapshot_a_id: str
    snapshot_b_id: str
    added_nodes: list[SnapshotNodeKey]
    removed_nodes: list[SnapshotNodeKey]
    changed_nodes: list[SnapshotNodeKey]
    added_edges: list[tuple[SnapshotNodeKey, SnapshotNodeKey, str]]
    removed_edges: list[tuple[SnapshotNodeKey, SnapshotNodeKey, str]]
    affected_techniques: list[str]

    @property
    def is_empty(self) -> bool:
        return not (
            self.added_nodes
            or self.removed_nodes
            or self.changed_nodes
            or self.added_edges
            or self.removed_edges
        )


def _hash_snapshot(nodes: dict, edges: dict) -> str:
    payload = json.dumps(
        {
            "nodes": [
                (k.kind, k.label) for k in sorted(nodes.keys(), key=lambda x: (x.kind, x.label))
            ],
            "edges": [
                (s.kind, s.label, d.kind, d.label, k)
                for (s, d, k) in sorted(
                    edges.keys(),
                    key=lambda x: (x[0].kind, x[0].label, x[1].kind, x[1].label, x[2]),
                )
            ],
        },
        sort_keys=True,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(payload).hexdigest()


def diff_snapshots(a: EngagementSnapshot, b: EngagementSnapshot) -> SnapshotDelta:
    """Return the Δ between two snapshots, with technique tags from changed nodes."""
    a_node_keys = set(a.nodes.keys())
    b_node_keys = set(b.nodes.keys())
    added = sorted(b_node_keys - a_node_keys, key=lambda k: (k.kind, k.label))
    removed = sorted(a_node_keys - b_node_keys, key=lambda k: (k.kind, k.label))
    changed: list[SnapshotNodeKey] = []
    for key in sorted(a_node_keys & b_node_keys, key=lambda k: (k.kind, k.label)):
        if a.nodes[key] != b.nodes[key]:
            changed.append(key)

    a_edge_keys = set(a.edges.keys())
    b_edge_keys = set(b.edges.keys())
    added_edges = sorted(
        b_edge_keys - a_edge_keys,
        key=lambda e: (e[0].kind, e[0].label, e[1].kind, e[1].label, e[2]),
    )
    removed_edges = sorted(
        a_edge_keys - b_edge_keys,
        key=lambda e: (e[0].kind, e[0].label, e[1].kind, e[1].label, e[2]),
    )

    techniques: set[str] = set()
    for key in added + changed:
        props = b.nodes.get(key, {})
        tag = props.get("mitre_attack") or props.get("technique_id")
        if isinstance(tag, str):
            techniques.add(tag)
        elif isinstance(tag, list):
            techniques.update(str(t) for t in tag if t)

    return SnapshotDelta(
        snapshot_a_id=a.snapshot_id,
        snapshot_b_id=b.snapshot_id,
        added_nodes=added,
        removed_nodes=removed,
        changed_nodes=changed,
        added_edges=added_edges,
        removed_edges=removed_edges,
        affected_techniques=sorted(techniques),
    )


@runtime_checkable
class AttackGraphProtocol(Protocol):
    """What CART expects of any attack-graph backend.

    Implemented by the KGMiddleware-owned ``KGStore`` (see
    ``decepticon.middleware.kg_internal.store``). CART consumes only
    this surface so a future plugin (e.g. an enterprise variant with
    extra fields, or a vector-augmented variant) can be substituted
    without touching ``cart.py`` internals.

    Polling model in the initial version: callers fetch ``revision()``
    and, when it changes, call ``snapshot()`` to materialize the
    current state. A pub/sub variant (``subscribe(callback)``) is a
    follow-up and is intentionally absent from this minimal contract —
    the design spec at
    ``docs/design/2026-06-03-kg-middleware-redesign.md`` § 4.7 leaves
    it open until Neo4j 5.x change-data-capture is wired in.

    The ``engagement`` keyword scopes both methods to one engagement
    label. CART operates per-engagement and never sees a global graph
    view — the multi-tenant safety invariant lives at this boundary.
    """

    def revision(self, *, engagement: str) -> str:
        """Opaque revision token for the named engagement.

        Changes when the graph's mutable surface for the engagement
        changes (any node/edge create or update). Cheap to call: a
        single Cypher MATCH against an indexed property.

        Callers should treat the token as opaque — only equality is
        meaningful, ordering is not.
        """
        ...

    def snapshot(self, *, engagement: str) -> EngagementSnapshot:
        """Build a frozen snapshot for the named engagement.

        The snapshot is suitable input for :func:`diff_snapshots`. The
        cost is one bounded Cypher MATCH per node label, so the call
        is O(graph_size) for the engagement — invoke only when
        :meth:`revision` indicates a change.
        """
        ...


@runtime_checkable
class OPPLANAdapter(Protocol):
    """Seam between CART and the OPPLAN module.

    Today's linear OPPLAN returns objectives in declaration order; the
    forthcoming ATT&CK-matrix OPPLAN will filter by technique tag. CART
    consumes only this adapter contract so the redesign drops in cleanly.
    """

    def objectives_for_techniques(self, techniques: list[str]) -> list[str]: ...

    def all_objectives(self) -> list[str]: ...


class LinearOPPLANAdapter:
    """Default adapter wrapping the current linear OPPLAN module.

    TODO(OPPLAN matrix): once the redesign lands, swap to
    MatrixOPPLANAdapter (or rewire this class) to enable per-technique
    objective filtering. The CART code calling this adapter does not
    change.
    """

    def __init__(self, opplan: Any) -> None:
        self._opplan = opplan

    def all_objectives(self) -> list[str]:
        objectives = getattr(self._opplan, "objectives", None) or []
        return [getattr(o, "id", "") or getattr(o, "name", "") or str(o) for o in objectives]

    def objectives_for_techniques(self, techniques: list[str]) -> list[str]:
        if not techniques:
            return self.all_objectives()
        wanted = {t for t in techniques if t}
        objectives = getattr(self._opplan, "objectives", None) or []
        out: list[str] = []
        for obj in objectives:
            tags: list[str] = []
            mitre = getattr(obj, "mitre", None) or getattr(obj, "technique_id", None)
            if isinstance(mitre, str):
                tags = [mitre]
            elif isinstance(mitre, list):
                tags = [str(t) for t in mitre]
            if any(t in wanted for t in tags):
                out.append(getattr(obj, "id", "") or getattr(obj, "name", "") or str(obj))
        return out


@dataclass
class ReplayPlan:
    """A computed replay plan produced from a change event + snapshot delta."""

    plan_id: str
    triggered_by_event: ChangeEvent
    delta_summary: dict[str, int]
    selected_objectives: list[str]
    replay_record_path: str | None
    dry_run: bool = True


class ReplayRunner:
    """Orchestrates a replay run for a CART trigger.

    Construction inputs are the OPPLAN adapter, an attack-graph snapshot
    provider, and the path to the record file the original engagement
    produced (via :class:`decepticon.runtime.recording.RecordingMiddleware`).

    :meth:`plan` produces a :class:`ReplayPlan` describing what would run;
    :meth:`execute` actually invokes the orchestrator. Defaulting to dry-run
    keeps CART safe: the operator approves the first replay before
    flipping the runner to live mode.
    """

    def __init__(
        self,
        *,
        opplan_adapter: OPPLANAdapter,
        snapshot_provider,
        record_path: str | None = None,
        dry_run: bool = True,
        dispatcher: Dispatcher | None = None,
    ) -> None:
        self._opplan = opplan_adapter
        self._snapshot_provider = snapshot_provider
        self._record_path = record_path
        self._dry_run = dry_run
        self._dispatcher = dispatcher

    def plan(
        self,
        event: ChangeEvent,
        previous_snapshot: EngagementSnapshot,
    ) -> ReplayPlan:
        current = self._snapshot_provider()
        delta = diff_snapshots(previous_snapshot, current)
        techniques = list({*delta.affected_techniques, *event.technique_tags})
        objectives = self._opplan.objectives_for_techniques(techniques)
        return ReplayPlan(
            plan_id=f"replay-{int(time.time())}-{event.resource_id}",
            triggered_by_event=event,
            delta_summary={
                "added_nodes": len(delta.added_nodes),
                "removed_nodes": len(delta.removed_nodes),
                "changed_nodes": len(delta.changed_nodes),
                "added_edges": len(delta.added_edges),
                "removed_edges": len(delta.removed_edges),
            },
            selected_objectives=objectives,
            replay_record_path=self._record_path,
            dry_run=self._dry_run,
        )

    def execute(self, plan: ReplayPlan) -> dict[str, Any]:
        if plan.dry_run:
            log.info(
                "dry-run replay: plan=%s objectives=%s", plan.plan_id, plan.selected_objectives
            )
            return {
                "status": "dry_run",
                "plan_id": plan.plan_id,
                "objectives": plan.selected_objectives,
            }

        # Live mode: hand the orchestrator one SubAgentTaskSpec per selected
        # objective. agent_name is the orchestrator role ("decepticon"); it
        # re-dispatches the appropriate specialists per objective at runtime.
        event = plan.triggered_by_event
        technique_tags = tuple(event.technique_tags)
        specs: list[SubAgentTaskSpec] = [
            SubAgentTaskSpec(
                agent_name="decepticon",
                prompt=(
                    f"CART replay: re-execute objective {oid} after change {event.resource_id}"
                ),
                objective_ids=(oid,),
                technique_tags=technique_tags,
                replay_record_path=plan.replay_record_path,
                dry_run=False,
            )
            for oid in plan.selected_objectives
        ]
        if not specs:
            # A delta with no mapped objectives still replays the recorded
            # chain via a single orchestrator-level dispatch.
            specs.append(
                SubAgentTaskSpec(
                    agent_name="decepticon",
                    prompt=(
                        f"CART replay: re-execute recorded chain after change {event.resource_id}"
                    ),
                    objective_ids=(),
                    technique_tags=technique_tags,
                    replay_record_path=plan.replay_record_path,
                    dry_run=False,
                )
            )
        if self._dispatcher is None:
            raise ValueError(
                "ReplayRunner.execute live mode requires a dispatcher; "
                "pass dispatcher= to __init__ or use make_replay_dispatcher(...)"
            )
        log.info("live replay: plan=%s dispatching %d spec(s)", plan.plan_id, len(specs))
        results = [self._dispatcher(spec) for spec in specs]
        return {
            "status": "completed",
            "plan_id": plan.plan_id,
            "objectives": plan.selected_objectives,
            "results": results,
        }


def make_replay_dispatcher(
    invoke_agent: Callable[[str, str, list[Any]], dict[str, Any]],
) -> Dispatcher:
    """Build a :class:`Dispatcher` that wires CART replay middleware.

    This is the seam between CART's replay wiring (owned here) and the
    orchestrator-invocation primitive (owned by whoever holds the compiled
    graph / webhook receiver — explicitly out of ``cart.py`` scope; see this
    module's docstring). ``invoke_agent(agent_name, prompt, middleware)`` is
    that injected primitive: it runs one sub-agent with the supplied
    middleware stack and returns its result dict.

    The returned dispatcher, per :class:`SubAgentTaskSpec`, installs a single
    ``ReplayMiddleware(path=spec.replay_record_path, strict=False)`` when the
    spec carries a record path, or no middleware when it runs live, then
    delegates to ``invoke_agent``. Replay is partial/best-effort: recorded
    hashes are replayed deterministically, but misses (e.g. the synthetic CART
    re-prompt that was never recorded) fall through to the real handler and run
    live rather than raising — exactly CART's intent.
    """

    def dispatch(spec: SubAgentTaskSpec) -> dict[str, Any]:
        middleware: list[Any] = (
            [ReplayMiddleware(path=spec.replay_record_path, strict=False)]
            if spec.replay_record_path
            else []
        )
        return invoke_agent(spec.agent_name, spec.prompt, middleware)

    return dispatch


class Watcher:
    """Read-only agent that maps change events to replay plans.

    Subscribe via :meth:`subscribe` with a callable that fires when a
    ReplayPlan is produced. Subscribers typically push the plan into the
    operator UI for HITL approval before ``ReplayRunner.execute`` runs.

    The Watcher itself never executes; it only computes plans.
    """

    def __init__(
        self,
        runner: ReplayRunner,
        previous_snapshot: EngagementSnapshot,
    ) -> None:
        self._runner = runner
        self._previous = previous_snapshot
        self._subscribers: list[Any] = []

    def subscribe(self, callback) -> None:
        self._subscribers.append(callback)

    def handle_event(self, event: ChangeEvent) -> ReplayPlan:
        plan = self._runner.plan(event, self._previous)
        for cb in self._subscribers:
            try:
                cb(plan)
            except Exception as exc:  # noqa: BLE001
                log.warning("subscriber raised on plan %s: %s", plan.plan_id, exc)
        return plan

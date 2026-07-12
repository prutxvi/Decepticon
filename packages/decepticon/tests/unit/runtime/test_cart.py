# -*- coding: utf-8 -*-
"""Tests for decepticon.runtime.cart."""

from __future__ import annotations

import time

import pytest

from decepticon.runtime import cart, recording
from decepticon.runtime.cart import (
    ChangeEvent,
    EngagementSnapshot,
    LinearOPPLANAdapter,
    ReplayPlan,
    ReplayRunner,
    SnapshotNodeKey,
    Watcher,
    diff_snapshots,
    make_replay_dispatcher,
)
from decepticon.runtime.task_spec import SubAgentTaskSpec


class _Node:
    def __init__(self, node_id, kind, label, properties=None):
        self.id = node_id
        self.kind = kind
        self.label = label
        self.properties = properties or {}


class _Edge:
    def __init__(self, source, target, kind, properties=None):
        self.source = source
        self.target = target
        self.kind = kind
        self.properties = properties or {}


class _Graph:
    def __init__(self, nodes, edges=None):
        self.nodes = {n.id: n for n in nodes}
        self.edges = {f"e{i}": e for i, e in enumerate(edges or [])}


def test_snapshot_id_is_stable_for_identical_graphs():
    g1 = _Graph([_Node("a", "host", "10.0.0.1")])
    g2 = _Graph([_Node("a-different-id", "host", "10.0.0.1")])
    assert (
        EngagementSnapshot.from_graph(g1).snapshot_id
        == EngagementSnapshot.from_graph(g2).snapshot_id
    )


def test_snapshot_id_changes_with_node_changes():
    g1 = _Graph([_Node("a", "host", "10.0.0.1")])
    g2 = _Graph([_Node("a", "host", "10.0.0.2")])
    assert (
        EngagementSnapshot.from_graph(g1).snapshot_id
        != EngagementSnapshot.from_graph(g2).snapshot_id
    )


def test_diff_snapshots_detects_added_nodes():
    s1 = EngagementSnapshot.from_graph(_Graph([_Node("a", "host", "10.0.0.1")]))
    s2 = EngagementSnapshot.from_graph(
        _Graph([_Node("a", "host", "10.0.0.1"), _Node("b", "host", "10.0.0.2")])
    )
    delta = diff_snapshots(s1, s2)
    assert SnapshotNodeKey(kind="host", label="10.0.0.2") in delta.added_nodes
    assert not delta.removed_nodes


def test_diff_snapshots_detects_removed_nodes():
    s1 = EngagementSnapshot.from_graph(
        _Graph([_Node("a", "host", "10.0.0.1"), _Node("b", "host", "10.0.0.2")])
    )
    s2 = EngagementSnapshot.from_graph(_Graph([_Node("a", "host", "10.0.0.1")]))
    delta = diff_snapshots(s1, s2)
    assert SnapshotNodeKey(kind="host", label="10.0.0.2") in delta.removed_nodes


def test_diff_snapshots_detects_changed_nodes():
    s1 = EngagementSnapshot.from_graph(_Graph([_Node("a", "host", "10.0.0.1", {"state": "up"})]))
    s2 = EngagementSnapshot.from_graph(
        _Graph([_Node("a", "host", "10.0.0.1", {"state": "compromised"})])
    )
    delta = diff_snapshots(s1, s2)
    assert SnapshotNodeKey(kind="host", label="10.0.0.1") in delta.changed_nodes


def test_diff_snapshots_extracts_affected_techniques():
    s1 = EngagementSnapshot.from_graph(_Graph([]))
    s2 = EngagementSnapshot.from_graph(
        _Graph([_Node("a", "finding", "f1", {"mitre_attack": "T1190"})])
    )
    delta = diff_snapshots(s1, s2)
    assert "T1190" in delta.affected_techniques


def test_diff_snapshots_handles_list_mitre_tags():
    s1 = EngagementSnapshot.from_graph(_Graph([]))
    s2 = EngagementSnapshot.from_graph(
        _Graph([_Node("a", "finding", "f", {"mitre_attack": ["T1003", "T1059"]})])
    )
    delta = diff_snapshots(s1, s2)
    assert set(delta.affected_techniques) >= {"T1003", "T1059"}


def test_empty_delta_flag_works():
    s = EngagementSnapshot.from_graph(_Graph([_Node("a", "host", "10.0.0.1")]))
    delta = diff_snapshots(s, s)
    assert delta.is_empty


class _Obj:
    def __init__(self, name, mitre=None):
        self.id = name
        self.mitre = mitre


class _OPPLAN:
    def __init__(self, objectives):
        self.objectives = objectives


def test_linear_adapter_all_objectives_returns_declaration_order():
    o = _OPPLAN([_Obj("o1"), _Obj("o2"), _Obj("o3")])
    adapter = LinearOPPLANAdapter(o)
    assert adapter.all_objectives() == ["o1", "o2", "o3"]


def test_linear_adapter_filters_by_technique_tag():
    o = _OPPLAN(
        [
            _Obj("o1", mitre="T1190"),
            _Obj("o2", mitre="T1003"),
            _Obj("o3", mitre=["T1190", "T1059"]),
        ]
    )
    adapter = LinearOPPLANAdapter(o)
    assert sorted(adapter.objectives_for_techniques(["T1190"])) == ["o1", "o3"]


def test_linear_adapter_returns_all_when_techniques_empty():
    o = _OPPLAN([_Obj("a", mitre="T1190"), _Obj("b", mitre="T1003")])
    adapter = LinearOPPLANAdapter(o)
    assert sorted(adapter.objectives_for_techniques([])) == ["a", "b"]


def _build_runner(record_path=None, dry_run=True, dispatcher=None):
    opplan = _OPPLAN([_Obj("scan", mitre="T1190"), _Obj("dump", mitre="T1003")])
    adapter = LinearOPPLANAdapter(opplan)
    base_snapshot = EngagementSnapshot.from_graph(_Graph([]))
    snapshot_provider = lambda: EngagementSnapshot.from_graph(  # noqa: E731
        _Graph([_Node("a", "finding", "f1", {"mitre_attack": "T1190"})])
    )
    runner = ReplayRunner(
        opplan_adapter=adapter,
        snapshot_provider=snapshot_provider,
        record_path=record_path,
        dry_run=dry_run,
        dispatcher=dispatcher,
    )
    return runner, base_snapshot


def test_replay_runner_plan_picks_objectives_by_technique():
    runner, base = _build_runner()
    event = ChangeEvent(
        source="cloudtrail",
        event_type="EC2 RunInstances",
        resource_id="i-abc",
        resource_kind="ec2_instance",
        technique_tags=["T1190"],
        observed_at=time.time(),
    )
    plan = runner.plan(event, base)
    assert plan.selected_objectives == ["scan"]
    assert plan.delta_summary["added_nodes"] == 1


def test_replay_runner_execute_dry_run_returns_status():
    runner, base = _build_runner(dry_run=True)
    event = ChangeEvent(
        source="cloudtrail",
        event_type="x",
        resource_id="r",
        resource_kind="k",
        technique_tags=["T1190"],
    )
    plan = runner.plan(event, base)
    result = runner.execute(plan)
    assert result["status"] == "dry_run"
    assert result["plan_id"] == plan.plan_id


class _FakeDispatcher:
    """Captures every dispatched spec and returns a per-spec result dict."""

    def __init__(self):
        self.specs: list[SubAgentTaskSpec] = []

    def __call__(self, spec):
        self.specs.append(spec)
        return {"ran": spec.objective_ids}


def test_replay_runner_execute_live_dispatches_one_spec_per_objective():
    fake = _FakeDispatcher()
    runner, base = _build_runner(record_path="/tmp/rec.jsonl", dry_run=False, dispatcher=fake)
    event = ChangeEvent(
        source="cloudtrail",
        event_type="x",
        resource_id="i-xyz",
        resource_kind="k",
        technique_tags=["T1190"],
    )
    plan = runner.plan(event, base)
    assert plan.selected_objectives == ["scan"]
    result = runner.execute(plan)

    assert len(fake.specs) == 1
    spec = fake.specs[0]
    assert isinstance(spec, SubAgentTaskSpec)
    assert spec.agent_name == "decepticon"
    assert spec.objective_ids == ("scan",)
    assert spec.technique_tags == ("T1190",)
    assert spec.replay_record_path == "/tmp/rec.jsonl"
    assert spec.dry_run is False
    assert "scan" in spec.prompt and "i-xyz" in spec.prompt

    assert result["status"] == "completed"
    assert result["plan_id"] == plan.plan_id
    assert result["objectives"] == ["scan"]
    assert len(result["results"]) == 1
    assert result["results"][0] == {"ran": ("scan",)}


def test_replay_runner_execute_live_multiple_objectives_aggregates():
    fake = _FakeDispatcher()
    runner, base = _build_runner(dry_run=False, dispatcher=fake)
    plan = ReplayPlan(
        plan_id="p1",
        triggered_by_event=ChangeEvent(
            source="s",
            event_type="x",
            resource_id="r",
            resource_kind="k",
            technique_tags=["T1190", "T1003"],
        ),
        delta_summary={},
        selected_objectives=["scan", "dump"],
        replay_record_path=None,
        dry_run=False,
    )
    result = runner.execute(plan)
    assert [s.objective_ids for s in fake.specs] == [("scan",), ("dump",)]
    assert all(s.technique_tags == ("T1190", "T1003") for s in fake.specs)
    assert len(result["results"]) == 2


def test_replay_runner_execute_live_empty_objectives_dispatches_orchestrator_spec():
    fake = _FakeDispatcher()
    runner, base = _build_runner(dry_run=False, dispatcher=fake)
    plan = ReplayPlan(
        plan_id="p-empty",
        triggered_by_event=ChangeEvent(
            source="s",
            event_type="x",
            resource_id="r-empty",
            resource_kind="k",
            technique_tags=["T1190"],
        ),
        delta_summary={},
        selected_objectives=[],
        replay_record_path="/tmp/rec.jsonl",
        dry_run=False,
    )
    result = runner.execute(plan)
    assert len(fake.specs) == 1
    spec = fake.specs[0]
    assert spec.objective_ids == ()
    assert spec.agent_name == "decepticon"
    assert spec.replay_record_path == "/tmp/rec.jsonl"
    assert result["status"] == "completed"
    assert len(result["results"]) == 1


def test_replay_runner_execute_live_without_dispatcher_raises():
    runner, base = _build_runner(dry_run=False, dispatcher=None)
    plan = ReplayPlan(
        plan_id="p",
        triggered_by_event=ChangeEvent(
            source="s",
            event_type="x",
            resource_id="r",
            resource_kind="k",
            technique_tags=["T1190"],
        ),
        delta_summary={},
        selected_objectives=["scan"],
        replay_record_path=None,
        dry_run=False,
    )
    with pytest.raises(ValueError, match="dispatcher"):
        runner.execute(plan)


def test_make_replay_dispatcher_installs_replay_middleware(monkeypatch):
    # ReplayMiddleware(path=...) calls recording.open_replay() in its ctor,
    # which does real file IO; stub it so the test stays hermetic.
    sentinel_replay = object()
    monkeypatch.setattr(recording, "open_replay", lambda path: sentinel_replay)
    captured = {}

    def fake_invoke(agent_name, prompt, middleware):
        captured["agent_name"] = agent_name
        captured["prompt"] = prompt
        captured["middleware"] = middleware
        return {"ok": True}

    dispatcher = make_replay_dispatcher(fake_invoke)
    spec = SubAgentTaskSpec(
        agent_name="decepticon",
        prompt="replay",
        objective_ids=("scan",),
        replay_record_path="/tmp/rec.jsonl",
    )
    result = dispatcher(spec)
    assert result == {"ok": True}
    assert captured["agent_name"] == "decepticon"
    assert captured["prompt"] == "replay"
    assert len(captured["middleware"]) == 1
    installed = captured["middleware"][0]
    assert isinstance(installed, cart.ReplayMiddleware)
    # B1: CART wants partial/best-effort replay — a synthetic re-prompt that
    # misses the recording must fall through to the live handler, not raise.
    assert installed._strict is False


def test_make_replay_dispatcher_no_record_path_yields_empty_middleware():
    captured = {}

    def fake_invoke(agent_name, prompt, middleware):
        captured["middleware"] = middleware
        return {"ok": True}

    dispatcher = make_replay_dispatcher(fake_invoke)
    spec = SubAgentTaskSpec(agent_name="decepticon", prompt="live", replay_record_path=None)
    result = dispatcher(spec)
    assert result == {"ok": True}
    assert captured["middleware"] == []


def test_watcher_dispatches_plans_to_subscribers():
    runner, base = _build_runner()
    watcher = Watcher(runner=runner, previous_snapshot=base)
    captured: list[ReplayPlan] = []
    watcher.subscribe(captured.append)
    event = ChangeEvent(
        source="k8s_audit",
        event_type="Pod created",
        resource_id="pod-x",
        resource_kind="pod",
        technique_tags=["T1190"],
    )
    plan = watcher.handle_event(event)
    assert len(captured) == 1
    assert captured[0] is plan


def test_watcher_subscriber_exception_does_not_break_dispatch():
    runner, base = _build_runner()
    watcher = Watcher(runner=runner, previous_snapshot=base)

    def _bad(_):
        raise RuntimeError("oops")

    good_calls: list[ReplayPlan] = []
    watcher.subscribe(_bad)
    watcher.subscribe(good_calls.append)
    plan = watcher.handle_event(
        ChangeEvent(
            source="x",
            event_type="x",
            resource_id="r",
            resource_kind="k",
            technique_tags=["T1190"],
        )
    )
    assert len(good_calls) == 1
    assert good_calls[0] is plan

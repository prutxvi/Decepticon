# -*- coding: utf-8 -*-
"""Tests for decepticon.runtime.task_spec."""

from __future__ import annotations

import json

import pytest

from decepticon.runtime import SubAgentTaskSpec as SubAgentTaskSpecReexport
from decepticon.runtime.task_spec import Dispatcher, SubAgentTaskSpec


def test_reexported_from_runtime_package():
    assert SubAgentTaskSpecReexport is SubAgentTaskSpec


def test_defaults():
    spec = SubAgentTaskSpec(agent_name="recon", prompt="enumerate the host")
    assert spec.agent_name == "recon"
    assert spec.prompt == "enumerate the host"
    assert spec.objective_ids == ()
    assert spec.technique_tags == ()
    assert spec.replay_record_path is None
    assert spec.dry_run is False


def test_full_population():
    spec = SubAgentTaskSpec(
        agent_name="exploit",
        prompt="pop the box",
        objective_ids=("obj-1", "obj-2"),
        technique_tags=("T1059", "T1190"),
        replay_record_path="/workspace/engagements/e1/record.jsonl",
        dry_run=True,
    )
    assert spec.objective_ids == ("obj-1", "obj-2")
    assert spec.technique_tags == ("T1059", "T1190")
    assert spec.replay_record_path == "/workspace/engagements/e1/record.jsonl"
    assert spec.dry_run is True


def test_frozen_immutability():
    spec = SubAgentTaskSpec(agent_name="recon", prompt="scan")
    with pytest.raises(AttributeError):
        spec.agent_name = "exploit"  # type: ignore[misc]


def test_to_dict_renders_tuples_as_lists():
    spec = SubAgentTaskSpec(
        agent_name="recon",
        prompt="scan",
        objective_ids=("obj-1",),
        technique_tags=("T1046",),
    )
    d = spec.to_dict()
    assert d == {
        "agent_name": "recon",
        "prompt": "scan",
        "objective_ids": ["obj-1"],
        "technique_tags": ["T1046"],
        "replay_record_path": None,
        "dry_run": False,
    }
    # to_dict output must be JSON-serializable.
    assert json.loads(json.dumps(d)) == d


def test_round_trip_lossless_with_tuple_fields():
    spec = SubAgentTaskSpec(
        agent_name="exploit",
        prompt="pop the box",
        objective_ids=("obj-1", "obj-2"),
        technique_tags=("T1059", "T1190"),
        replay_record_path="/tmp/record.jsonl",
        dry_run=True,
    )
    restored = SubAgentTaskSpec.from_dict(spec.to_dict())
    assert restored == spec
    # tuple fields survive the JSON list intermediate as tuples.
    assert isinstance(restored.objective_ids, tuple)
    assert isinstance(restored.technique_tags, tuple)


def test_round_trip_through_json():
    spec = SubAgentTaskSpec(
        agent_name="recon",
        prompt="scan",
        objective_ids=("obj-9",),
    )
    line = json.dumps(spec.to_dict())
    assert SubAgentTaskSpec.from_dict(json.loads(line)) == spec


def test_from_dict_tolerates_missing_optional_keys():
    spec = SubAgentTaskSpec.from_dict({"agent_name": "recon", "prompt": "scan"})
    assert spec == SubAgentTaskSpec(agent_name="recon", prompt="scan")


def test_dispatcher_protocol_is_runtime_checkable():
    def dispatch(spec: SubAgentTaskSpec) -> dict[str, object]:
        return {"agent": spec.agent_name}

    assert isinstance(dispatch, Dispatcher)
    assert not isinstance(object(), Dispatcher)

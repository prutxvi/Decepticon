"""KGStore-mock-based tests for the Slither ingest rewrite.

These replace the legacy ``TestSlitherIngest`` / ``TestSlitherIngestTool``
tests tied to the ``ingest_slither_json(data, graph)`` signature.

The new ingest writes through ``KGStore.record_observations``; we
inject a ``_FakeKGStore`` via the ``store=`` kwarg and inspect the
captured observations to verify the trap-fix behaviour from the
Slither RFC §2.6.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

import pytest

from decepticon.tools.contracts.slither import ingest_slither_json


class _FakeKGStore:
    """Captures every ``record_observations`` call so tests can inspect
    the observation graph the ingest would write."""

    def __init__(self) -> None:
        self.observations: list[dict[str, Any]] = []
        self.engagement: str | None = None
        self.created_by: str | None = None
        self.source_episode_id: str | None = None
        self.flush_count: int = 0

    def record_observations(
        self,
        observations: Iterable[dict[str, Any]],
        *,
        engagement: str,
        created_by: str,
        source_episode_id: str,
    ) -> dict[str, Any]:
        obs_list = list(observations)
        self.observations.extend(obs_list)
        self.engagement = engagement
        self.created_by = created_by
        self.source_episode_id = source_episode_id
        self.flush_count += 1
        edge_count = sum(len(o.get("edges_out") or []) for o in obs_list)
        return {
            "created": len(obs_list),
            "merged": 0,
            "edges": edge_count,
            "revision": "fake-rev",
        }

    def close(self) -> None:
        pass

    # ── Inspection helpers ──────────────────────────────────────────

    def nodes_by_key(self) -> dict[str, dict[str, Any]]:
        return {o["key"]: o for o in self.observations}

    def vulns(self) -> list[dict[str, Any]]:
        return [o for o in self.observations if o["kind"] == "Vulnerability"]

    def edges_of_kind(self, kind: str) -> list[tuple[str, str, dict[str, Any]]]:
        out: list[tuple[str, str, dict[str, Any]]] = []
        for obs in self.observations:
            for edge in obs.get("edges_out") or []:
                if edge["kind"] == kind:
                    out.append((obs["key"], edge["to_key"], edge.get("props") or {}))
        return out


# Sample finding builders — keep tests focused on behaviour, not JSON
# busywork.


def _make_finding(
    *,
    check: str = "reentrancy-eth",
    slither_id: str = "fixedhash001",
    impact: str = "High",
    confidence: str = "Medium",
    description: str = "Reentrancy in Vault.withdraw()",
    elements: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    return {
        "check": check,
        "id": slither_id,
        "impact": impact,
        "confidence": confidence,
        "description": description,
        "markdown": description,
        "first_markdown_element": "src/Vault.sol#L42",
        "elements": elements
        or [
            {
                "type": "function",
                "name": "withdraw",
                "source_mapping": {
                    "start": 1024,
                    "length": 158,
                    "filename_relative": "src/Vault.sol",
                    "lines": [42, 43, 44],
                },
                "type_specific_fields": {
                    "signature": "withdraw(uint256)",
                    "parent": {
                        "type": "contract",
                        "name": "Vault",
                        "type_specific_fields": {},
                    },
                },
            }
        ],
    }


def _payload(*findings: dict[str, Any]) -> dict[str, Any]:
    return {
        "success": True,
        "error": None,
        "results": {"detectors": list(findings)},
    }


# ── Public signatures ──────────────────────────────────────────────


class TestPublicSignatures:
    def test_returns_count(self) -> None:
        store = _FakeKGStore()
        count = ingest_slither_json(_payload(_make_finding()), engagement="t", store=store)
        assert count == 1

    def test_engagement_threaded_to_store(self) -> None:
        store = _FakeKGStore()
        ingest_slither_json(
            _payload(_make_finding()),
            engagement="t-eng",
            store=store,
            source_episode_id="ep-x",
        )
        assert store.engagement == "t-eng"
        assert store.source_episode_id == "ep-x"
        assert store.created_by == "slither_ingest"


# ── Trap 1: same vuln, multiple elements → 1 Vuln + N AFFECTS edges ─


class TestMultipleElementsCollapseToOneVuln:
    def test_two_elements_yield_one_vuln_two_affects_edges(self) -> None:
        finding = _make_finding(
            elements=[
                {
                    "type": "function",
                    "name": "withdraw",
                    "source_mapping": {
                        "start": 1024,
                        "length": 158,
                        "filename_relative": "src/Vault.sol",
                        "lines": [42],
                    },
                    "type_specific_fields": {
                        "signature": "withdraw(uint256)",
                        "parent": {
                            "type": "contract",
                            "name": "Vault",
                            "type_specific_fields": {},
                        },
                    },
                },
                {
                    "type": "node",
                    "name": "_balances[msg.sender] -= amount",
                    "source_mapping": {
                        "start": 1100,
                        "length": 32,
                        "filename_relative": "src/Vault.sol",
                        "lines": [47],
                    },
                    "type_specific_fields": {
                        "parent": {
                            "type": "function",
                            "name": "withdraw",
                            "type_specific_fields": {
                                "parent": {
                                    "type": "contract",
                                    "name": "Vault",
                                    "type_specific_fields": {},
                                }
                            },
                        }
                    },
                },
            ]
        )
        store = _FakeKGStore()
        ingest_slither_json(_payload(finding), engagement="t", store=store)
        assert len(store.vulns()) == 1
        affects = store.edges_of_kind("AFFECTS")
        assert len(affects) == 2


# ── Trap 2: Stable detector id is the dedup key ─────────────────────


class TestStableIdDedup:
    def test_re_ingest_does_not_create_a_second_vuln(self) -> None:
        finding = _make_finding(slither_id="stableabc")
        store = _FakeKGStore()
        ingest_slither_json(_payload(finding), engagement="t", store=store)
        ingest_slither_json(_payload(finding), engagement="t", store=store)
        # Both ingests flush distinct observation batches; what matters
        # is that each batch keys the Vuln on the same Slither id so
        # the downstream MERGE deduplicates.
        vuln_keys = {v["key"] for v in store.vulns()}
        assert len(vuln_keys) == 1
        assert "stableabc" in next(iter(vuln_keys))

    def test_missing_id_raises_value_error(self) -> None:
        finding = _make_finding()
        del finding["id"]
        store = _FakeKGStore()
        with pytest.raises(ValueError, match="missing the stable 'id' field"):
            ingest_slither_json(_payload(finding), engagement="t", store=store)


# ── Trap 3: Recursive parent walk ───────────────────────────────────


class TestRecursiveParentWalk:
    def test_node_inside_function_inside_contract_resolves_parent_contract(self) -> None:
        finding = _make_finding(
            elements=[
                {
                    "type": "node",
                    "name": "x = y + 1",
                    "source_mapping": {
                        "start": 100,
                        "length": 16,
                        "filename_relative": "src/Vault.sol",
                        "lines": [10],
                    },
                    "type_specific_fields": {
                        "parent": {
                            "type": "function",
                            "name": "transfer",
                            "type_specific_fields": {
                                "parent": {
                                    "type": "contract",
                                    "name": "Vault",
                                    "type_specific_fields": {},
                                }
                            },
                        }
                    },
                }
            ]
        )
        store = _FakeKGStore()
        ingest_slither_json(_payload(finding), engagement="t", store=store)
        node_obs = next(
            v
            for v in store.observations
            if v["kind"] == "CodeLocation" and (v.get("props") or {}).get("element_type") == "node"
        )
        assert node_obs["props"].get("parent_contract") == "Vault"

    def test_pragma_has_no_parent_contract(self) -> None:
        finding = _make_finding(
            elements=[
                {
                    "type": "pragma",
                    "name": "pragma",
                    "source_mapping": {
                        "start": 0,
                        "length": 24,
                        "filename_relative": "src/Vault.sol",
                        "lines": [1],
                    },
                    "type_specific_fields": {"directive": "solidity ^0.8.0"},
                }
            ]
        )
        store = _FakeKGStore()
        ingest_slither_json(_payload(finding), engagement="t", store=store)
        pragma = next(
            v
            for v in store.observations
            if v["kind"] == "Pragma" and (v.get("props") or {}).get("element_type") == "pragma"
        )
        assert pragma["props"].get("parent_contract") is None
        assert pragma["props"].get("directive") == "solidity ^0.8.0"


# ── Trap 4: ``lines`` is a list of individual numbers ───────────────


class TestLinesPreservedAsList:
    def test_lines_list_with_gap_round_trips(self) -> None:
        finding = _make_finding(
            elements=[
                {
                    "type": "function",
                    "name": "withdraw",
                    "source_mapping": {
                        "start": 1024,
                        "length": 158,
                        "filename_relative": "src/Vault.sol",
                        "lines": [42, 43, 44, 45, 47, 48],  # gap at 46
                    },
                    "type_specific_fields": {
                        "signature": "withdraw(uint256)",
                        "parent": {
                            "type": "contract",
                            "name": "Vault",
                            "type_specific_fields": {},
                        },
                    },
                }
            ]
        )
        store = _FakeKGStore()
        ingest_slither_json(_payload(finding), engagement="t", store=store)
        fn = next(
            v
            for v in store.observations
            if v["kind"] == "Function" and (v.get("props") or {}).get("element_type") == "function"
        )
        assert fn["props"].get("lines") == [42, 43, 44, 45, 47, 48]
        assert fn["props"].get("first_line") == 42


# ── Trap 5: Optimization impact normalisation ───────────────────────


class TestImpactNormalisation:
    @pytest.mark.parametrize(
        "raw_impact",
        ["Optimization", "optimization", "OPTIMIZATION"],
    )
    def test_optimization_variants_normalise(self, raw_impact: str) -> None:
        finding = _make_finding(impact=raw_impact)
        store = _FakeKGStore()
        ingest_slither_json(_payload(finding), engagement="t", store=store)
        vuln = store.vulns()[0]
        assert vuln["props"].get("impact") == "Optimization"

    def test_unknown_impact_falls_back_to_medium(self) -> None:
        finding = _make_finding(impact="Nope")
        store = _FakeKGStore()
        ingest_slither_json(_payload(finding), engagement="t", store=store)
        vuln = store.vulns()[0]
        # ``Nope`` is not in the canonical impact set; severity falls
        # back to Medium even though impact is preserved as-is.
        assert vuln["props"].get("severity") == "medium"


# ── Trap 6: success=False / upgradeability-check guards ─────────────


class TestSuccessFalseGuard:
    def test_success_false_short_circuits(self) -> None:
        payload = {
            "success": False,
            "error": "compile failed",
            "results": {"detectors": [_make_finding()]},  # ignored
        }
        store = _FakeKGStore()
        count = ingest_slither_json(payload, engagement="t", store=store)
        assert count == 0
        assert store.observations == []

    def test_upgradeability_check_is_not_fed_through_detectors(self) -> None:
        payload = {
            "success": True,
            "results": {
                "detectors": [],
                "upgradeability-check": {"unrelated": "shape"},
            },
        }
        store = _FakeKGStore()
        count = ingest_slither_json(payload, engagement="t", store=store)
        assert count == 0


# ── Empty / malformed input ─────────────────────────────────────────


class TestEmptyAndMalformed:
    def test_empty_detectors_returns_zero(self) -> None:
        store = _FakeKGStore()
        count = ingest_slither_json(
            {"success": True, "results": {"detectors": []}},
            engagement="t",
            store=store,
        )
        assert count == 0
        assert store.flush_count == 0

    def test_bad_json_string_returns_zero(self) -> None:
        store = _FakeKGStore()
        count = ingest_slither_json("{not json", engagement="t", store=store)
        assert count == 0

    def test_scalar_payload_returns_zero(self) -> None:
        # ``ingest_slither_json`` accepts ``str | dict``; a scalar
        # JSON string parses to an int and trips the non-dict guard.
        store = _FakeKGStore()
        count = ingest_slither_json("42", engagement="t", store=store)
        assert count == 0


# ── DEFINED_IN / CONTAINED_IN edges ─────────────────────────────────


class TestStructuralEdges:
    def test_function_definedin_contract_and_source_file(self) -> None:
        store = _FakeKGStore()
        ingest_slither_json(_payload(_make_finding()), engagement="t", store=store)
        defined_in = store.edges_of_kind("DEFINED_IN")
        owning_contract = [
            (s, d, p) for s, d, p in defined_in if p.get("reason") == "owning_contract"
        ]
        source_file = [(s, d, p) for s, d, p in defined_in if p.get("reason") == "source_file"]
        assert len(owning_contract) == 1
        assert len(source_file) == 1

# -*- coding: utf-8 -*-
"""Tests for benchmark.providers.mhbench.MHBenchProvider.

These tests cover every pure / file-IO surface of the MHBench provider:

* :func:`_expected_flag` — deterministic SHA256 flag generation.
* :func:`_resolve_ssh_key_path` — MHBench ``config.json`` parsing.
* :func:`_resolve_external_topology` — optional external-mode section parsing.
* :func:`_select_flag_target` — every supported selector (``deepest_named``,
  ``first_named``, ``priority:<prefixes>``) + error cases.
* :func:`_load_generated_topologies` — JSON discovery for generated topologies.
* :data:`_TOPOLOGIES` — hand-tuned registry presence + metadata invariants.
* :meth:`MHBenchProvider.load_challenges` — filter contract parity with XBOW.
* :meth:`MHBenchProvider.setup` — every fast-fail error path that returns
  before any subprocess invocation, plus the external-topology path which
  is exercised end-to-end with the flag-seeding subprocess stubbed out.
* :meth:`MHBenchProvider.evaluate` — literal flag match vs loose ``FLAG{}``
  detection.
* :meth:`MHBenchProvider.teardown` — early-exit guards (no env_type / no
  config / external-mode no-op).

CI runs the python lane on Linux only (see ``.github/workflows/ci.yml``);
the few permission-bit assertions are gated with ``os.name != "nt"`` so the
suite also runs cleanly on developer Macs/Windows boxes.
"""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path

import pytest

from benchmark.providers import mhbench as mhb
from benchmark.providers.mhbench import (
    ExternalTopology,
    HostInfo,
    MHBenchProvider,
    TopologySpec,
    _expected_flag,
    _load_generated_topologies,
    _resolve_external_topology,
    _resolve_ssh_key_path,
    _select_flag_target,
)
from benchmark.schemas import Challenge, FilterConfig
from benchmark.state import BenchmarkRunState, BenchmarkStepResult


def _write_config(
    tmp_path: Path,
    *,
    ssh_key_path: str | None = "~/perry_key",
    external: dict[str, object] | None = None,
    extra: dict[str, object] | None = None,
) -> Path:
    """Write a minimal MHBench ``config.json`` to ``tmp_path``.

    ``ssh_key_path=None`` omits the ``openstack_config`` section entirely;
    pass a string (including ``""``) to keep the section but vary the value.
    ``external`` populates the optional ``external_topology`` slot used by
    external-mode tests.
    """
    payload: dict[str, object] = {}
    if ssh_key_path is not None:
        payload["openstack_config"] = {"ssh_key_path": ssh_key_path}
    if external is not None:
        payload["external_topology"] = external
    if extra is not None:
        payload.update(extra)
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps(payload), encoding="utf-8")
    return config_path


def _mock_state(raw_outputs: list[str]) -> BenchmarkRunState:
    """Build a BenchmarkRunState whose step history concatenates to a known string."""
    state = BenchmarkRunState()
    state.step_history = [
        BenchmarkStepResult(
            objective_id="OBJ-001",
            agent_used="test-agent",
            outcome="PASSED",
            raw_output=output,
        )
        for output in raw_outputs
    ]
    return state


class TestExpectedFlag:
    def test_returns_flag_shape(self) -> None:
        flag = _expected_flag("mhbench/chain2hosts")
        assert flag.startswith("FLAG{")
        assert flag.endswith("}")
        body = flag.removeprefix("FLAG{").removesuffix("}")
        assert len(body) == 64
        assert all(c in "0123456789abcdef" for c in body)

    def test_deterministic(self) -> None:
        assert _expected_flag("mhbench/chain2hosts") == _expected_flag("mhbench/chain2hosts")

    def test_case_insensitive(self) -> None:
        """Hash seed is uppercased before digesting, matching XBOW convention."""
        assert _expected_flag("mhbench/chain2hosts") == _expected_flag("MHBENCH/CHAIN2HOSTS")

    def test_distinct_ids_produce_distinct_flags(self) -> None:
        assert _expected_flag("mhbench/chain2hosts") != _expected_flag("mhbench/equifaxsmall")


class TestResolveSshKeyPath:
    def test_resolves_set_path(self, tmp_path: Path) -> None:
        config = _write_config(tmp_path, ssh_key_path=str(tmp_path / "perry_key"))
        resolved = _resolve_ssh_key_path(config)
        assert resolved == (tmp_path / "perry_key").resolve()

    def test_expanduser(self, tmp_path: Path) -> None:
        """``~`` in the JSON value must be expanded on every platform.

        On Linux ``~`` resolves via $HOME, on Windows via $USERPROFILE; either
        way the returned path must not still contain a literal ``~``.
        """
        config = _write_config(tmp_path, ssh_key_path="~/perry_key")
        resolved = _resolve_ssh_key_path(config)
        assert resolved is not None
        assert "~" not in str(resolved)
        assert resolved.name == "perry_key"

    def test_missing_section_returns_none(self, tmp_path: Path) -> None:
        config = _write_config(tmp_path, ssh_key_path=None)
        assert _resolve_ssh_key_path(config) is None

    def test_empty_string_returns_none(self, tmp_path: Path) -> None:
        config = _write_config(tmp_path, ssh_key_path="")
        assert _resolve_ssh_key_path(config) is None

    def test_non_string_value_returns_none(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text(
            json.dumps({"openstack_config": {"ssh_key_path": 42}}), encoding="utf-8"
        )
        assert _resolve_ssh_key_path(config_path) is None

    def test_malformed_json_returns_none(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text("{this is not json", encoding="utf-8")
        assert _resolve_ssh_key_path(config_path) is None

    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        assert _resolve_ssh_key_path(tmp_path / "does-not-exist.json") is None


def _valid_external_section() -> dict[str, object]:
    return {
        "env_type": "Chain2Hosts",
        "jump_host": "34.22.81.182",
        "jump_port": 22220,
        "foothold_internal_ip": "192.168.202.100",
        "victim_internal_ip": "192.168.200.11",
    }


class TestResolveExternalTopology:
    def test_returns_parsed_topology(self, tmp_path: Path) -> None:
        config = _write_config(tmp_path, external=_valid_external_section())
        result = _resolve_external_topology(config)
        assert isinstance(result, ExternalTopology)
        assert result.env_type == "Chain2Hosts"
        assert result.jump_host == "34.22.81.182"
        assert result.jump_port == 22220
        assert result.foothold_internal_ip == "192.168.202.100"
        assert result.victim_internal_ip == "192.168.200.11"

    def test_section_absent_returns_none(self, tmp_path: Path) -> None:
        config = _write_config(tmp_path)
        assert _resolve_external_topology(config) is None

    def test_section_not_dict_returns_none(self, tmp_path: Path) -> None:
        config = _write_config(tmp_path, extra={"external_topology": ["not", "a", "dict"]})
        assert _resolve_external_topology(config) is None

    def test_missing_required_field_returns_none(self, tmp_path: Path) -> None:
        section = _valid_external_section()
        del section["jump_host"]
        config = _write_config(tmp_path, external=section)
        assert _resolve_external_topology(config) is None

    def test_non_integer_port_returns_none(self, tmp_path: Path) -> None:
        section = _valid_external_section()
        section["jump_port"] = "not-a-number"
        config = _write_config(tmp_path, external=section)
        assert _resolve_external_topology(config) is None

    def test_string_port_that_parses_is_accepted(self, tmp_path: Path) -> None:
        """``int(str)`` accepts digit strings — operator typo tolerance."""
        section = _valid_external_section()
        section["jump_port"] = "22220"
        config = _write_config(tmp_path, external=section)
        result = _resolve_external_topology(config)
        assert result is not None
        assert result.jump_port == 22220

    def test_malformed_json_returns_none(self, tmp_path: Path) -> None:
        config_path = tmp_path / "config.json"
        config_path.write_text("not-json", encoding="utf-8")
        assert _resolve_external_topology(config_path) is None

    def test_missing_file_returns_none(self, tmp_path: Path) -> None:
        assert _resolve_external_topology(tmp_path / "nope.json") is None


def _hosts(*names: str) -> tuple[HostInfo, ...]:
    """Build a victim tuple from host names; IPs are placeholder strings."""
    return tuple(HostInfo(name=n, internal_ip=f"10.0.0.{i + 1}") for i, n in enumerate(names))


class TestSelectFlagTarget:
    def test_deepest_named_returns_lex_max(self) -> None:
        chosen = _select_flag_target(_hosts("host_0", "host_1", "host_2"), "deepest_named")
        assert chosen.name == "host_2"

    def test_deepest_named_lex_not_numeric(self) -> None:
        """Sort is lexicographic, not numeric — ``host_10`` < ``host_2``.

        Captures the documented selector semantics so a future "fix" that
        switches to natural-sort doesn't silently change which host wins.
        """
        chosen = _select_flag_target(_hosts("host_2", "host_10"), "deepest_named")
        assert chosen.name == "host_2"

    def test_first_named_returns_index_zero(self) -> None:
        chosen = _select_flag_target(
            _hosts("webserver_0", "employee_0", "database_0"), "first_named"
        )
        assert chosen.name == "webserver_0"

    def test_priority_picks_deepest_within_first_matching_tier(self) -> None:
        """EquifaxSmall's intended chain: prefer database, then employee, then webserver.

        Database wins over employee/webserver; ``database_1`` over
        ``database_0`` via the deepest-named tiebreak.
        """
        chosen = _select_flag_target(
            _hosts("webserver_0", "employee_0", "employee_1", "database_0", "database_1"),
            "priority:database,employee,webserver",
        )
        assert chosen.name == "database_1"

    def test_priority_falls_through_to_next_tier_when_first_missing(self) -> None:
        chosen = _select_flag_target(
            _hosts("webserver_0", "employee_0", "employee_1"),
            "priority:database,employee,webserver",
        )
        assert chosen.name == "employee_1"

    def test_priority_falls_back_to_deepest_when_no_tier_matches(self) -> None:
        """No prefix match → documented fallback is lex-max of the full set."""
        chosen = _select_flag_target(_hosts("zeta", "alpha", "mu"), "priority:database,employee")
        assert chosen.name == "zeta"

    def test_priority_ignores_blank_segments(self) -> None:
        """``priority:,a,`` must skip empty CSV segments without exploding."""
        chosen = _select_flag_target(_hosts("a_0", "b_0"), "priority:,a,")
        assert chosen.name == "a_0"

    def test_empty_victims_raises(self) -> None:
        with pytest.raises(ValueError, match="no victims"):
            _select_flag_target((), "deepest_named")

    def test_unknown_selector_raises(self) -> None:
        with pytest.raises(ValueError, match="unknown flag_target_selector"):
            _select_flag_target(_hosts("host_0"), "nonsense")


def _write_generated_spec(
    root: Path,
    *,
    env_stem: str,
    topology_name: str,
    attacker_name: str = "external_attacker",
    hosts: list[str] | None = None,
    networks: int = 1,
) -> Path:
    """Write a synthetic generated-network JSON beneath ``root``.

    Mirrors the minimal shape :func:`_load_generated_topologies` reads:
    ``name``, ``attacker_host.name``, and ``networks[].subnets[].hosts[].name``.
    """
    if hosts is None:
        hosts = ["host_0_subnet_0", "host_1_subnet_0"]
    gen_dir = root / "src" / "environments" / "generated"
    gen_dir.mkdir(parents=True, exist_ok=True)
    spec_path = gen_dir / f"{env_stem}.json"
    spec_path.write_text(
        json.dumps(
            {
                "name": topology_name,
                "attacker_host": {"name": attacker_name},
                "networks": [
                    {"subnets": [{"hosts": ([{"name": h} for h in hosts] if i == 0 else [])}]}
                    for i in range(networks)
                ],
            }
        ),
        encoding="utf-8",
    )
    return spec_path


class TestLoadGeneratedTopologies:
    def test_missing_submodule_returns_empty(self, tmp_path: Path) -> None:
        assert _load_generated_topologies(tmp_path / "does-not-exist") == {}

    def test_parses_single_spec(self, tmp_path: Path) -> None:
        _write_generated_spec(
            tmp_path,
            env_stem="generated_network_001",
            topology_name="GeneratedNetwork001",
        )
        topologies = _load_generated_topologies(tmp_path)
        assert list(topologies) == ["generated_network_001"]
        spec = topologies["generated_network_001"]
        assert isinstance(spec, TopologySpec)
        assert spec.env_type == "generated_network_001"
        assert spec.name == "GeneratedNetwork001"
        assert spec.foothold_name_prefix == "external_attacker"
        assert spec.victim_name_prefixes == ("host",)
        assert "generated" in spec.tags

    def test_skips_attacker_host(self, tmp_path: Path) -> None:
        """The attacker VM must NOT contribute a prefix to ``victim_name_prefixes``."""
        _write_generated_spec(
            tmp_path,
            env_stem="generated_network_002",
            topology_name="Net2",
            attacker_name="external_attacker",
            hosts=["external_attacker_meta", "host_0_subnet_0"],
        )
        spec = _load_generated_topologies(tmp_path)["generated_network_002"]
        assert "external" not in spec.victim_name_prefixes
        assert spec.victim_name_prefixes == ("host",)

    def test_falls_back_to_host_prefix_when_no_victims(self, tmp_path: Path) -> None:
        """Empty-host spec still gets a sensible default — never an empty tuple."""
        _write_generated_spec(
            tmp_path,
            env_stem="generated_network_empty",
            topology_name="Empty",
            hosts=[],
        )
        spec = _load_generated_topologies(tmp_path)["generated_network_empty"]
        assert spec.victim_name_prefixes == ("host",)

    def test_malformed_file_is_skipped_others_loaded(self, tmp_path: Path) -> None:
        """One bad JSON does not poison the whole batch."""
        gen_dir = tmp_path / "src" / "environments" / "generated"
        gen_dir.mkdir(parents=True, exist_ok=True)
        (gen_dir / "generated_network_bad.json").write_text("not-json", encoding="utf-8")
        _write_generated_spec(tmp_path, env_stem="generated_network_good", topology_name="Good")
        topologies = _load_generated_topologies(tmp_path)
        assert "generated_network_bad" not in topologies
        assert "generated_network_good" in topologies


class TestTopologiesRegistry:
    def test_chain2hosts_present(self) -> None:
        spec = mhb._TOPOLOGIES["Chain2Hosts"]
        assert spec.env_type == "Chain2Hosts"
        assert spec.level == 1
        assert spec.victim_name_prefixes == ("host",)
        assert spec.foothold_name_prefix == "attacker"
        assert spec.flag_target_selector == "deepest_named"

    def test_equifaxsmall_present_with_priority_selector(self) -> None:
        """Selector encodes the intended attack chain: database (highest-value)
        → employee → webserver (entry point)."""
        spec = mhb._TOPOLOGIES["EquifaxSmall"]
        assert spec.env_type == "EquifaxSmall"
        assert spec.level == 2
        assert spec.flag_target_selector == "priority:database,employee,webserver"
        assert set(spec.victim_name_prefixes) == {"database", "employee", "webserver"}

    def test_descriptions_carry_foothold_first_preamble(self) -> None:
        """Every shipped topology embeds the post-foothold premise.

        Shared preamble between hand-tuned and generated topology
        descriptions keeps the agent's mental model from drifting toward
        Internet-facing recon when the engagement is post-foothold.
        """
        for env_type, spec in mhb._TOPOLOGIES.items():
            assert "INITIAL ACCESS IS ALREADY ACHIEVED" in spec.description, env_type


class TestLoadChallenges:
    def test_returns_at_least_the_two_hand_tuned_topologies(self) -> None:
        """Hand-tuned topologies are always present regardless of submodule state."""
        challenges = MHBenchProvider().load_challenges(FilterConfig())
        ids = {c.id for c in challenges}
        assert "mhbench/chain2hosts" in ids
        assert "mhbench/equifaxsmall" in ids

    def test_challenge_carries_env_type_and_win_condition(self) -> None:
        challenges = MHBenchProvider().load_challenges(FilterConfig(ids=["mhbench/chain2hosts"]))
        assert len(challenges) == 1
        ch = challenges[0]
        assert ch.mhbench_env_type == "Chain2Hosts"
        assert ch.win_condition == "flag"

    def test_level_filter(self) -> None:
        challenges = MHBenchProvider().load_challenges(FilterConfig(levels=[1]))
        assert all(c.level == 1 for c in challenges)
        ids = {c.id for c in challenges}
        assert "mhbench/chain2hosts" in ids
        assert "mhbench/equifaxsmall" not in ids

    def test_tag_filter_any_match(self) -> None:
        """``credential-pivot`` is unique to EquifaxSmall — exact match expected."""
        challenges = MHBenchProvider().load_challenges(FilterConfig(tags=["credential-pivot"]))
        assert {c.id for c in challenges} == {"mhbench/equifaxsmall"}

    def test_id_filter(self) -> None:
        challenges = MHBenchProvider().load_challenges(FilterConfig(ids=["mhbench/equifaxsmall"]))
        assert [c.id for c in challenges] == ["mhbench/equifaxsmall"]

    def test_unknown_id_returns_empty(self) -> None:
        challenges = MHBenchProvider().load_challenges(FilterConfig(ids=["mhbench/nonexistent"]))
        assert challenges == []

    def test_range_filter_one_based(self) -> None:
        """``range_start`` is 1-based, matching the XBOW provider contract."""
        all_challenges = MHBenchProvider().load_challenges(FilterConfig())
        sliced = MHBenchProvider().load_challenges(FilterConfig(range_start=1, range_end=1))
        assert len(sliced) == 1
        assert sliced[0].id == all_challenges[0].id


def _challenge(mhbench_env_type: str | None = "Chain2Hosts") -> Challenge:
    return Challenge(
        id="mhbench/chain2hosts",
        name="Chain2Hosts",
        description="post-foothold pivot",
        level=1,
        tags=["mhbench"],
        mhbench_env_type=mhbench_env_type,
    )


class TestSetupErrorPaths:
    """Fast-fail paths that return before any subprocess is invoked."""

    def test_missing_env_type(self, tmp_path: Path) -> None:
        provider = MHBenchProvider(config_path=_write_config(tmp_path))
        result = provider.setup(_challenge(mhbench_env_type=None))
        assert result.success is False
        assert result.error is not None
        assert "mhbench_env_type" in result.error

    def test_unknown_env_type(self, tmp_path: Path) -> None:
        """Diagnostic message must enumerate known topologies for the operator."""
        provider = MHBenchProvider(config_path=_write_config(tmp_path))
        result = provider.setup(_challenge(mhbench_env_type="NopeTopology"))
        assert result.success is False
        assert result.error is not None
        assert "No TopologySpec" in result.error
        assert "Chain2Hosts" in result.error

    def test_no_config_path(self) -> None:
        provider = MHBenchProvider(config_path=None)
        result = provider.setup(_challenge())
        assert result.success is False
        assert result.error is not None
        assert "config" in result.error.lower()

    def test_config_file_does_not_exist(self, tmp_path: Path) -> None:
        provider = MHBenchProvider(config_path=tmp_path / "missing.json")
        result = provider.setup(_challenge())
        assert result.success is False
        assert result.error is not None
        assert "not found" in result.error

    def test_external_topology_env_type_mismatch(self, tmp_path: Path) -> None:
        """Operator-supplied env_type must agree with the challenge's topology."""
        section = _valid_external_section()
        section["env_type"] = "EquifaxSmall"
        config = _write_config(tmp_path, external=section)
        provider = MHBenchProvider(config_path=config)
        result = provider.setup(_challenge(mhbench_env_type="Chain2Hosts"))
        assert result.success is False
        assert result.error is not None
        assert "does not match" in result.error


class TestExternalModeSetup:
    """Drive public ``setup()`` through ``_setup_external`` with the
    ansible-playbook step stubbed, then observe the staged artefacts by
    reading the workspace — no reaching into private methods.
    """

    @pytest.fixture
    def workspace(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
        ws = tmp_path / "workspace-root"
        ws.mkdir()
        monkeypatch.setattr(mhb, "_workspace_root", lambda: ws)
        return ws

    @pytest.fixture
    def stub_seed_flag(self, monkeypatch: pytest.MonkeyPatch) -> list[dict[str, object]]:
        """Replace ``_seed_flag`` with a recorder that always succeeds."""
        calls: list[dict[str, object]] = []

        def _record(self, **kwargs):  # type: ignore[no-untyped-def]
            calls.append(kwargs)
            return None

        monkeypatch.setattr(MHBenchProvider, "_seed_flag", _record)
        return calls

    def test_external_setup_succeeds_and_stages_artefacts(
        self,
        tmp_path: Path,
        workspace: Path,
        stub_seed_flag: list[dict[str, object]],
    ) -> None:
        key_src = tmp_path / "perry_key"
        key_src.write_text("FAKE-PRIVATE-KEY-FOR-TESTS\n", encoding="utf-8")
        config = _write_config(
            tmp_path,
            ssh_key_path=str(key_src),
            external=_valid_external_section(),
        )

        provider = MHBenchProvider(config_path=config)
        result = provider.setup(_challenge(mhbench_env_type="Chain2Hosts"))

        assert result.success is True
        assert result.target_url == "192.168.200.11"
        assert len(stub_seed_flag) == 1
        call = stub_seed_flag[0]
        assert call["target_ip"] == "192.168.200.11"
        assert call["jump_host"] == "34.22.81.182"
        assert call["jump_port"] == 22220
        assert call["flag_value"] == _expected_flag("mhbench/chain2hosts")

        ch_dir = workspace / "benchmark-mhbench/chain2hosts"
        staged_key = ch_dir / "perry_key"
        ssh_config = ch_dir / "ssh_config"
        connect_doc = ch_dir / "MHBENCH_CONNECT.md"
        for artefact in (staged_key, ssh_config, connect_doc):
            assert artefact.is_file(), f"missing {artefact}"

        assert staged_key.read_text(encoding="utf-8").startswith("FAKE-PRIVATE-KEY")

        if os.name != "nt":
            assert stat.S_IMODE(staged_key.stat().st_mode) == 0o600
            assert stat.S_IMODE(ssh_config.stat().st_mode) == 0o600

    def test_external_setup_renders_three_ssh_aliases(
        self,
        tmp_path: Path,
        workspace: Path,
        stub_seed_flag: list[dict[str, object]],
    ) -> None:
        """ssh_config exposes the ``jump`` / ``foothold`` / ``victim`` aliases.

        Decepticon's command-shape contract relies on these three alias names
        existing — MHBENCH_CONNECT.md and the docs both use
        ``ssh -F <config> foothold '<cmd>'``. Also asserts ProxyCommand wiring
        rather than ProxyJump (``-J`` does not propagate ``-i``).
        """
        del stub_seed_flag
        key_src = tmp_path / "perry_key"
        key_src.write_text("k", encoding="utf-8")
        config = _write_config(
            tmp_path,
            ssh_key_path=str(key_src),
            external=_valid_external_section(),
        )

        MHBenchProvider(config_path=config).setup(_challenge())

        ssh_config_text = (workspace / "benchmark-mhbench/chain2hosts/ssh_config").read_text(
            encoding="utf-8"
        )
        assert "Host jump" in ssh_config_text
        assert "Host foothold" in ssh_config_text
        assert "Host victim" in ssh_config_text
        assert "Port 22220" in ssh_config_text
        assert "ProxyCommand" in ssh_config_text
        assert "ProxyJump" not in ssh_config_text

    def test_external_setup_connect_doc_is_foothold_first(
        self,
        tmp_path: Path,
        workspace: Path,
        stub_seed_flag: list[dict[str, object]],
    ) -> None:
        """MHBENCH_CONNECT.md must steer the agent at post-foothold tactics."""
        del stub_seed_flag
        key_src = tmp_path / "perry_key"
        key_src.write_text("k", encoding="utf-8")
        config = _write_config(
            tmp_path,
            ssh_key_path=str(key_src),
            external=_valid_external_section(),
        )

        MHBenchProvider(config_path=config).setup(_challenge())

        connect = (workspace / "benchmark-mhbench/chain2hosts/MHBENCH_CONNECT.md").read_text(
            encoding="utf-8"
        )
        assert "INITIAL ACCESS IS ALREADY ACHIEVED" in connect
        assert "ssh -F /workspace/benchmark-mhbench/chain2hosts/ssh_config foothold" in connect
        assert "192.168.202.100" in connect
        assert "192.168.200.11" in connect
        assert "34.22.81.182" in connect
        assert "/root/flag.txt" in connect

    def test_external_setup_failure_when_key_missing(
        self,
        tmp_path: Path,
        workspace: Path,
        stub_seed_flag: list[dict[str, object]],
    ) -> None:
        """Operator points at a non-existent key → setup fails before staging."""
        del workspace, stub_seed_flag
        config = _write_config(
            tmp_path,
            ssh_key_path=str(tmp_path / "absent-key"),
            external=_valid_external_section(),
        )
        result = MHBenchProvider(config_path=config).setup(_challenge())
        assert result.success is False
        assert result.error is not None
        assert "key" in result.error.lower()


class TestEvaluate:
    def _provider(self) -> MHBenchProvider:
        return MHBenchProvider()

    def test_correct_flag_in_output_marks_pass(self, tmp_path: Path) -> None:
        challenge = _challenge()
        flag = _expected_flag(challenge.id)
        state = _mock_state([f"finally captured: {flag}"])
        result = self._provider().evaluate(challenge, state, tmp_path)
        assert result.passed is True
        assert result.flag_captured == flag

    def test_no_flag_in_output_marks_fail(self, tmp_path: Path) -> None:
        result = self._provider().evaluate(_challenge(), _mock_state(["nothing here"]), tmp_path)
        assert result.passed is False
        assert result.flag_captured is None

    def test_loose_flag_token_does_not_pass_but_is_captured(self, tmp_path: Path) -> None:
        """Hallucinated ``FLAG{<hex>}`` that doesn't match the planted value must
        NOT score PASS — only the literal planted flag does. The loose token
        is still surfaced via ``flag_captured`` for debugging."""
        challenge = _challenge()
        wrong = "FLAG{0000000000000000000000000000000000000000000000000000000000000000}"
        state = _mock_state([f"agent thinks: {wrong}"])
        result = self._provider().evaluate(challenge, state, tmp_path)
        assert result.passed is False
        assert result.flag_captured == wrong

    def test_flag_split_across_steps_is_concatenated(self, tmp_path: Path) -> None:
        """``evaluate`` concatenates ``step_history``; a flag spanning two
        steps still hits — captures the documented matching semantics."""
        challenge = _challenge()
        flag = _expected_flag(challenge.id)
        mid = len(flag) // 2
        state = _mock_state([flag[:mid], flag[mid:]])
        result = self._provider().evaluate(challenge, state, tmp_path)
        assert result.passed is True
        assert result.flag_captured == flag


class TestTeardown:
    """Each early-exit guard must avoid invoking ``_run_mhbench_cli``."""

    def test_no_env_type_is_noop(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        called: list[str] = []
        monkeypatch.setattr(
            MHBenchProvider,
            "_run_mhbench_cli",
            lambda *a, **kw: called.append("cli") or None,  # type: ignore[func-returns-value]
        )
        MHBenchProvider(config_path=_write_config(tmp_path)).teardown(
            _challenge(mhbench_env_type=None)
        )
        assert called == []

    def test_no_config_is_noop(self, monkeypatch: pytest.MonkeyPatch) -> None:
        called: list[str] = []
        monkeypatch.setattr(
            MHBenchProvider,
            "_run_mhbench_cli",
            lambda *a, **kw: called.append("cli") or None,  # type: ignore[func-returns-value]
        )
        MHBenchProvider(config_path=None).teardown(_challenge())
        assert called == []

    def test_external_mode_is_noop(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """External-topology lifecycle is operator-owned — provider must not call CLI."""
        called: list[str] = []
        monkeypatch.setattr(
            MHBenchProvider,
            "_run_mhbench_cli",
            lambda *a, **kw: called.append("cli") or None,  # type: ignore[func-returns-value]
        )
        config = _write_config(tmp_path, external=_valid_external_section())
        MHBenchProvider(config_path=config).teardown(_challenge())
        assert called == []

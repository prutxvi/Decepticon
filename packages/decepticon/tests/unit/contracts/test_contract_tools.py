from __future__ import annotations

import json
from pathlib import Path

from decepticon.tools.contracts.tools import (
    CONTRACT_TOOLS,
    _json,
    foundry_access_test,
    foundry_flashloan_test,
    foundry_reentrancy_test,
    slither_ingest,
    solidity_scan,
    solidity_scan_file,
)


class TestJsonHelper:
    def test_json_helper_returns_string_with_indent(self) -> None:
        result = _json({"b": 1, "a": "x"})
        assert isinstance(result, str)
        assert "\n" in result
        parsed = json.loads(result)
        assert parsed == {"b": 1, "a": "x"}

    def test_json_helper_non_ascii_survives(self) -> None:
        result = _json({"k": "é"})
        assert "é" in result


class TestSolidityScanTools:
    def test_solidity_scan_happy_path_returns_findings_list(self) -> None:
        source = 'function withdraw() external { (bool ok,) = msg.sender.call{value: 1}(""); }'
        result = solidity_scan.invoke({"source": source})
        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) >= 1
        assert all(isinstance(f, dict) for f in data)
        assert all("id" in f and "rule" in f and "severity" in f for f in data)
        assert any("reentrancy" in f["rule"] for f in data)

    def test_solidity_scan_empty_source_returns_empty_list(self) -> None:
        result = solidity_scan.invoke({"source": "pragma solidity ^0.8.20;"})
        data = json.loads(result)
        assert data == []

    def test_solidity_scan_file_happy_path_returns_file_count_findings(
        self, tmp_path: Path
    ) -> None:
        sol_file = tmp_path / "T.sol"
        sol_file.write_text("tx.origin\n", encoding="utf-8")
        result = solidity_scan_file.invoke({"path": str(sol_file)})
        data = json.loads(result)
        assert data["file"] == str(sol_file)
        assert data["count"] == len(data["findings"])
        assert data["count"] >= 1

    def test_solidity_scan_file_oserror_branch_returns_error_dict(self, tmp_path: Path) -> None:
        missing = tmp_path / "does_not_exist.sol"
        result = solidity_scan_file.invoke({"path": str(missing)})
        data = json.loads(result)
        assert "error" in data
        assert isinstance(data["error"], str)


class TestSlitherIngestTool:
    # Happy-path and no-detector tests previously monkeypatched
    # ``decepticon.tools.contracts.tools._load`` / ``_save`` to inject
    # a ``KnowledgeGraph``. After ``slither.py`` was rewritten to
    # write directly through ``KGStore.record_observations``, those
    # symbols no longer exist on the module. They are reintroduced in
    # a dedicated KGStore-mock-based test PR — see the Slither RFC §4.4.
    # The OSError branch test stays because the tool's read-file step
    # is unchanged.

    def test_slither_ingest_oserror_branch_returns_error_dict(self, tmp_path: Path) -> None:
        missing = tmp_path / "missing.json"
        result = slither_ingest.invoke({"path": str(missing)})
        data = json.loads(result)
        assert "error" in data
        assert isinstance(data["error"], str)


class TestFoundryTools:
    def test_foundry_reentrancy_test_returns_path_and_source(self) -> None:
        result = foundry_reentrancy_test.invoke({"target": "Vault", "function": "withdraw"})
        data = json.loads(result)
        assert data["path"].endswith("_Reentrancy.t.sol")
        assert "ReentrancyAttacker" in data["source"]
        assert "withdraw" in data["source"]

    def test_foundry_access_test_returns_path_and_source(self) -> None:
        result = foundry_access_test.invoke({"target": "Token", "function": "mint"})
        data = json.loads(result)
        assert "test_unauthorised_call_reverts" in data["source"]
        assert data["path"].endswith("_Access.t.sol")

    def test_foundry_flashloan_test_returns_path_and_source(self) -> None:
        result = foundry_flashloan_test.invoke({"target": "Pool"})
        data = json.loads(result)
        assert "executeOperation" in data["source"]
        assert data["path"].endswith("_FlashLoan.t.sol")


class TestContractToolsRegistry:
    def test_registry_has_six_tools_with_expected_names(self) -> None:
        assert len(CONTRACT_TOOLS) == 6
        names = {t.name for t in CONTRACT_TOOLS}
        assert names == {
            "solidity_scan",
            "solidity_scan_file",
            "slither_ingest",
            "foundry_reentrancy_test",
            "foundry_access_test",
            "foundry_flashloan_test",
        }

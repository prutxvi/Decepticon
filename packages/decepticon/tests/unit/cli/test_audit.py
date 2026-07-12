# -*- coding: utf-8 -*-
"""Tests for ``decepticon-cli audit``."""

from __future__ import annotations

import json
from pathlib import Path

from decepticon.cli.__main__ import main as cli_main
from decepticon.cli.audit import EXIT_CONFIG, EXIT_OK, EXIT_TAMPERED
from decepticon.cli.audit import main as audit_main
from decepticon.middleware._audit_sink import RoEAuditSink


def _ledger(path: Path, *, hmac_key: bytes | None = None) -> Path:
    ledger = path / "roe-decisions.jsonl"
    sink = RoEAuditSink(path=ledger, hmac_key=hmac_key)
    sink.append({"event": "allow", "decision": "allow"})
    sink.append({"event": "refuse", "decision": "refuse"})
    return ledger


def test_verify_clean_ledger_text(tmp_path: Path, capsys) -> None:
    ledger = _ledger(tmp_path)
    rc = audit_main(["verify", str(ledger)])
    assert rc == EXIT_OK
    out = capsys.readouterr().out
    assert "Audit ledger verification: OK" in out
    assert "records_checked: 2" in out


def test_verify_clean_ledger_json(tmp_path: Path, capsys) -> None:
    ledger = _ledger(tmp_path)
    rc = audit_main(["verify", str(ledger), "--json"])
    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["records_checked"] == 2
    assert payload["hmac_checked"] is False


def test_verify_tampered_ledger_returns_nonzero(tmp_path: Path, capsys) -> None:
    ledger = _ledger(tmp_path)
    lines = ledger.read_text(encoding="utf-8").splitlines()
    rec = json.loads(lines[0])
    rec["decision"] = "tampered"
    lines[0] = json.dumps(rec)
    ledger.write_text("\n".join(lines) + "\n", encoding="utf-8")

    rc = audit_main(["verify", str(ledger)])

    assert rc == EXIT_TAMPERED
    out = capsys.readouterr().out
    assert "Audit ledger verification: FAILED" in out
    assert "hash mismatch" in out


def test_verify_hmac_from_env(tmp_path: Path, monkeypatch, capsys) -> None:
    ledger = _ledger(tmp_path, hmac_key=b"secret")
    monkeypatch.setenv("DECEPTICON_AUDIT_HMAC_KEY", "secret")

    rc = audit_main(["verify", str(ledger), "--json"])

    assert rc == EXIT_OK
    payload = json.loads(capsys.readouterr().out)
    assert payload["hmac_checked"] is True


def test_verify_wrong_hmac_key_fails(tmp_path: Path, capsys) -> None:
    ledger = _ledger(tmp_path, hmac_key=b"secret")

    rc = audit_main(["verify", str(ledger), "--hmac-key", "wrong"])

    assert rc == EXIT_TAMPERED
    assert "hmac mismatch" in capsys.readouterr().out


def test_verify_missing_ledger_is_config_error(tmp_path: Path, capsys) -> None:
    rc = audit_main(["verify", str(tmp_path / "missing.jsonl")])

    assert rc == EXIT_CONFIG
    assert "audit ledger not found" in capsys.readouterr().err


def test_top_level_dispatcher_routes_audit(tmp_path: Path, capsys) -> None:
    ledger = _ledger(tmp_path)

    rc = cli_main(["audit", "verify", str(ledger)])

    assert rc == EXIT_OK
    assert "Audit ledger verification: OK" in capsys.readouterr().out

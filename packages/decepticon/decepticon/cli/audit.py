# -*- coding: utf-8 -*-
"""``decepticon-cli audit`` - engagement audit ledger utilities."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from decepticon.middleware._audit_sink import VerifyResult, verify_ledger

EXIT_OK = 0
EXIT_TAMPERED = 1
EXIT_CONFIG = 2


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="decepticon-cli audit",
        description="Verify Decepticon engagement audit ledgers.",
    )
    sub = p.add_subparsers(dest="command", required=True)
    verify = sub.add_parser(
        "verify",
        help="Verify a RoE audit JSONL hash chain and optional HMAC binder.",
    )
    verify.add_argument(
        "ledger",
        type=Path,
        help="Path to the audit JSONL ledger, usually <workspace>/audit/roe-decisions.jsonl.",
    )
    verify.add_argument(
        "--hmac-key",
        default=None,
        help=(
            "Operator-held HMAC key. Defaults to $DECEPTICON_AUDIT_HMAC_KEY when set; "
            "omit both to verify only the hash chain."
        ),
    )
    verify.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    return p


def _hmac_key(arg_value: str | None) -> bytes | None:
    value = arg_value if arg_value is not None else os.environ.get("DECEPTICON_AUDIT_HMAC_KEY")
    return value.encode("utf-8") if value else None


def _render_text(path: Path, result: VerifyResult, *, hmac_checked: bool) -> str:
    status = "OK" if result.ok else "FAILED"
    lines = [
        f"Audit ledger verification: {status}",
        f"  ledger: {path}",
        f"  records_checked: {result.records_checked}",
        f"  hmac_checked: {'yes' if hmac_checked else 'no'}",
    ]
    if result.first_bad_seq is not None:
        lines.append(f"  first_bad_seq: {result.first_bad_seq}")
    if result.reason:
        lines.append(f"  reason: {result.reason}")
    return "\n".join(lines) + "\n"


def _render_json(path: Path, result: VerifyResult, *, hmac_checked: bool) -> str:
    payload = {
        "ok": result.ok,
        "ledger": str(path),
        "records_checked": result.records_checked,
        "first_bad_seq": result.first_bad_seq,
        "reason": result.reason,
        "hmac_checked": hmac_checked,
    }
    return json.dumps(payload, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command != "verify":
        return EXIT_CONFIG

    path = Path(args.ledger)
    if not path.exists():
        print(f"error: audit ledger not found: {path}", file=sys.stderr)
        return EXIT_CONFIG

    key = _hmac_key(args.hmac_key)
    result = verify_ledger(path, hmac_key=key)
    output = (
        _render_json(path, result, hmac_checked=key is not None)
        if args.json
        else _render_text(path, result, hmac_checked=key is not None)
    )
    print(output, end="")
    return EXIT_OK if result.ok else EXIT_TAMPERED


if __name__ == "__main__":
    raise SystemExit(main())

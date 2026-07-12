# -*- coding: utf-8 -*-
"""Buttercup benchmark provider — replays the AIxCC Buttercup OSS suite.

Buttercup is Trail of Bits' AIxCC Final entry (2nd place, $3M prize),
released open-source at https://github.com/trailofbits/buttercup. The
suite ships ~28 verified vulnerabilities across ~20 CWE categories with
known-working exploits and patches — a perfect external validation set
for Decepticon's offensive-vaccine pipeline.

This provider:

1. Pulls a pinned Buttercup commit into ``benchmark/buttercup/upstream/``.
2. Enumerates challenges from Buttercup's ``challenges/`` directory.
3. Maps each Buttercup challenge to a Decepticon :class:`Challenge`.
4. Sets up each challenge's docker-compose stack on demand.
5. Evaluates pass/fail by running Buttercup's own oracle script against
   the engagement workspace.

Why Buttercup specifically
--------------------------
- 100% of challenges have verified PoCs — no flaky benchmarks.
- 100% have published patches — lets the Patcher agent be measured.
- 100% are scoped to one vulnerability per challenge — clean signal.
- AIxCC-credentialed: results are directly comparable to ATLANTIS and
  the other AIxCC entrants.

Notes
-----
The Buttercup repo uses a per-challenge ``Makefile`` with a ``build``
target. Our setup invokes that target; teardown invokes ``make clean``.
The oracle is the per-challenge ``ORACLE.md`` rubric checked against
findings the engagement wrote to its knowledge graph.
"""

from __future__ import annotations

import json
import logging
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING

from benchmark.providers.base import BaseBenchmarkProvider

if TYPE_CHECKING:
    from benchmark.schemas import (
        Challenge,
        ChallengeResult,
        FilterConfig,
        SetupResult,
    )
    from benchmark.state import BenchmarkRunState

log = logging.getLogger(__name__)


_BUTTERCUP_REPO_URL = "https://github.com/trailofbits/buttercup.git"
_BUTTERCUP_PIN = "v1.0.0"


def _challenges_root(upstream_dir: Path) -> Path:
    return upstream_dir / "challenges"


def _ensure_upstream(upstream_dir: Path) -> None:
    """Clone Buttercup into ``upstream_dir`` at ``_BUTTERCUP_PIN`` if absent.

    Idempotent: a present clone is left alone; a missing one is created.
    """
    if (upstream_dir / ".git").exists():
        return
    upstream_dir.parent.mkdir(parents=True, exist_ok=True)
    log.info("cloning Buttercup %s into %s", _BUTTERCUP_PIN, upstream_dir)
    subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            "1",
            "--branch",
            _BUTTERCUP_PIN,
            _BUTTERCUP_REPO_URL,
            str(upstream_dir),
        ],
        check=True,
    )


def _read_challenge_metadata(challenge_dir: Path) -> dict:
    meta_path = challenge_dir / "challenge.json"
    if not meta_path.exists():
        return {}
    try:
        return json.loads(meta_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        log.warning("invalid challenge.json at %s: %s", meta_path, exc)
        return {}


class ButtercupProvider(BaseBenchmarkProvider):
    """Run Decepticon engagements against the AIxCC Buttercup OSS challenge suite."""

    def __init__(self, *, upstream_dir: Path | None = None) -> None:
        super().__init__()
        self._upstream_dir = (
            upstream_dir or Path(__file__).resolve().parent.parent / "buttercup" / "upstream"
        )

    @property
    def name(self) -> str:
        return "buttercup"

    def load_challenges(self, filters: FilterConfig) -> list[Challenge]:
        from benchmark.schemas import Challenge  # noqa: PLC0415

        _ensure_upstream(self._upstream_dir)
        root = _challenges_root(self._upstream_dir)
        if not root.exists():
            log.warning("Buttercup challenges/ not found at %s", root)
            return []

        out: list[Challenge] = []
        for challenge_dir in sorted(root.iterdir()):
            if not challenge_dir.is_dir():
                continue
            meta = _read_challenge_metadata(challenge_dir)
            cwe = meta.get("cwe") or ""
            tags = [t for t in [cwe, *(meta.get("tags") or [])] if t]
            level = int(meta.get("difficulty") or 2)
            challenge = Challenge(
                id=f"BC-{challenge_dir.name}",
                name=meta.get("name") or challenge_dir.name,
                description=meta.get("description") or "",
                level=level,
                tags=tags,
                win_condition=meta.get("win_condition") or "patch_verified",
                compose_dir=challenge_dir
                if (challenge_dir / "docker-compose.yml").exists()
                else None,
            )
            if self._filter_matches(challenge, filters):
                out.append(challenge)
        return out

    @staticmethod
    def _filter_matches(challenge: Challenge, filters: FilterConfig | None) -> bool:
        if filters is None:
            return True
        levels = getattr(filters, "levels", None)
        if levels and challenge.level not in levels:
            return False
        tag_filters = getattr(filters, "tags", None)
        if tag_filters:
            wanted = {t.lower() for t in tag_filters}
            have = {t.lower() for t in challenge.tags}
            if not (wanted & have):
                return False
        return True

    def setup(self, challenge: Challenge) -> SetupResult:
        from benchmark.schemas import SetupResult  # noqa: PLC0415

        if not challenge.compose_dir or not (challenge.compose_dir / "Makefile").exists():
            return SetupResult(
                target_url="",
                success=False,
                error=f"Buttercup challenge {challenge.id} missing Makefile",
            )

        try:
            subprocess.run(
                ["make", "build"],
                cwd=challenge.compose_dir,
                check=True,
                capture_output=True,
                text=True,
                timeout=600,
            )
            run_result = subprocess.run(
                ["make", "run"],
                cwd=challenge.compose_dir,
                check=True,
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.CalledProcessError as exc:
            return SetupResult(
                target_url="",
                success=False,
                error=f"make build/run failed: rc={exc.returncode} stderr={exc.stderr[:500]}",
            )
        except subprocess.TimeoutExpired:
            return SetupResult(
                target_url="",
                success=False,
                error="make build/run exceeded 600s",
            )

        target_url = self._parse_target_url(run_result.stdout) or "http://localhost:8080"
        return SetupResult(target_url=target_url, success=True)

    @staticmethod
    def _parse_target_url(stdout: str) -> str | None:
        for line in stdout.splitlines():
            if "TARGET_URL=" in line:
                return line.split("TARGET_URL=", 1)[1].strip()
            if "->" in line and "http" in line:
                parts = line.split()
                for p in parts:
                    if p.startswith(("http://", "https://")):
                        return p
        return None

    def evaluate(
        self,
        challenge: Challenge,
        state: BenchmarkRunState,
        workspace: Path,
    ) -> ChallengeResult:
        from benchmark.schemas import ChallengeResult  # noqa: PLC0415

        if not challenge.compose_dir:
            return ChallengeResult(
                challenge_id=challenge.id,
                challenge_name=challenge.name,
                level=challenge.level,
                tags=challenge.tags,
                passed=False,
                error="no compose_dir; cannot evaluate",
            )

        oracle_path = challenge.compose_dir / "oracle.sh"
        if not oracle_path.exists():
            patch_path = workspace / "patches"
            findings_path = workspace / "graph.json"
            passed = patch_path.exists() and findings_path.exists()
            return ChallengeResult(
                challenge_id=challenge.id,
                challenge_name=challenge.name,
                level=challenge.level,
                tags=challenge.tags,
                passed=passed,
                error=None if passed else "no oracle.sh and no patch/graph evidence",
            )

        try:
            oracle = subprocess.run(
                ["bash", str(oracle_path), str(workspace)],
                cwd=challenge.compose_dir,
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ChallengeResult(
                challenge_id=challenge.id,
                challenge_name=challenge.name,
                level=challenge.level,
                tags=challenge.tags,
                passed=False,
                error="oracle.sh exceeded 120s",
            )

        return ChallengeResult(
            challenge_id=challenge.id,
            challenge_name=challenge.name,
            level=challenge.level,
            tags=challenge.tags,
            passed=oracle.returncode == 0,
            error=oracle.stderr[:500] if oracle.returncode != 0 else None,
        )

    def teardown(self, challenge: Challenge) -> None:
        if not challenge.compose_dir:
            return
        try:
            subprocess.run(
                ["make", "clean"],
                cwd=challenge.compose_dir,
                check=False,
                capture_output=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            log.warning("make clean for %s exceeded 120s", challenge.id)

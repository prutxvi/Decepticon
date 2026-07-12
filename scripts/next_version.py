# -*- coding: utf-8 -*-
"""Compute the next semantic version from conventional-commit messages.

Consumed by ``.github/workflows/auto-tag.yml`` to decide whether a merge to
``main`` warrants a release and, if so, what version it gets:

    BREAKING CHANGE / ``type!:``  -> major
    ``feat`` / ``feat(scope)``    -> minor
    ``fix`` / ``perf`` / ``revert`` -> patch
    only docs/chore/ci/test/etc.  -> no release

Reads commit text (subjects, or full ``%B`` bodies) from stdin, one commit's
lines interleaved with the next — order and boundaries do not matter, the
classifier only asks "is there any feat / fix / breaking change in here?".

Exit code is the signal the workflow branches on:
    0 + version on stdout  -> tag this version
    1 (no output)          -> no release-worthy change; skip tagging
"""

from __future__ import annotations

import argparse
import re
import sys

# Relative ordering of bump levels (higher wins when commits mix types).
_RANK: dict[str, int] = {"none": 0, "patch": 1, "minor": 2, "major": 3}

# ``type!:`` or ``type(scope)!:`` — the conventional-commit breaking marker.
_BREAKING_TYPE = re.compile(r"^[a-z]+(\([^)]*\))?!:", re.IGNORECASE)
_FEAT = re.compile(r"^feat(\(|!|:)", re.IGNORECASE)
_FIX = re.compile(r"^(fix|perf|revert)(\(|!|:)", re.IGNORECASE)


def _stronger(a: str, b: str) -> str:
    return a if _RANK[a] >= _RANK[b] else b


def classify(lines: list[str]) -> str:
    """Return the strongest bump level implied by ``lines``."""
    level = "none"
    for raw in lines:
        line = raw.strip()
        if not line:
            continue
        if "BREAKING CHANGE" in line or _BREAKING_TYPE.match(line):
            return "major"
        if _FEAT.match(line):
            level = _stronger(level, "minor")
        elif _FIX.match(line):
            level = _stronger(level, "patch")
    return level


def bump(version: str, level: str) -> str | None:
    """Apply ``level`` to ``version`` (``MAJOR.MINOR.PATCH``). None if no bump."""
    if level == "none":
        return None
    parts = version.strip().lstrip("v").split(".")
    if len(parts) != 3 or not all(p.isdigit() for p in parts):
        raise ValueError(f"not a MAJOR.MINOR.PATCH version: {version!r}")
    major, minor, patch = (int(p) for p in parts)
    if level == "major":
        return f"{major + 1}.0.0"
    if level == "minor":
        return f"{major}.{minor + 1}.0"
    return f"{major}.{minor}.{patch + 1}"


def next_version(current: str, lines: list[str]) -> str | None:
    """Next version for ``current`` given the commit ``lines``, or None."""
    return bump(current, classify(lines))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--current", required=True, help="current version (e.g. 1.1.3 or v1.1.3)")
    args = parser.parse_args(argv)
    result = next_version(args.current, sys.stdin.read().splitlines())
    if result is None:
        return 1
    sys.stdout.write(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# -*- coding: utf-8 -*-
"""Tests for scripts/next_version.py (auto-tag version computation)."""

from __future__ import annotations

import sys
from pathlib import Path

# scripts/ is not a package; add it to the path so the auto-tag helper is
# importable from the (collected) package test tree.
_SCRIPTS = Path(__file__).resolve().parents[4] / "scripts"
sys.path.insert(0, str(_SCRIPTS))

import next_version as nv  # noqa: E402


def test_feat_bumps_minor():
    assert nv.next_version("1.1.3", ["feat: add auth login", "docs: notes"]) == "1.2.0"


def test_fix_bumps_patch():
    assert nv.next_version("1.1.3", ["fix(auth): route subscriptions", "chore: deps"]) == "1.1.4"


def test_breaking_marker_bumps_major():
    assert nv.next_version("1.1.3", ["feat!: drop legacy route"]) == "2.0.0"
    assert nv.next_version("1.1.3", ["feat(api)!: rename"]) == "2.0.0"


def test_breaking_footer_bumps_major():
    assert nv.next_version("1.1.3", ["refactor: x", "", "BREAKING CHANGE: removed Y"]) == "2.0.0"


def test_strongest_level_wins():
    assert nv.next_version("1.1.3", ["fix: a", "feat: b", "docs: c"]) == "1.2.0"


def test_no_release_worthy_commits():
    assert nv.next_version("1.1.3", ["docs: x", "chore: y", "ci: z", "test: w"]) is None


def test_v_prefix_and_blank_lines_tolerated():
    assert nv.next_version("v1.1.3", ["", "  ", "fix: a"]) == "1.1.4"


def test_lookalike_types_do_not_trigger():
    # "feature:" / "fixture:" must not be read as feat / fix.
    assert nv.next_version("1.1.3", ["feature: marketing", "fixtures: test data"]) is None


def test_bump_rejects_bad_version():
    import pytest

    with pytest.raises(ValueError):
        nv.bump("1.2", "patch")

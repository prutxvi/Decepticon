"""Tests for decepticon.skillogy.server.ingest — and full skill-corpus migration."""

from __future__ import annotations

from pathlib import Path

from decepticon.skillogy.proto import SkillListRequest
from decepticon.skillogy.server.ingest import ingest_directory
from decepticon.skillogy.server.registry import SkillRegistry


def test_ingest_missing_dir_returns_zero(tmp_path: Path):
    reg = SkillRegistry()
    assert ingest_directory(reg, tmp_path / "nope") == 0


def test_ingest_directory_walks_recursively(tmp_path: Path):
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "SKILL.md").write_text(
        "---\nname: a\ndescription: a\n---\nbody-a", encoding="utf-8"
    )
    (tmp_path / "a" / "b" / "SKILL.md").write_text(
        "---\nname: b\ndescription: b\n---\nbody-b", encoding="utf-8"
    )
    reg = SkillRegistry()
    count = ingest_directory(reg, tmp_path)
    assert count == 2
    assert reg.load("/skills/a/SKILL.md") is not None
    assert reg.load("/skills/a/b/SKILL.md") is not None


def test_ingest_pulls_in_references_and_scripts(tmp_path: Path):
    (tmp_path / "ad").mkdir()
    (tmp_path / "ad" / "SKILL.md").write_text(
        "---\nname: ad\ndescription: ad skill\n---\nbody", encoding="utf-8"
    )
    (tmp_path / "ad" / "references").mkdir()
    (tmp_path / "ad" / "references" / "paper.md").write_text("paper", encoding="utf-8")
    (tmp_path / "ad" / "scripts").mkdir()
    (tmp_path / "ad" / "scripts" / "run.sh").write_text("#!/bin/bash\necho ok", encoding="utf-8")
    reg = SkillRegistry()
    ingest_directory(reg, tmp_path)
    env = reg.load("/skills/ad/SKILL.md")
    assert env is not None
    assert "paper.md" in env.references
    assert "run.sh" in env.scripts


def test_full_decepticon_corpus_ingests_cleanly():
    """Real migration test: all 193+ skills under the in-tree skills/ tree
    must ingest without errors and end up indexable."""
    skills_root = (
        Path(__file__).resolve().parent.parent.parent.parent
        / "decepticon"
        / "skills"
    )
    if not skills_root.exists():
        return
    reg = SkillRegistry()
    count = ingest_directory(reg, skills_root)
    assert count > 100
    resp = reg.list(SkillListRequest(page_size=1000))
    assert resp.total_count == count
    assert all(s.name or s.path for s in resp.skills)

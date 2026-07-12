# -*- coding: utf-8 -*-
"""Tests for the Decepticon ``load_skill`` tool."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from decepticon.tools.skills import build_load_skill_tool
from decepticon.tools.skills_registry import SkillRecord


@dataclass
class _BackendResult:
    error: str | None = None
    file_data: dict[str, Any] | None = None


class _Backend:
    def __init__(self, files: dict[str, str], dirs: dict[str, list[str]] | None = None) -> None:
        self.files = files
        self.dirs = dirs or {}
        self.reads: list[str] = []

    def read(self, path: str) -> _BackendResult:
        self.reads.append(path)
        if path not in self.files:
            return _BackendResult(error="not found")
        return _BackendResult(file_data={"content": self.files[path]})

    def ls(self, path: str) -> _BackendResult:
        return _BackendResult(file_data={"entries": self.dirs.get(path, [])})


def _record(path: str, slug: str) -> SkillRecord:
    return SkillRecord(id=path, slug=slug, name=slug, description="", source="/skills/")


def _skill_body(name: str = "sql-injection") -> str:
    return f"---\nname: {name}\ndescription: test skill\n---\n# Body\nDo the safe thing.\n"


def _invoke(tool_obj, skill_path: str, include_siblings: bool = False) -> str:
    return tool_obj.invoke({"skill_path": skill_path, "include_siblings": include_siblings})


def test_load_skill_accepts_exact_path() -> None:
    path = "/skills/standard/analyst/sql-injection/SKILL.md"
    backend = _Backend({path: _skill_body()})
    tool = build_load_skill_tool(backend, ["/skills/standard/analyst/"], registry=[])

    out = _invoke(tool, path)

    assert "Base directory for this skill: /skills/standard/analyst/sql-injection" in out
    assert "# Body" in out
    assert backend.reads == [path]


def test_load_skill_resolves_unique_slug() -> None:
    path = "/skills/standard/analyst/sql-injection/SKILL.md"
    backend = _Backend({path: _skill_body()})
    tool = build_load_skill_tool(
        backend,
        ["/skills/standard/analyst/"],
        registry=[_record(path, "sql-injection")],
    )

    out = _invoke(tool, "sql injection")

    assert "Skill: sql-injection" in out
    assert backend.reads == [path]


def test_load_skill_resolves_relative_path() -> None:
    path = "/skills/standard/exploit/web/sqli/SKILL.md"
    backend = _Backend({path: _skill_body("sqli")})
    tool = build_load_skill_tool(backend, ["/skills/standard/exploit/"], registry=[])

    out = _invoke(tool, "standard/exploit/web/sqli")

    assert "Skill: sqli" in out
    assert backend.reads == [path]


def test_load_skill_reports_ambiguous_slug_without_reading() -> None:
    first = "/skills/standard/analyst/reporting/SKILL.md"
    second = "/skills/standard/decepticon/reporting/SKILL.md"
    backend = _Backend({first: _skill_body("reporting"), second: _skill_body("reporting")})
    tool = build_load_skill_tool(
        backend,
        ["/skills/standard/"],
        registry=[_record(first, "reporting"), _record(second, "reporting")],
    )

    out = _invoke(tool, "reporting")

    assert "[load_skill error] Ambiguous skill query" in out
    assert first in out
    assert second in out
    assert backend.reads == []


def test_load_skill_rejects_slug_outside_allowed_sources() -> None:
    path = "/skills/standard/contracts/reentrancy/SKILL.md"
    backend = _Backend({path: _skill_body("reentrancy")})
    tool = build_load_skill_tool(
        backend,
        ["/skills/standard/analyst/"],
        registry=[_record(path, "reentrancy")],
    )

    out = _invoke(tool, "reentrancy")

    assert "[load_skill error] Skill not found for query" in out
    assert backend.reads == []


def test_load_skill_rejects_unsafe_short_path() -> None:
    backend = _Backend({})
    tool = build_load_skill_tool(backend, ["/skills/standard/"], registry=[])

    out = _invoke(tool, "../standard/analyst/sql-injection/SKILL.md")

    assert "Unsafe skill query rejected" in out
    assert backend.reads == []


def test_load_skill_lists_references_and_siblings_for_resolved_slug() -> None:
    path = "/skills/standard/analyst/sql-injection/SKILL.md"
    backend = _Backend(
        {path: _skill_body()},
        dirs={
            "/skills/standard/analyst/sql-injection/references": ["cheatsheet.md"],
            "/skills/standard/analyst/sql-injection": ["SKILL.md", "variant.md"],
        },
    )
    tool = build_load_skill_tool(
        backend,
        ["/skills/standard/analyst/"],
        registry=[_record(path, "sql-injection")],
    )

    out = _invoke(tool, "sql-injection", include_siblings=True)

    assert "/skills/standard/analyst/sql-injection/references/cheatsheet.md" in out
    assert "/skills/standard/analyst/sql-injection/variant.md" in out

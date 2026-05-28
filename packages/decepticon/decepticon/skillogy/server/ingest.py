"""Filesystem -> Skillogy registry ingester.

Walks every ``SKILL.md`` under a root directory, reads its body and any
``references/`` and ``scripts/`` sibling directories, then registers
each with the in-process registry. Used both at server boot (to seed
the catalog from the in-tree skills/) and by a standalone CLI for
operator-driven imports.

The canonical skill path used as the registry key is the
``/skills/<...>/<name>/SKILL.md`` form expected by the existing
SkillsMiddleware so the client/middleware swap is a no-op for skill
references in the agent prompts.
"""

from __future__ import annotations

import logging
from pathlib import Path

from decepticon.skillogy.server.registry import SkillRegistry

log = logging.getLogger(__name__)


def _canonical_path(skill_md: Path, root: Path) -> str:
    rel = skill_md.relative_to(root).as_posix()
    return "/skills/" + rel


def _read_attachment_dir(dirpath: Path) -> dict[str, bytes]:
    if not dirpath.exists() or not dirpath.is_dir():
        return {}
    out: dict[str, bytes] = {}
    for f in dirpath.rglob("*"):
        if not f.is_file():
            continue
        try:
            out[f.relative_to(dirpath).as_posix()] = f.read_bytes()
        except OSError as exc:
            log.warning("attachment read failed for %s: %s", f, exc)
    return out


def ingest_directory(registry: SkillRegistry, root: str | Path) -> int:
    """Walk every SKILL.md under ``root`` and register it. Returns the count."""
    root_path = Path(root)
    if not root_path.exists():
        log.warning("ingest root does not exist: %s", root_path)
        return 0
    count = 0
    for skill_md in root_path.rglob("SKILL.md"):
        try:
            body = skill_md.read_text(encoding="utf-8")
        except OSError as exc:
            log.warning("skill read failed for %s: %s", skill_md, exc)
            continue
        path = _canonical_path(skill_md, root_path)
        references = _read_attachment_dir(skill_md.parent / "references")
        scripts = _read_attachment_dir(skill_md.parent / "scripts")
        registry.ingest(path, body, references=references, scripts=scripts)
        count += 1
    log.info("ingested %d skills from %s", count, root_path)
    return count

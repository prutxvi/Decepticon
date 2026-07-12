# -*- coding: utf-8 -*-
"""Skill source paths contributed by this plugin.

The framework reads ``/skills/<bundle>/<role>/`` paths via the
``SkillsMiddleware``. Plugins ship skill markdown files as package data
and register the path prefix here.
"""

from __future__ import annotations


def get_skill_sources(role: str | None = None) -> list[str]:
    """Plugin factory called by the framework's skill loader."""
    del role
    return ["/skills/decepticon_example_skill/"]

__all__ = []

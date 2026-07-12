# -*- coding: utf-8 -*-
"""Custom callback handler contributed to Decepticon."""

from __future__ import annotations


class HelloCallback:
    """Minimal CallbackProtocol-compliant handler."""

    def on_llm_start(self, *args: object, **kwargs: object) -> None:
        return None

    def on_llm_end(self, *args: object, **kwargs: object) -> None:
        return None

    def on_tool_start(self, *args: object, **kwargs: object) -> None:
        return None

    def on_tool_end(self, *args: object, **kwargs: object) -> None:
        return None


def get_callbacks(role: str | None = None, **_: object) -> list[HelloCallback]:
    """Plugin factory called by the framework's callback loader."""
    del role
    return [HelloCallback()]

__all__ = []

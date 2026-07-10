"""Custom middleware contributed to Decepticon."""

from __future__ import annotations

from decepticon_sdk import MiddlewareProtocol, MiddlewareSlot


class HelloMiddleware:
    """Minimal MiddlewareProtocol-compliant middleware."""

    name = "decepticon_example_middleware"
    slot: MiddlewareSlot | str = MiddlewareSlot.SKILLS
    priority = 150

    def wrap_model_call(self, state: object, runtime: object, config: object) -> object:
        return state


def get_middleware(role: str | None = None, **_: object) -> list[MiddlewareProtocol]:
    """Plugin factory called by the framework's middleware loader."""
    del role
    return [HelloMiddleware()]

__all__ = []

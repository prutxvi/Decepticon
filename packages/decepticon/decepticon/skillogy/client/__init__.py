from __future__ import annotations
"""Skillogy REST client (Phase 1a, Amendment v0.2.2)."""

from decepticon.skillogy.client.rest import (
    RestSkillogyClient,
    SkillogyClientError,
    from_env,
)

__all__ = ["RestSkillogyClient", "SkillogyClientError", "from_env"]

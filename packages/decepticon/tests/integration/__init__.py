# -*- coding: utf-8 -*-
"""Integration tests — require live infrastructure.

Tests in this tree (compose Neo4j, langgraph, sandbox, etc.) skip
automatically when the service they need is unreachable, so a default
``pytest`` invocation in a fresh checkout does not fail. CI brings the
stack up before running this lane.
"""

from __future__ import annotations

__all__ = []

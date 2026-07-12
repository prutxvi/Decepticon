# -*- coding: utf-8 -*-
from __future__ import annotations
"""Persistent Playwright browser sessions for the Decepticon agent.

Exposes ``browser_action(action, **kwargs)`` — a single multiplex
LangChain tool covering the operations a specialist needs to drive a
real browser (SPA auth flows, OAuth callbacks, DOM-XSS verification,
companion-app inspection). State lives in a per-process session
manager; the optional Playwright dependency is imported lazily so the
agent process keeps booting even when Playwright is not installed in
the current environment.

Sandbox / ``containers/sandbox.Dockerfile`` install of Playwright +
Chromium and the ``docker-compose.yml`` wiring are intentionally out
of scope for this initial library PR; a follow-up will install the
deps in the sandbox image so the tool can be used end-to-end at runtime.
"""

from decepticon.tools.browser.tools import (
    BROWSER_TOOLS,
    BrowserActionError,
    BrowserSessionManager,
    browser_action,
)

__all__ = [
    "BROWSER_TOOLS",
    "BrowserActionError",
    "BrowserSessionManager",
    "browser_action",
]

# -*- coding: utf-8 -*-
from __future__ import annotations
"""Caido intercepting-proxy integration.

Provides LangChain ``@tool`` wrappers so an agent can capture, view,
replay, mutate, and scope HTTP traffic through a Caido instance. Tools
issue Caido CLI commands via subprocess; the CLI binary and the Caido
server are configured by env vars (``CAIDO_CLI``, ``CAIDO_API_URL``,
``CAIDO_API_TOKEN``).

Caido container provisioning and ``docker-compose.yml`` wiring are
intentionally out of scope for this initial library PR; a follow-up
will install the Caido client in the sandbox and add a Caido service
to the compose stack.
"""

from decepticon.tools.proxy.tools import (
    PROXY_TOOLS,
    CaidoClient,
    CaidoConfig,
    CaidoError,
    proxy_list_requests,
    proxy_list_sitemap,
    proxy_repeat_request,
    proxy_scope_rules,
    proxy_send_request,
    proxy_view_request,
    proxy_view_sitemap_entry,
)

__all__ = [
    "CaidoClient",
    "CaidoConfig",
    "CaidoError",
    "PROXY_TOOLS",
    "proxy_list_requests",
    "proxy_list_sitemap",
    "proxy_repeat_request",
    "proxy_scope_rules",
    "proxy_send_request",
    "proxy_view_request",
    "proxy_view_sitemap_entry",
]

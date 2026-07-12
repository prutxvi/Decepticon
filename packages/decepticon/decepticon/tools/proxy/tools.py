# -*- coding: utf-8 -*-
"""Caido proxy LangChain tool wrappers.

Each ``@tool`` shell-invokes the Caido CLI (configurable via the
``CAIDO_CLI`` env var, default ``caido``) and returns the structured
result as a JSON string. The agent prompt instructs specialists to call
these tools whenever a proxy-first workflow is appropriate (capture,
replay, scope, sitemap inspection).

Errors are returned as ``{"error": "..."}`` JSON rather than raised so
the LLM can reason about them in-band. Subprocess invocations are
bounded by a configurable timeout (``CAIDO_TIMEOUT_SECONDS``, default
``30``) so a wedged CLI cannot stall the agent loop.
"""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from dataclasses import dataclass
from typing import Any

from langchain_core.tools import tool

DEFAULT_CAIDO_CLI = "caido"
DEFAULT_TIMEOUT_SECONDS = 30


class CaidoError(RuntimeError):
    """Raised internally when the Caido CLI invocation fails fatally.

    Caught by every tool wrapper and converted to a JSON ``{"error": ...}``
    string so the LLM can see and react to the failure instead of having
    the agent loop terminate.
    """


@dataclass(frozen=True, slots=True)
class CaidoConfig:
    """Caido CLI / API configuration resolved from environment.

    Fields are kept narrow so future config-file or per-engagement
    overrides can land without breaking call sites.
    """

    cli: str = DEFAULT_CAIDO_CLI
    api_url: str | None = None
    api_token: str | None = None
    timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS

    @classmethod
    def from_env(cls) -> CaidoConfig:
        timeout_raw = os.getenv("CAIDO_TIMEOUT_SECONDS", "").strip()
        try:
            timeout = int(timeout_raw) if timeout_raw else DEFAULT_TIMEOUT_SECONDS
        except ValueError:
            timeout = DEFAULT_TIMEOUT_SECONDS
        return cls(
            cli=os.getenv("CAIDO_CLI", DEFAULT_CAIDO_CLI),
            api_url=os.getenv("CAIDO_API_URL") or None,
            api_token=os.getenv("CAIDO_API_TOKEN") or None,
            timeout_seconds=timeout,
        )


class CaidoClient:
    """Thin shell over the Caido CLI used by the ``@tool`` wrappers.

    Constructed once per tool call from :class:`CaidoConfig`. Splitting
    this out of the tool functions keeps the wrappers tiny (each is a
    one-liner over the client) and lets tests substitute a fake client
    to assert command shape without spawning a real subprocess.
    """

    def __init__(self, config: CaidoConfig | None = None) -> None:
        self._config = config or CaidoConfig.from_env()

    @property
    def config(self) -> CaidoConfig:
        return self._config

    def _run(self, args: list[str]) -> dict[str, Any]:
        argv = [self._config.cli, *args]
        env = os.environ.copy()
        if self._config.api_url:
            env.setdefault("CAIDO_API_URL", self._config.api_url)
        if self._config.api_token:
            env.setdefault("CAIDO_API_TOKEN", self._config.api_token)
        try:
            proc = subprocess.run(
                argv,
                env=env,
                capture_output=True,
                text=True,
                timeout=self._config.timeout_seconds,
                check=False,
            )
        except FileNotFoundError as exc:
            raise CaidoError(f"Caido CLI not found: {self._config.cli}") from exc
        except subprocess.TimeoutExpired as exc:
            raise CaidoError(
                f"Caido CLI timed out after {self._config.timeout_seconds}s: {shlex.join(argv)}"
            ) from exc
        if proc.returncode != 0:
            stderr = (proc.stderr or "").strip() or (proc.stdout or "").strip()
            raise CaidoError(f"Caido CLI exited {proc.returncode}: {stderr[:512]}")
        stdout = (proc.stdout or "").strip()
        if not stdout:
            return {}
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            return {"raw": stdout}

    def list_requests(
        self, project: str | None = None, limit: int = 50, filter_: str | None = None
    ) -> dict[str, Any]:
        args = ["requests", "list", "--limit", str(limit), "--json"]
        if project:
            args += ["--project", project]
        if filter_:
            args += ["--filter", filter_]
        return self._run(args)

    def view_request(self, request_id: str) -> dict[str, Any]:
        return self._run(["requests", "view", request_id, "--json"])

    def send_request(
        self, method: str, url: str, headers_json: str = "", body: str = ""
    ) -> dict[str, Any]:
        args = ["requests", "send", "--method", method, "--url", url, "--json"]
        if headers_json:
            args += ["--headers", headers_json]
        if body:
            args += ["--body", body]
        return self._run(args)

    def repeat_request(self, request_id: str, mutations_json: str = "") -> dict[str, Any]:
        args = ["requests", "repeat", request_id, "--json"]
        if mutations_json:
            args += ["--mutations", mutations_json]
        return self._run(args)

    def scope_rules(
        self, action: str = "list", in_scope: str = "", out_of_scope: str = ""
    ) -> dict[str, Any]:
        args = ["scope", action, "--json"]
        if in_scope:
            args += ["--in-scope", in_scope]
        if out_of_scope:
            args += ["--out-of-scope", out_of_scope]
        return self._run(args)

    def list_sitemap(self, project: str | None = None) -> dict[str, Any]:
        args = ["sitemap", "list", "--json"]
        if project:
            args += ["--project", project]
        return self._run(args)

    def view_sitemap_entry(self, entry_id: str) -> dict[str, Any]:
        return self._run(["sitemap", "view", entry_id, "--json"])


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)


def _safe_call(fn: Any, *args: Any, **kwargs: Any) -> str:
    try:
        result = fn(*args, **kwargs)
    except CaidoError as exc:
        return _json({"error": str(exc)})
    return _json(result)


@tool
def proxy_list_requests(project: str = "", limit: int = 50, filter: str = "") -> str:
    """List captured HTTP requests from Caido's traffic history.

    Args:
        project: Optional Caido project ID to scope the listing.
        limit: Maximum number of recent requests to return (default 50).
        filter: Optional Caido filter expression (e.g. ``host=target.example``).
    """
    client = CaidoClient()
    return _safe_call(
        client.list_requests,
        project=project or None,
        limit=limit,
        filter_=filter or None,
    )


@tool
def proxy_view_request(request_id: str) -> str:
    """View a single captured HTTP request by id (full headers + body)."""
    client = CaidoClient()
    return _safe_call(client.view_request, request_id)


@tool
def proxy_send_request(method: str, url: str, headers_json: str = "", body: str = "") -> str:
    """Send a one-off HTTP request through Caido and capture the response.

    Args:
        method: HTTP verb, e.g. ``GET`` / ``POST``.
        url: Absolute target URL.
        headers_json: Optional JSON object of header name -> value.
        body: Optional request body string.
    """
    client = CaidoClient()
    return _safe_call(
        client.send_request,
        method=method,
        url=url,
        headers_json=headers_json,
        body=body,
    )


@tool
def proxy_repeat_request(request_id: str, mutations_json: str = "") -> str:
    """Replay an existing captured request, optionally mutating fields.

    Args:
        request_id: Id of the captured request to replay.
        mutations_json: Optional JSON object describing mutations
            (e.g. ``{"headers": {"X-User": "admin"}, "path": "/admin"}``).
    """
    client = CaidoClient()
    return _safe_call(client.repeat_request, request_id=request_id, mutations_json=mutations_json)


@tool
def proxy_scope_rules(action: str = "list", in_scope: str = "", out_of_scope: str = "") -> str:
    """Read or update Caido scope (in-scope / out-of-scope host patterns).

    Args:
        action: ``list`` (read) or ``set`` (replace) or ``add`` (append).
        in_scope: Comma-separated host / CIDR patterns to include.
        out_of_scope: Comma-separated patterns to exclude.
    """
    client = CaidoClient()
    return _safe_call(
        client.scope_rules,
        action=action,
        in_scope=in_scope,
        out_of_scope=out_of_scope,
    )


@tool
def proxy_list_sitemap(project: str = "") -> str:
    """List sitemap entries discovered by Caido for the current project."""
    client = CaidoClient()
    return _safe_call(client.list_sitemap, project=project or None)


@tool
def proxy_view_sitemap_entry(entry_id: str) -> str:
    """View a single sitemap entry (URL + parameter inventory) by id."""
    client = CaidoClient()
    return _safe_call(client.view_sitemap_entry, entry_id)


PROXY_TOOLS = [
    proxy_list_requests,
    proxy_view_request,
    proxy_send_request,
    proxy_repeat_request,
    proxy_scope_rules,
    proxy_list_sitemap,
    proxy_view_sitemap_entry,
]


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

# -*- coding: utf-8 -*-
"""Tests for ``decepticon.tools.proxy`` — Caido CLI tool wrappers."""

from __future__ import annotations

import asyncio
import json
import subprocess
from unittest.mock import patch

import pytest

from decepticon.tools.proxy import (
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


def _completed(
    stdout: str = "", stderr: str = "", returncode: int = 0
) -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


class TestCaidoConfigFromEnv:
    def test_defaults_when_env_empty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key in ("CAIDO_CLI", "CAIDO_API_URL", "CAIDO_API_TOKEN", "CAIDO_TIMEOUT_SECONDS"):
            monkeypatch.delenv(key, raising=False)
        cfg = CaidoConfig.from_env()
        assert cfg.cli == "caido"
        assert cfg.api_url is None
        assert cfg.api_token is None
        assert cfg.timeout_seconds == 30

    def test_env_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CAIDO_CLI", "/opt/caido/caido-cli")
        monkeypatch.setenv("CAIDO_API_URL", "http://caido:7000")
        monkeypatch.setenv("CAIDO_API_TOKEN", "tok-123")
        monkeypatch.setenv("CAIDO_TIMEOUT_SECONDS", "10")
        cfg = CaidoConfig.from_env()
        assert cfg.cli == "/opt/caido/caido-cli"
        assert cfg.api_url == "http://caido:7000"
        assert cfg.api_token == "tok-123"
        assert cfg.timeout_seconds == 10

    def test_invalid_timeout_falls_back_to_default(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("CAIDO_TIMEOUT_SECONDS", "not-a-number")
        assert CaidoConfig.from_env().timeout_seconds == 30


class TestCaidoClientCommandShapes:
    def test_list_requests_passes_limit_and_filter(self) -> None:
        client = CaidoClient(CaidoConfig(cli="caido", timeout_seconds=5))
        with patch("subprocess.run", return_value=_completed('{"results": []}')) as m:
            client.list_requests(project="proj-1", limit=25, filter_="host=target")
        args = m.call_args[0][0]
        assert args[0] == "caido"
        assert "requests" in args and "list" in args
        assert "--limit" in args and "25" in args
        assert "--project" in args and "proj-1" in args
        assert "--filter" in args and "host=target" in args
        assert "--json" in args

    def test_view_request_passes_id(self) -> None:
        client = CaidoClient(CaidoConfig(cli="caido"))
        with patch("subprocess.run", return_value=_completed("{}")) as m:
            client.view_request("REQ-42")
        args = m.call_args[0][0]
        assert args[:3] == ["caido", "requests", "view"]
        assert "REQ-42" in args

    def test_send_request_passes_method_url_headers_body(self) -> None:
        client = CaidoClient(CaidoConfig(cli="caido"))
        with patch("subprocess.run", return_value=_completed("{}")) as m:
            client.send_request(
                method="POST",
                url="https://target/login",
                headers_json='{"X-User": "admin"}',
                body="user=admin",
            )
        args = m.call_args[0][0]
        assert "--method" in args and "POST" in args
        assert "--url" in args and "https://target/login" in args
        assert "--headers" in args and '{"X-User": "admin"}' in args
        assert "--body" in args and "user=admin" in args

    def test_repeat_request_with_mutations(self) -> None:
        client = CaidoClient(CaidoConfig(cli="caido"))
        with patch("subprocess.run", return_value=_completed("{}")) as m:
            client.repeat_request("REQ-7", mutations_json='{"path": "/admin"}')
        args = m.call_args[0][0]
        assert "repeat" in args and "REQ-7" in args
        assert "--mutations" in args

    def test_scope_rules_default_lists(self) -> None:
        client = CaidoClient(CaidoConfig(cli="caido"))
        with patch("subprocess.run", return_value=_completed("{}")) as m:
            client.scope_rules()
        args = m.call_args[0][0]
        assert args[:3] == ["caido", "scope", "list"]

    def test_list_sitemap_passes_project(self) -> None:
        client = CaidoClient(CaidoConfig(cli="caido"))
        with patch("subprocess.run", return_value=_completed("{}")) as m:
            client.list_sitemap(project="proj-2")
        args = m.call_args[0][0]
        assert "--project" in args and "proj-2" in args

    def test_view_sitemap_entry_passes_id(self) -> None:
        client = CaidoClient(CaidoConfig(cli="caido"))
        with patch("subprocess.run", return_value=_completed("{}")) as m:
            client.view_sitemap_entry("ENTRY-99")
        args = m.call_args[0][0]
        assert "view" in args and "ENTRY-99" in args


class TestCaidoClientErrorHandling:
    def test_cli_not_found_raises_caido_error(self) -> None:
        client = CaidoClient(CaidoConfig(cli="definitely-not-on-path"))
        with patch("subprocess.run", side_effect=FileNotFoundError("not found")):
            with pytest.raises(CaidoError, match="not found"):
                client.list_requests()

    def test_cli_timeout_raises_caido_error(self) -> None:
        client = CaidoClient(CaidoConfig(cli="caido", timeout_seconds=2))
        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired(cmd="caido", timeout=2),
        ):
            with pytest.raises(CaidoError, match="timed out"):
                client.list_requests()

    def test_nonzero_exit_raises_caido_error_with_stderr(self) -> None:
        client = CaidoClient(CaidoConfig(cli="caido"))
        with patch(
            "subprocess.run",
            return_value=_completed(stderr="auth failed", returncode=2),
        ):
            with pytest.raises(CaidoError, match="exited 2"):
                client.list_requests()

    def test_non_json_stdout_returns_raw(self) -> None:
        client = CaidoClient(CaidoConfig(cli="caido"))
        with patch("subprocess.run", return_value=_completed("plain text output")):
            result = client.list_requests()
        assert result == {"raw": "plain text output"}

    def test_empty_stdout_returns_empty_dict(self) -> None:
        client = CaidoClient(CaidoConfig(cli="caido"))
        with patch("subprocess.run", return_value=_completed("")):
            result = client.list_requests()
        assert result == {}


class TestToolWrappers:
    def test_proxy_list_requests_returns_json(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_completed(stdout=json.dumps({"results": [{"id": "REQ-1"}]})),
        ):
            out = asyncio.run(proxy_list_requests.ainvoke({"limit": 10}))
        parsed = json.loads(out)
        assert parsed == {"results": [{"id": "REQ-1"}]}

    def test_proxy_view_request_returns_json(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_completed(stdout=json.dumps({"id": "REQ-1", "method": "GET"})),
        ):
            out = asyncio.run(proxy_view_request.ainvoke({"request_id": "REQ-1"}))
        assert json.loads(out)["id"] == "REQ-1"

    def test_proxy_send_request_returns_json(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_completed(stdout=json.dumps({"status": 200})),
        ):
            out = asyncio.run(
                proxy_send_request.ainvoke(
                    {
                        "method": "GET",
                        "url": "https://target/",
                    }
                )
            )
        assert json.loads(out)["status"] == 200

    def test_proxy_repeat_request_returns_json(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_completed(stdout=json.dumps({"status": 401})),
        ):
            out = asyncio.run(proxy_repeat_request.ainvoke({"request_id": "REQ-5"}))
        assert json.loads(out)["status"] == 401

    def test_proxy_scope_rules_returns_json(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_completed(stdout=json.dumps({"in_scope": ["target.example"]})),
        ):
            out = asyncio.run(proxy_scope_rules.ainvoke({}))
        assert json.loads(out)["in_scope"] == ["target.example"]

    def test_proxy_list_sitemap_returns_json(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_completed(stdout=json.dumps({"entries": []})),
        ):
            out = asyncio.run(proxy_list_sitemap.ainvoke({}))
        assert json.loads(out) == {"entries": []}

    def test_proxy_view_sitemap_entry_returns_json(self) -> None:
        with patch(
            "subprocess.run",
            return_value=_completed(stdout=json.dumps({"url": "/login"})),
        ):
            out = asyncio.run(proxy_view_sitemap_entry.ainvoke({"entry_id": "ENTRY-1"}))
        assert json.loads(out)["url"] == "/login"

    def test_cli_not_found_surfaces_as_error_json(self) -> None:
        with patch("subprocess.run", side_effect=FileNotFoundError("nope")):
            out = asyncio.run(proxy_list_requests.ainvoke({}))
        parsed = json.loads(out)
        assert "error" in parsed
        assert "Caido CLI not found" in parsed["error"]


def test_proxy_tools_export_is_complete() -> None:
    """Sanity-check the agent-facing PROXY_TOOLS bundle has all 7 wrappers."""
    assert len(PROXY_TOOLS) == 7
    names = {t.name for t in PROXY_TOOLS}
    assert names == {
        "proxy_list_requests",
        "proxy_view_request",
        "proxy_send_request",
        "proxy_repeat_request",
        "proxy_scope_rules",
        "proxy_list_sitemap",
        "proxy_view_sitemap_entry",
    }

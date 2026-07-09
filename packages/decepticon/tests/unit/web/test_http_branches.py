"""test_http_branches module."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from decepticon.tools.web.http import (
    HTTPHistory,
    HTTPRequest,
    HTTPResponse,
    HTTPSession,
    diff_responses,
)


def _request(
    req_id: str,
    *,
    url: str = "https://example.test",
    method: str = "GET",
    tag: str = "",
) -> HTTPRequest:
    return HTTPRequest(
        id=req_id,
        method=method,
        url=url,
        headers={},
        body=b"",
        timestamp=1.0,
        tag=tag,
    )


def _response(request_id: str, *, status: int = 200) -> HTTPResponse:
    return HTTPResponse(
        id=f"resp-{request_id}",
        request_id=request_id,
        status=status,
        headers={},
        body=b"ok",
        elapsed_ms=5.0,
        timestamp=2.0,
    )


class TestHTTPRequestToDict:
    def test_to_dict_returns_all_expected_keys_with_correct_values(self) -> None:
        req = HTTPRequest(
            id="r1",
            method="GET",
            url="https://x",
            headers={"A": "1"},
            body=b"hello",
            timestamp=1.0,
            tag="t",
        )
        result = req.to_dict()
        assert result["id"] == "r1"
        assert result["method"] == "GET"
        assert result["url"] == "https://x"
        assert result["timestamp"] == 1.0
        assert result["tag"] == "t"
        assert result["body"] == "hello"

    def test_to_dict_headers_is_a_copy_not_original_reference(self) -> None:
        req = HTTPRequest(
            id="r1",
            method="GET",
            url="https://x",
            headers={"A": "1"},
            body=b"",
            timestamp=1.0,
        )
        result = req.to_dict()
        result["headers"]["NEW"] = "injected"
        assert "NEW" not in req.headers

    def test_to_dict_non_utf8_body_decoded_with_replacement_character(self) -> None:
        req = HTTPRequest(
            id="r1",
            method="GET",
            url="https://x",
            headers={},
            body=b"\xff\xfe",
            timestamp=1.0,
        )
        result = req.to_dict()
        assert "�" in result["body"]


class TestHTTPResponseToDict:
    def test_to_dict_returns_all_expected_keys(self) -> None:
        resp = HTTPResponse(
            id="resp1",
            request_id="r1",
            status=200,
            headers={"X": "y"},
            body=b"ok",
            elapsed_ms=12.345,
            timestamp=2.0,
        )
        result = resp.to_dict()
        assert result["id"] == "resp1"
        assert result["request_id"] == "r1"
        assert result["status"] == 200
        assert result["elapsed_ms"] == 12.35
        assert result["body"] == "ok"
        assert result["timestamp"] == 2.0

    def test_to_dict_headers_is_a_copy_not_original_reference(self) -> None:
        resp = HTTPResponse(
            id="resp1",
            request_id="r1",
            status=200,
            headers={"X": "y"},
            body=b"ok",
            elapsed_ms=5.0,
            timestamp=2.0,
        )
        result = resp.to_dict()
        result["headers"]["NEW"] = "injected"
        assert "NEW" not in resp.headers

    def test_to_dict_non_utf8_body_decoded_with_replacement_character(self) -> None:
        resp = HTTPResponse(
            id="resp1",
            request_id="r1",
            status=200,
            headers={},
            body=b"\x80abc",
            elapsed_ms=5.0,
            timestamp=2.0,
        )
        result = resp.to_dict()
        assert "�" in result["body"]

    def test_to_dict_elapsed_ms_rounded_to_two_decimal_places(self) -> None:
        resp = HTTPResponse(
            id="r",
            request_id="q",
            status=200,
            headers={},
            body=b"",
            elapsed_ms=99.999,
            timestamp=1.0,
        )
        assert resp.to_dict()["elapsed_ms"] == 100.0


class TestHTTPResponseText:
    def test_text_returns_full_body_when_within_max_chars(self) -> None:
        body = ("a" * 10).encode()
        resp = HTTPResponse(
            id="r",
            request_id="q",
            status=200,
            headers={},
            body=body,
            elapsed_ms=1.0,
            timestamp=1.0,
        )
        assert resp.text() == "a" * 10

    def test_text_truncates_body_when_exceeds_max_chars(self) -> None:
        body = ("a" * 5000).encode()
        resp = HTTPResponse(
            id="r",
            request_id="q",
            status=200,
            headers={},
            body=body,
            elapsed_ms=1.0,
            timestamp=1.0,
        )
        result = resp.text(max_chars=4000)
        assert result.startswith("a" * 4000)
        assert result.endswith("[...1000 truncated]")
        assert "\n" in result

    def test_text_at_exact_max_chars_boundary_no_truncation(self) -> None:
        body = b"abcd"
        resp = HTTPResponse(
            id="r",
            request_id="q",
            status=200,
            headers={},
            body=body,
            elapsed_ms=1.0,
            timestamp=1.0,
        )
        assert resp.text(max_chars=4) == "abcd"


class TestHTTPHistoryLen:
    def test_empty_history_has_len_zero(self) -> None:
        history = HTTPHistory()
        assert len(history) == 0

    def test_len_increases_after_record_calls(self) -> None:
        history = HTTPHistory()
        history.record(_request("r1"))
        history.record(_request("r2"))
        assert len(history) == 2


class TestHTTPHistoryRecord:
    def test_explicit_eviction_removes_oldest_from_by_id(self) -> None:
        history = HTTPHistory(maxlen=2)
        history.record(_request("req-1"), _response("req-1"))
        history.record(_request("req-2"), _response("req-2"))
        history.record(_request("req-3"), _response("req-3"))
        assert history.get_by_id("req-1") is None
        assert len(history) == 2
        assert history.get_by_id("req-2") is not None
        assert history.get_by_id("req-3") is not None

    def test_record_with_no_response_stores_none(self) -> None:
        history = HTTPHistory()
        req = _request("r1")
        history.record(req)
        pair = history.get_by_id("r1")
        assert pair is not None
        assert pair[0] is req
        assert pair[1] is None


class TestHTTPHistorySearch:
    def test_search_by_url_substr_returns_only_matching_entries(self) -> None:
        history = HTTPHistory()
        history.record(_request("r1", url="https://one.test"))
        history.record(_request("r2", url="https://two.test"))
        results = history.search(url_substr="one")
        assert len(results) == 1
        assert results[0][0].id == "r1"

    def test_search_by_url_substr_no_match_returns_empty_list(self) -> None:
        history = HTTPHistory()
        history.record(_request("r1", url="https://one.test"))
        results = history.search(url_substr="nomatch")
        assert results == []

    def test_search_by_method_case_insensitive_match(self) -> None:
        history = HTTPHistory()
        history.record(_request("r1", method="GET"))
        history.record(_request("r2", method="post"))
        get_results = history.search(method="get")
        post_results = history.search(method="POST")
        assert len(get_results) == 1
        assert get_results[0][0].id == "r1"
        assert len(post_results) == 1
        assert post_results[0][0].id == "r2"

    def test_search_by_tag_returns_only_tagged_entries(self) -> None:
        history = HTTPHistory()
        history.record(_request("r1", tag="sqli"))
        history.record(_request("r2", tag=""))
        results = history.search(tag="sqli")
        assert len(results) == 1
        assert results[0][0].id == "r1"

    def test_search_by_status_skips_none_response_and_wrong_status(self) -> None:
        history = HTTPHistory()
        req1 = _request("r1")
        req2 = _request("r2")
        req3 = _request("r3")
        history.record(req1, _response("r1", status=200))
        history.record(req2)
        history.record(req3, _response("r3", status=500))
        results = history.search(status=200)
        assert len(results) == 1
        assert results[0][0].id == "r1"

    def test_search_combined_filters_returns_matching_entry(self) -> None:
        history = HTTPHistory()
        history.record(
            _request("r1", url="https://target.test", method="POST", tag="enum"),
            _response("r1", status=200),
        )
        history.record(
            _request("r2", url="https://other.test", method="GET", tag=""),
            _response("r2", status=404),
        )
        results = history.search(url_substr="target", method="POST", tag="enum", status=200)
        assert len(results) == 1
        assert results[0][0].id == "r1"

    def test_search_combined_filters_no_match_returns_empty(self) -> None:
        history = HTTPHistory()
        history.record(
            _request("r1", url="https://target.test", method="POST"), _response("r1", status=200)
        )
        results = history.search(url_substr="target", method="POST", status=404)
        assert results == []

    def test_search_no_filters_returns_all_entries(self) -> None:
        history = HTTPHistory()
        history.record(_request("r1"))
        history.record(_request("r2"))
        history.record(_request("r3"))
        results = history.search()
        assert len(results) == 3


class TestHTTPHistoryDump:
    def test_dump_returns_list_of_dicts_with_request_and_response(self) -> None:
        history = HTTPHistory()
        req = _request("r1")
        resp = _response("r1")
        history.record(req, resp)
        dumped = history.dump()
        assert len(dumped) == 1
        assert dumped[0]["request"] == req.to_dict()
        assert dumped[0]["response"] == resp.to_dict()

    def test_dump_response_none_entry_has_none_in_dict(self) -> None:
        history = HTTPHistory()
        req = _request("r1")
        history.record(req)
        dumped = history.dump()
        assert dumped[0]["response"] is None

    def test_dump_mixed_entries_both_arms_of_ternary(self) -> None:
        history = HTTPHistory()
        req1 = _request("r1")
        resp1 = _response("r1")
        req2 = _request("r2")
        history.record(req1, resp1)
        history.record(req2)
        dumped = history.dump()
        assert dumped[0]["response"] is not None
        assert dumped[1]["response"] is None


class TestHTTPHistoryFromDump:
    def test_from_dump_round_trip_restores_request_and_response(self) -> None:
        history1 = HTTPHistory()
        req = _request("r1")
        resp = _response("r1")
        history1.record(req, resp)
        payload = history1.dump()
        history2 = HTTPHistory.from_dump(payload)
        assert len(history2) == 1
        pair = history2.get_by_id("r1")
        assert pair is not None
        restored_req, restored_resp = pair
        assert restored_req.id == "r1"
        assert isinstance(restored_req.body, bytes)
        assert restored_resp is not None
        assert restored_resp.status == 200

    def test_from_dump_response_none_entry_stays_none(self) -> None:
        history1 = HTTPHistory()
        req = _request("r1")
        history1.record(req)
        payload = history1.dump()
        history2 = HTTPHistory.from_dump(payload)
        pair = history2.get_by_id("r1")
        assert pair is not None
        assert pair[1] is None

    def test_from_dump_missing_tag_defaults_to_empty_string(self) -> None:
        payload = [
            {
                "request": {
                    "id": "r1",
                    "method": "GET",
                    "url": "https://x",
                    "headers": {},
                    "body": "",
                    "timestamp": 1.0,
                },
                "response": None,
            }
        ]
        history = HTTPHistory.from_dump(payload)
        pair = history.get_by_id("r1")
        assert pair is not None
        assert pair[0].tag == ""

    def test_from_dump_malformed_entry_raises_value_error_with_message(self) -> None:
        payload: list[dict[str, Any]] = [{"request": {"id": "x"}}]
        with pytest.raises(ValueError, match="Malformed history entry: missing key"):
            HTTPHistory.from_dump(payload)

    def test_from_dump_tag_is_preserved_on_round_trip(self) -> None:
        history1 = HTTPHistory()
        req = HTTPRequest(
            id="r1",
            method="GET",
            url="https://x",
            headers={},
            body=b"",
            timestamp=1.0,
            tag="scanner",
        )
        history1.record(req)
        payload = history1.dump()
        history2 = HTTPHistory.from_dump(payload)
        pair = history2.get_by_id("r1")
        assert pair is not None
        assert pair[0].tag == "scanner"


class TestHTTPSessionRequest:
    async def test_request_happy_path_with_mock_transport(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(201, headers={"content-type": "text/plain"}, content=b"hello")

        transport = httpx.MockTransport(handler)
        real_async_client = httpx.AsyncClient

        def patched(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return real_async_client(*args, **kwargs)

        with patch("decepticon.tools.web.http.httpx.AsyncClient", side_effect=patched):
            session = HTTPSession(base_url="https://api.test")
            try:
                resp = await session.request("get", "/users", tag="enum")
                assert resp.status == 201
                assert resp.body == b"hello"
                assert len(session.history) == 1
                pair = session.history.get_by_id(resp.request_id)
                assert pair is not None
                req_recorded = pair[0]
                assert req_recorded.method == "GET"
                assert req_recorded.url == "https://api.test/users"
                assert req_recorded.tag == "enum"
                assert isinstance(resp.elapsed_ms, float)
                assert resp.elapsed_ms >= 0
            finally:
                await session.close()

    async def test_request_absolute_url_not_prepended_with_base_url(self) -> None:
        seen_urls: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_urls.append(str(request.url))
            return httpx.Response(200, content=b"ok")

        transport = httpx.MockTransport(handler)
        real_async_client = httpx.AsyncClient

        def patched(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return real_async_client(*args, **kwargs)

        with patch("decepticon.tools.web.http.httpx.AsyncClient", side_effect=patched):
            session = HTTPSession(base_url="https://api.test")
            try:
                await session.request("GET", "https://other.test/x")
                pair = list(session.history)[0]
                assert pair[0].url == "https://other.test/x"
            finally:
                await session.close()

    async def test_request_body_encoding_json_body(self) -> None:
        received_body: list[bytes] = []

        def handler(request: httpx.Request) -> httpx.Response:
            received_body.append(request.content)
            return httpx.Response(200, content=b"ok")

        transport = httpx.MockTransport(handler)
        real_async_client = httpx.AsyncClient

        def patched(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return real_async_client(*args, **kwargs)

        with patch("decepticon.tools.web.http.httpx.AsyncClient", side_effect=patched):
            session = HTTPSession()
            try:
                await session.request("POST", "https://x.test/ep", json_body={"a": 1})
                pair = list(session.history)[0]
                assert pair[0].body == json.dumps({"a": 1}).encode()
                assert received_body[0] == json.dumps({"a": 1}).encode()
            finally:
                await session.close()

    async def test_request_body_encoding_str_body(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"ok")

        transport = httpx.MockTransport(handler)
        real_async_client = httpx.AsyncClient

        def patched(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return real_async_client(*args, **kwargs)

        with patch("decepticon.tools.web.http.httpx.AsyncClient", side_effect=patched):
            session = HTTPSession()
            try:
                await session.request("POST", "https://x.test/ep", body="raw")
                pair = list(session.history)[0]
                assert pair[0].body == b"raw"
            finally:
                await session.close()

    async def test_request_body_encoding_bytes_body(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"ok")

        transport = httpx.MockTransport(handler)
        real_async_client = httpx.AsyncClient

        def patched(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return real_async_client(*args, **kwargs)

        with patch("decepticon.tools.web.http.httpx.AsyncClient", side_effect=patched):
            session = HTTPSession()
            try:
                await session.request("POST", "https://x.test/ep", body=b"\x00\x01")
                pair = list(session.history)[0]
                assert pair[0].body == b"\x00\x01"
            finally:
                await session.close()

    async def test_request_body_encoding_bytearray_body(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"ok")

        transport = httpx.MockTransport(handler)
        real_async_client = httpx.AsyncClient

        def patched(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return real_async_client(*args, **kwargs)

        with patch("decepticon.tools.web.http.httpx.AsyncClient", side_effect=patched):
            session = HTTPSession()
            try:
                await session.request("POST", "https://x.test/ep", body=bytearray(b"xy"))
                pair = list(session.history)[0]
                assert pair[0].body == b"xy"
            finally:
                await session.close()

    async def test_request_no_body_stores_empty_bytes(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"ok")

        transport = httpx.MockTransport(handler)
        real_async_client = httpx.AsyncClient

        def patched(*args: Any, **kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return real_async_client(*args, **kwargs)

        with patch("decepticon.tools.web.http.httpx.AsyncClient", side_effect=patched):
            session = HTTPSession()
            try:
                await session.request("GET", "https://x.test/ep")
                pair = list(session.history)[0]
                assert pair[0].body == b""
            finally:
                await session.close()


class TestHTTPSessionVerbDelegation:
    async def test_get_delegates_to_request_with_get_method(self) -> None:
        session = HTTPSession()
        session.request = AsyncMock(return_value=_response("r1"))
        result = await session.get("https://x.test/")
        session.request.assert_awaited_once_with("GET", "https://x.test/")
        assert result is session.request.return_value

    async def test_post_delegates_to_request_with_post_method(self) -> None:
        session = HTTPSession()
        session.request = AsyncMock(return_value=_response("r1"))
        result = await session.post("https://x.test/")
        session.request.assert_awaited_once_with("POST", "https://x.test/")
        assert result is session.request.return_value

    async def test_put_delegates_to_request_with_put_method(self) -> None:
        session = HTTPSession()
        session.request = AsyncMock(return_value=_response("r1"))
        result = await session.put("https://x.test/")
        session.request.assert_awaited_once_with("PUT", "https://x.test/")
        assert result is session.request.return_value

    async def test_delete_delegates_to_request_with_delete_method(self) -> None:
        session = HTTPSession()
        session.request = AsyncMock(return_value=_response("r1"))
        result = await session.delete("https://x.test/")
        session.request.assert_awaited_once_with("DELETE", "https://x.test/")
        assert result is session.request.return_value


class TestHTTPSessionContextManager:
    async def test_context_manager_returns_session_and_calls_close_on_exit(self) -> None:
        session = HTTPSession()
        close_mock = AsyncMock()
        session.close = close_mock
        async with session as s:
            assert s is session
        close_mock.assert_awaited_once()


class TestDiffResponses:
    def _make_resp(self, request_id: str, status: int, body: bytes) -> HTTPResponse:
        return HTTPResponse(
            id=f"id-{request_id}",
            request_id=request_id,
            status=status,
            headers={},
            body=body,
            elapsed_ms=1.0,
            timestamp=1.0,
        )

    def test_diff_responses_shows_changed_line_in_unified_diff(self) -> None:
        a = self._make_resp("req-a", 200, b"line1\nline2\nline3")
        b = self._make_resp("req-b", 200, b"line1\nCHANGED\nline3")
        result = diff_responses(a, b)
        assert "-line2" in result
        assert "+CHANGED" in result
        assert "req-a" in result
        assert "(200)" in result

    def test_diff_responses_fromfile_tofile_headers_include_request_id_and_status(self) -> None:
        a = self._make_resp("req-a", 404, b"not found")
        b = self._make_resp("req-b", 200, b"found")
        result = diff_responses(a, b)
        assert "req-a (404)" in result
        assert "req-b (200)" in result

    def test_diff_responses_identical_bodies_returns_empty_string(self) -> None:
        a = self._make_resp("req-a", 200, b"same\nlines")
        result = diff_responses(a, a)
        assert result == ""

    def test_diff_responses_context_kwarg_reduces_context_lines(self) -> None:
        body_a = b"ctx1\nctx2\nctx3\nCHANGED_A\nctx4\nctx5\nctx6"
        body_b = b"ctx1\nctx2\nctx3\nCHANGED_B\nctx4\nctx5\nctx6"
        a = self._make_resp("req-a", 200, body_a)
        b = self._make_resp("req-b", 200, body_b)
        default_diff = diff_responses(a, b)
        small_context_diff = diff_responses(a, b, context=1)
        assert len(small_context_diff) < len(default_diff)

    def test_diff_responses_non_utf8_body_decoded_with_errors_replace(self) -> None:
        a = self._make_resp("req-a", 200, b"\xff\xfe data")
        b = self._make_resp("req-b", 200, b"clean data")
        result = diff_responses(a, b)
        assert isinstance(result, str)

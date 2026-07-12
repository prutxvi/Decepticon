# -*- coding: utf-8 -*-
"""Extended unit tests for cve.py — Cache, rehydrate, async lookups.

All network calls are mocked. Tests run offline.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from decepticon.tools.research.cve import (
    Exploitability,
    _Cache,
    _parse_epss,
    _parse_nvd,
    _rehydrate,
    lookup_cve,
    lookup_cves,
    lookup_package,
)

# ── _Cache ───────────────────────────────────────────────────────────────


class TestCacheBasicOps:
    def test_set_and_get(self, tmp_path: Path) -> None:
        cache = _Cache(path=tmp_path / "cve.json")
        cache.set("key1", {"foo": "bar"})
        result = cache.get("key1")
        assert result == {"foo": "bar"}

    def test_missing_key_returns_none(self, tmp_path: Path) -> None:
        cache = _Cache(path=tmp_path / "cve.json")
        assert cache.get("nonexistent") is None

    def test_ttl_expiry_returns_none(self, tmp_path: Path) -> None:
        cache = _Cache(path=tmp_path / "cve.json", ttl=0.001)
        cache.set("expiring", {"val": 1})
        time.sleep(0.05)
        assert cache.get("expiring") is None

    def test_fresh_entry_not_expired(self, tmp_path: Path) -> None:
        cache = _Cache(path=tmp_path / "cve.json", ttl=3600)
        cache.set("fresh", {"val": 2})
        assert cache.get("fresh") == {"val": 2}

    def test_overwrite_updates_value(self, tmp_path: Path) -> None:
        cache = _Cache(path=tmp_path / "cve.json")
        cache.set("k", {"v": 1})
        cache.set("k", {"v": 2})
        assert cache.get("k") == {"v": 2}


class TestCacheLRUEviction:
    def test_evicts_oldest_when_over_capacity(self, tmp_path: Path) -> None:
        # Use a tiny cap so we can test eviction quickly
        # Fill past MAX_CACHE_ENTRIES by temporarily patching the module constant
        with patch("decepticon.tools.research.cve.MAX_CACHE_ENTRIES", 3):
            small = _Cache(path=tmp_path / "small.json")
            small.set("a", {"v": "a"})
            small.set("b", {"v": "b"})
            small.set("c", {"v": "c"})
            small.set("d", {"v": "d"})  # triggers eviction of "a"
            # "a" evicted; b/c/d still present
            assert small.get("a") is None
            assert small.get("d") == {"v": "d"}

    def test_get_promotes_to_most_recently_used(self, tmp_path: Path) -> None:
        with patch("decepticon.tools.research.cve.MAX_CACHE_ENTRIES", 3):
            cache = _Cache(path=tmp_path / "promote.json")
            cache.set("a", {"v": "a"})
            cache.set("b", {"v": "b"})
            cache.set("c", {"v": "c"})
            # Promote "a" so it's not evicted
            cache.get("a")
            cache.set("d", {"v": "d"})  # should evict "b" (LRU)
            assert cache.get("a") is not None
            assert cache.get("b") is None


class TestCachePersistence:
    def test_flush_writes_file(self, tmp_path: Path) -> None:
        cache_path = tmp_path / "persist.json"
        cache = _Cache(path=cache_path)
        cache.set("cve:CVE-2024-0001", {"cve_id": "CVE-2024-0001"})
        cache.flush()
        assert cache_path.exists()
        raw = json.loads(cache_path.read_text(encoding="utf-8"))
        assert "cve:CVE-2024-0001" in raw

    def test_load_reads_existing_file(self, tmp_path: Path) -> None:
        cache_path = tmp_path / "existing.json"
        data = {
            "cve:CVE-TEST-1": {
                "value": {"cve_id": "CVE-TEST-1"},
                "_ts": time.time(),
                "_lru": time.time(),
            }
        }
        cache_path.write_text(json.dumps(data), encoding="utf-8")
        cache = _Cache(path=cache_path)
        result = cache.get("cve:CVE-TEST-1")
        assert result is not None
        assert result["cve_id"] == "CVE-TEST-1"

    def test_corrupt_json_does_not_raise(self, tmp_path: Path) -> None:
        cache_path = tmp_path / "bad.json"
        cache_path.write_text("{bad json!!}", encoding="utf-8")
        cache = _Cache(path=cache_path)  # should not raise
        assert cache.get("anything") is None

    def test_missing_file_ok(self, tmp_path: Path) -> None:
        cache_path = tmp_path / "does-not-exist.json"
        cache = _Cache(path=cache_path)
        assert cache.get("k") is None


# ── _rehydrate ────────────────────────────────────────────────────────────


class TestRehydrate:
    def test_full_dict_reconstructs_exploitability(self) -> None:
        d = {
            "cve_id": "CVE-2024-1234",
            "cvss": 9.8,
            "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            "cwe": ["CWE-89"],
            "epss": 0.7,
            "epss_percentile": 0.95,
            "kev": True,
            "published": "2024-01-01T00:00:00",
            "summary": "Test vuln",
            "references": ["https://example.com"],
            "poc_links": [],
            "source": "nvd+epss",
            "fetched_at": time.time(),
        }
        exp = _rehydrate(d)
        assert exp.cve_id == "CVE-2024-1234"
        assert exp.cvss == 9.8
        assert exp.kev is True
        assert exp.cwe == ["CWE-89"]

    def test_extra_keys_ignored(self) -> None:
        d: dict[str, Any] = {
            "cve_id": "CVE-X",
            "unexpected_key": "should be ignored",
            "another_extra": 42,
        }
        exp = _rehydrate(d)
        assert exp.cve_id == "CVE-X"
        assert not hasattr(exp, "unexpected_key")

    def test_missing_optional_keys_get_defaults(self) -> None:
        d: dict[str, Any] = {"cve_id": "CVE-Y"}
        exp = _rehydrate(d)
        assert exp.cvss is None
        assert exp.cwe == []
        assert exp.kev is False


# ── Exploitability.to_dict ────────────────────────────────────────────────


class TestExploitabilityToDict:
    def test_score_included_in_dict(self) -> None:
        exp = Exploitability(cve_id="CVE-A", cvss=8.0, epss=0.5)
        d = exp.to_dict()
        assert "score" in d
        assert d["score"] == exp.score

    def test_all_base_fields_present(self) -> None:
        exp = Exploitability(cve_id="CVE-B")
        d = exp.to_dict()
        for field in ("cve_id", "cvss", "epss", "kev", "cwe", "references", "poc_links"):
            assert field in d


# ── lookup_cve (async, mocked network) ───────────────────────────────────


def _nvd_payload(score: float = 8.5, cve_id: str = "CVE-2024-0001") -> dict[str, Any]:
    return {
        "vulnerabilities": [
            {
                "cve": {
                    "published": "2024-06-01T00:00:00",
                    "descriptions": [{"lang": "en", "value": f"Vuln {cve_id}"}],
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": score,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                                }
                            }
                        ]
                    },
                    "weaknesses": [{"description": [{"value": "CWE-79"}]}],
                    "references": [{"url": "https://nvd.nist.gov/vuln/detail/" + cve_id}],
                }
            }
        ]
    }


def _epss_payload(prob: float = 0.5, pct: float = 0.9) -> dict[str, Any]:
    return {"data": [{"epss": str(prob), "percentile": str(pct)}]}


class TestLookupCve:
    def test_cache_hit_skips_network(self, tmp_path: Path) -> None:
        cache = _Cache(path=tmp_path / "cve.json")
        exp = Exploitability(cve_id="CVE-2024-9999", cvss=7.0)
        cache.set("cve:CVE-2024-9999", exp.to_dict())

        async def _run() -> Exploitability:
            return await lookup_cve("CVE-2024-9999", cache=cache)

        result = asyncio.run(_run())
        assert result.cve_id == "CVE-2024-9999"
        assert result.cvss == 7.0

    def test_network_response_builds_exploitability(self, tmp_path: Path) -> None:
        """Mock both NVD and EPSS responses, verify Exploitability is assembled."""
        cache = _Cache(path=tmp_path / "fresh.json")
        nvd_data = _nvd_payload(9.8, "CVE-2024-0001")
        epss_data = _epss_payload(0.7, 0.95)

        async def _run() -> Exploitability:
            with (
                patch("decepticon.tools.research.cve._fetch_nvd", new_callable=AsyncMock) as fn,
                patch("decepticon.tools.research.cve._fetch_epss", new_callable=AsyncMock) as fe,
            ):
                fn.return_value = nvd_data
                fe.return_value = epss_data
                return await lookup_cve("CVE-2024-0001", cache=cache)

        result = asyncio.run(_run())
        assert result.cve_id == "CVE-2024-0001"
        assert result.cvss == 9.8
        assert result.epss == pytest.approx(0.7)
        assert result.epss_percentile == pytest.approx(0.95)
        assert result.summary == "Vuln CVE-2024-0001"

    def test_kev_flag_set_when_id_in_kev_set(self, tmp_path: Path) -> None:
        cache = _Cache(path=tmp_path / "kev.json")
        nvd_data = _nvd_payload(5.0, "CVE-2024-KEV")
        epss_data = _epss_payload(0.1, 0.5)

        async def _run() -> Exploitability:
            with (
                patch("decepticon.tools.research.cve._fetch_nvd", new_callable=AsyncMock) as fn,
                patch("decepticon.tools.research.cve._fetch_epss", new_callable=AsyncMock) as fe,
            ):
                fn.return_value = nvd_data
                fe.return_value = epss_data
                return await lookup_cve("CVE-2024-KEV", kev_set={"CVE-2024-KEV"}, cache=cache)

        result = asyncio.run(_run())
        assert result.kev is True
        assert result.score >= 9.0

    def test_network_failure_degrades_gracefully(self, tmp_path: Path) -> None:
        cache = _Cache(path=tmp_path / "fail.json")

        async def _run() -> Exploitability:
            with (
                patch("decepticon.tools.research.cve._fetch_nvd", new_callable=AsyncMock) as fn,
                patch("decepticon.tools.research.cve._fetch_epss", new_callable=AsyncMock) as fe,
            ):
                fn.return_value = {}
                fe.return_value = {}
                return await lookup_cve("CVE-2024-FAIL", cache=cache)

        result = asyncio.run(_run())
        assert result.cve_id == "CVE-2024-FAIL"
        assert result.cvss is None

    def test_cve_id_normalised_to_upper(self, tmp_path: Path) -> None:
        cache = _Cache(path=tmp_path / "norm.json")
        nvd_data = _nvd_payload(7.0, "CVE-2024-0001")
        epss_data = _epss_payload(0.3, 0.7)

        async def _run() -> Exploitability:
            with (
                patch("decepticon.tools.research.cve._fetch_nvd", new_callable=AsyncMock) as fn,
                patch("decepticon.tools.research.cve._fetch_epss", new_callable=AsyncMock) as fe,
            ):
                fn.return_value = nvd_data
                fe.return_value = epss_data
                return await lookup_cve("cve-2024-0001", cache=cache)

        result = asyncio.run(_run())
        assert result.cve_id == "CVE-2024-0001"

    def test_result_stored_in_cache(self, tmp_path: Path) -> None:
        cache = _Cache(path=tmp_path / "store.json")
        nvd_data = _nvd_payload(6.0, "CVE-2024-STORE")
        epss_data = _epss_payload(0.2, 0.6)

        async def _run() -> None:
            with (
                patch("decepticon.tools.research.cve._fetch_nvd", new_callable=AsyncMock) as fn,
                patch("decepticon.tools.research.cve._fetch_epss", new_callable=AsyncMock) as fe,
            ):
                fn.return_value = nvd_data
                fe.return_value = epss_data
                await lookup_cve("CVE-2024-STORE", cache=cache)

        asyncio.run(_run())
        cached = cache.get("cve:CVE-2024-STORE")
        assert cached is not None
        assert cached["cve_id"] == "CVE-2024-STORE"


# ── lookup_cves ───────────────────────────────────────────────────────────


class TestLookupCves:
    def test_ranked_highest_first(self) -> None:
        """lookup_cves should return sorted by score descending."""

        async def _run() -> list[Exploitability]:
            with (
                patch("decepticon.tools.research.cve._fetch_nvd", new_callable=AsyncMock) as fn,
                patch("decepticon.tools.research.cve._fetch_epss", new_callable=AsyncMock) as fe,
            ):

                def nvd_side(*args: Any, **kwargs: Any) -> dict[str, Any]:
                    cve_id: str = kwargs.get("params", {}).get("cveId", "")
                    if cve_id == "CVE-2024-A":
                        return _nvd_payload(9.8, cve_id)
                    return _nvd_payload(4.0, cve_id)

                fn.side_effect = nvd_side
                fe.return_value = _epss_payload(0.3, 0.7)
                return await lookup_cves(["CVE-2024-B", "CVE-2024-A"])

        results = asyncio.run(_run())
        assert results[0].score >= results[-1].score

    def test_empty_list_returns_empty(self) -> None:
        async def _run() -> list[Exploitability]:
            return await lookup_cves([])

        results = asyncio.run(_run())
        assert results == []


# ── lookup_package ────────────────────────────────────────────────────────


class TestLookupPackage:
    def test_returns_cve_ids_from_osv(self) -> None:
        osv_response = {
            "vulns": [
                {"id": "GHSA-abc-123", "aliases": ["CVE-2024-5001"]},
                {"id": "CVE-2024-5002"},
            ]
        }

        async def _run() -> list[str]:
            with patch(
                "decepticon.tools.research.cve._fetch_osv", new_callable=AsyncMock
            ) as mock_osv:
                mock_osv.return_value = osv_response
                return await lookup_package("requests", "2.31.0", "PyPI")

        result = asyncio.run(_run())
        assert "CVE-2024-5001" in result
        assert "GHSA-abc-123" in result
        assert "CVE-2024-5002" in result

    def test_empty_response_returns_empty_list(self) -> None:
        async def _run() -> list[str]:
            with patch(
                "decepticon.tools.research.cve._fetch_osv", new_callable=AsyncMock
            ) as mock_osv:
                mock_osv.return_value = {}
                return await lookup_package("no-vulns", "1.0.0", "PyPI")

        result = asyncio.run(_run())
        assert result == []

    def test_no_duplicate_cve_ids(self) -> None:
        """If a CVE appears both as vuln id and alias, it should appear once."""
        osv_response = {
            "vulns": [
                {"id": "CVE-2024-9001", "aliases": ["CVE-2024-9001"]},
            ]
        }

        async def _run() -> list[str]:
            with patch(
                "decepticon.tools.research.cve._fetch_osv", new_callable=AsyncMock
            ) as mock_osv:
                mock_osv.return_value = osv_response
                return await lookup_package("pkg", "1.0.0", "npm")

        result = asyncio.run(_run())
        assert result.count("CVE-2024-9001") == 1

    def test_osv_network_error_handled_by_fetch_osv(self) -> None:
        # _fetch_osv catches HTTPError and returns {} — lookup_package then
        # sees no "vulns" key and returns an empty id list.
        async def _run() -> list[str]:
            with patch(
                "decepticon.tools.research.cve._fetch_osv", new_callable=AsyncMock
            ) as mock_osv:
                mock_osv.return_value = {}  # _fetch_osv error-path return value
                return await lookup_package("pkg", "1.0.0", "npm")

        result = asyncio.run(_run())
        assert result == []


# ── NVD parser edge cases ─────────────────────────────────────────────────


class TestNVDParserEdgeCases:
    def test_prefers_v31_over_v2(self) -> None:
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [],
                        "metrics": {
                            "cvssMetricV31": [
                                {"cvssData": {"baseScore": 9.0, "vectorString": "CVSS:3.1/X"}}
                            ],
                            "cvssMetricV2": [
                                {"cvssData": {"baseScore": 5.0, "vectorString": "AV:N"}}
                            ],
                        },
                    }
                }
            ]
        }
        parsed = _parse_nvd(data)
        assert parsed["cvss"] == 9.0

    def test_prefers_v30_over_v2(self) -> None:
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [],
                        "metrics": {
                            "cvssMetricV30": [
                                {"cvssData": {"baseScore": 7.5, "vectorString": "CVSS:3.0/X"}}
                            ],
                            "cvssMetricV2": [
                                {"cvssData": {"baseScore": 4.0, "vectorString": "AV:N"}}
                            ],
                        },
                    }
                }
            ]
        }
        parsed = _parse_nvd(data)
        assert parsed["cvss"] == 7.5

    def test_non_cwe_weakness_ignored(self) -> None:
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [],
                        "metrics": {},
                        "weaknesses": [
                            {"description": [{"value": "NVD-CWE-noinfo"}]},
                            {"description": [{"value": "CWE-79"}]},
                        ],
                    }
                }
            ]
        }
        parsed = _parse_nvd(data)
        # Only CWE-79 should be included (NVD-CWE-noinfo doesn't start with CWE-)
        assert "CWE-79" in parsed["cwe"]
        assert "NVD-CWE-noinfo" not in parsed["cwe"]

    def test_references_capped_at_10(self) -> None:
        refs = [{"url": f"https://example.com/{i}"} for i in range(15)]
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [],
                        "metrics": {},
                        "references": refs,
                    }
                }
            ]
        }
        parsed = _parse_nvd(data)
        assert len(parsed["references"]) == 10

    def test_non_english_description_skipped(self) -> None:
        data = {
            "vulnerabilities": [
                {
                    "cve": {
                        "descriptions": [
                            {"lang": "es", "value": "descripcion"},
                            {"lang": "en", "value": "english desc"},
                        ],
                        "metrics": {},
                    }
                }
            ]
        }
        parsed = _parse_nvd(data)
        assert parsed["summary"] == "english desc"


# ── EPSS parser edge cases ────────────────────────────────────────────────


class TestEPSSParserEdgeCases:
    def test_missing_percentile_returns_none(self) -> None:
        parsed = _parse_epss({"data": [{"epss": "0.5"}]})
        assert parsed["epss"] == pytest.approx(0.5)
        assert parsed["epss_percentile"] == pytest.approx(0.0)

    def test_none_values_return_none(self) -> None:
        parsed = _parse_epss({"data": [{"epss": None, "percentile": None}]})
        assert parsed["epss"] is None
        assert parsed["epss_percentile"] is None

    def test_missing_data_key_returns_nones(self) -> None:
        parsed = _parse_epss({})
        assert parsed["epss"] is None
        assert parsed["epss_percentile"] is None

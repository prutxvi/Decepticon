# -*- coding: utf-8 -*-
"""Unit tests for :class:`KGStore` — driver-free.

Covers: input validation (engagement label, label / rel-type vocabulary,
mandatory ``key`` field), provenance auto-injection, observation
flattening, and the Cypher shapes produced by ``record_observations``.

Integration tests against a live Neo4j (compose) live in
``tests/integration/kg/``.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest

from decepticon.middleware.kg_internal.store import (
    KGStore,
    KGStoreConfig,
    KGStoreConfigError,
    _flatten_props,
    _safe_label,
    _safe_rel_type,
)

# ── KGStoreConfig.from_env ──────────────────────────────────────────────


def test_config_from_env_full(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECEPTICON_NEO4J_URI", "bolt://neo4j:7687")
    monkeypatch.setenv("DECEPTICON_NEO4J_USER", "neo4j")
    monkeypatch.setenv("DECEPTICON_NEO4J_PASSWORD", "secret")
    monkeypatch.setenv("DECEPTICON_NEO4J_DATABASE", "decepticon")
    cfg = KGStoreConfig.from_env()
    assert cfg.uri == "bolt://neo4j:7687"
    assert cfg.user == "neo4j"
    assert cfg.password == "secret"
    assert cfg.database == "decepticon"


def test_config_from_env_default_database(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DECEPTICON_NEO4J_URI", "bolt://x")
    monkeypatch.setenv("DECEPTICON_NEO4J_USER", "u")
    monkeypatch.setenv("DECEPTICON_NEO4J_PASSWORD", "p")
    monkeypatch.delenv("DECEPTICON_NEO4J_DATABASE", raising=False)
    cfg = KGStoreConfig.from_env()
    assert cfg.database == "neo4j"


def test_config_from_env_missing_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    for var in ("DECEPTICON_NEO4J_URI", "DECEPTICON_NEO4J_USER", "DECEPTICON_NEO4J_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(KGStoreConfigError) as exc:
        KGStoreConfig.from_env()
    assert "DECEPTICON_NEO4J_URI" in str(exc.value)
    assert "DECEPTICON_NEO4J_USER" in str(exc.value)
    assert "DECEPTICON_NEO4J_PASSWORD" in str(exc.value)


# ── _safe_label / _safe_rel_type ────────────────────────────────────────


@pytest.mark.parametrize(
    "label", ["Host", "Service", "Vulnerability", "URL", "CrownJewel", "AttackPath", "X1"]
)
def test_safe_label_accepts_valid(label: str) -> None:
    assert _safe_label(label) == label


@pytest.mark.parametrize(
    "label",
    [
        "",
        "1Host",  # leading digit
        "host name",  # space
        "Host;DROP",  # injection attempt
        "Host`thing",
        "a" * 65,  # too long
    ],
)
def test_safe_label_rejects_invalid(label: str) -> None:
    with pytest.raises(ValueError, match="invalid node label"):
        _safe_label(label)


@pytest.mark.parametrize("rel_type", ["HOSTS", "HAS_VULN", "EXPLOITS", "STARTS_AT", "STEP", "R1_2"])
def test_safe_rel_type_accepts_valid(rel_type: str) -> None:
    assert _safe_rel_type(rel_type) == rel_type


@pytest.mark.parametrize(
    "rel_type",
    [
        "",
        "lowercase",
        "Host_Service",  # mixed case
        "HAS-VULN",  # hyphen
        "HAS VULN",  # space
        "1HAS",  # leading digit
        "A" * 65,  # too long
    ],
)
def test_safe_rel_type_rejects_invalid(rel_type: str) -> None:
    with pytest.raises(ValueError, match="invalid edge type"):
        _safe_rel_type(rel_type)


# ── _flatten_props ──────────────────────────────────────────────────────


def test_flatten_props_passes_primitives() -> None:
    out = _flatten_props({"ip": "10.0.0.1", "port": 80, "open": True, "score": 7.5, "none": None})
    assert out == {"ip": "10.0.0.1", "port": 80, "open": True, "score": 7.5, "none": None}


def test_flatten_props_passes_primitive_lists() -> None:
    out = _flatten_props({"tags": ["sqli", "ssrf"], "ports": [80, 443]})
    assert out == {"tags": ["sqli", "ssrf"], "ports": [80, 443]}


def test_flatten_props_stringifies_nested_dict() -> None:
    out = _flatten_props({"meta": {"a": 1}})
    assert out["meta"] == '{"a": 1}'


def test_flatten_props_stringifies_list_of_dicts() -> None:
    out = _flatten_props({"refs": [{"url": "x"}]})
    assert out["refs"] == '[{"url": "x"}]'


# ── Construction with fake driver ───────────────────────────────────────


def _fake_driver() -> MagicMock:
    """Mock that mimics neo4j.Driver / Session / Transaction enough for unit tests."""
    driver = MagicMock(name="Driver")
    session = MagicMock(name="Session")
    driver.session.return_value.__enter__.return_value = session
    driver.session.return_value.__exit__.return_value = None
    return driver


def _make_store(driver: Any | None = None) -> KGStore:
    cfg = KGStoreConfig(uri="bolt://x", user="u", password="p", database="neo4j")
    return KGStore(cfg, driver=driver or _fake_driver())


def test_close_swallows_driver_exception() -> None:
    driver = MagicMock()
    driver.close.side_effect = RuntimeError("network blip")
    store = _make_store(driver)
    # Should not raise.
    store.close()


# ── Engagement scope safety ─────────────────────────────────────────────


@pytest.mark.parametrize(
    "engagement",
    ["", None, " ", "-leading-dash", "has space", "has;semi", "has/slash", "a" * 129],
)
def test_engagement_scope_rejects_invalid(engagement: Any) -> None:
    store = _make_store()
    with pytest.raises(ValueError):
        store._check_engagement(engagement)


@pytest.mark.parametrize("engagement", ["acme-q2", "ENG_001", "client.test.42", "a", "A1"])
def test_engagement_scope_accepts_valid(engagement: str) -> None:
    store = _make_store()
    store._check_engagement(engagement)  # must not raise


def test_execute_read_requires_engagement() -> None:
    store = _make_store()
    with pytest.raises(ValueError):
        store.execute_read("MATCH (n) RETURN n", {}, engagement="")


def test_execute_write_requires_engagement() -> None:
    store = _make_store()
    with pytest.raises(ValueError):
        store.execute_write("CREATE (n)", {}, engagement="")


def test_delete_stale_requires_int_cutoff() -> None:
    store = _make_store()
    with pytest.raises(ValueError, match="before_unix must be an int"):
        store.delete_stale(engagement="acme-q2", before_unix=1.5)  # type: ignore[arg-type]


# ── record_observations validation ──────────────────────────────────────


def test_record_observations_rejects_missing_key() -> None:
    store = _make_store()
    with pytest.raises(ValueError, match="missing mandatory 'key'"):
        store.record_observations(
            [{"kind": "Host", "label": "10.0.0.1", "props": {"ip": "10.0.0.1"}}],
            engagement="acme",
            created_by="analyst",
            source_episode_id="tc-1",
        )


def test_record_observations_rejects_bad_label() -> None:
    store = _make_store()
    with pytest.raises(ValueError, match="invalid node label"):
        store.record_observations(
            [{"kind": "lowercase", "key": "x::1", "label": "x"}],
            engagement="acme",
            created_by="analyst",
            source_episode_id="tc-1",
        )


def test_record_observations_requires_created_by() -> None:
    store = _make_store()
    with pytest.raises(ValueError, match="created_by"):
        store.record_observations(
            [{"kind": "Host", "key": "h::1", "label": "1"}],
            engagement="acme",
            created_by="",
            source_episode_id="tc-1",
        )


def test_record_observations_requires_source_episode_id() -> None:
    store = _make_store()
    with pytest.raises(ValueError, match="source_episode_id"):
        store.record_observations(
            [{"kind": "Host", "key": "h::1", "label": "1"}],
            engagement="acme",
            created_by="analyst",
            source_episode_id="",
        )


def test_record_observations_empty_batch_is_noop() -> None:
    # When the observation list is empty, no driver session should be
    # opened beyond the revision() lookup.
    driver = _fake_driver()
    session = driver.session.return_value.__enter__.return_value
    session.execute_read.return_value = [{"rev": 0}]
    store = _make_store(driver)

    result = store.record_observations(
        [],
        engagement="acme",
        created_by="analyst",
        source_episode_id="tc-1",
    )
    assert result == {"created": 0, "merged": 0, "edges": 0, "revision": "rev-acme-0"}


# ── Provenance auto-injection enforcement ───────────────────────────────


def test_record_observations_strips_reserved_provenance_from_props() -> None:
    """The agent cannot forge engagement/firstseen/etc. via the props dict."""
    captured: list[dict[str, Any]] = []
    driver = _fake_driver()
    session = driver.session.return_value.__enter__.return_value

    def fake_write(write_fn):  # type: ignore[no-untyped-def]
        tx = MagicMock()
        # Record both UNWIND batches as they go past.
        results: dict[str, MagicMock] = {}

        def tx_run(query, **params):  # type: ignore[no-untyped-def]
            captured.append(dict(params))
            rec = MagicMock()
            rec.__iter__ = lambda self: iter([("created", 1), ("merged", 0), ("written", 1)])
            rec.__getitem__ = lambda self, k: {"created": 1, "merged": 0, "written": 1}.get(k, 0)
            results[query] = MagicMock()
            results[query].__iter__ = lambda self: iter([rec])
            return results[query]

        tx.run = tx_run
        return write_fn(tx)

    session.execute_write.side_effect = fake_write

    store = _make_store(driver)
    store.record_observations(
        [
            {
                "kind": "Host",
                "key": "host::10.0.0.1",
                "label": "10.0.0.1",
                "props": {
                    "ip": "10.0.0.1",
                    # Agent tries to forge provenance — all must be stripped.
                    "engagement": "MALICIOUS",
                    "firstseen": 0,
                    "lastupdated": 0,
                    "created_by": "spoofed",
                    "source_episode_id": "spoofed",
                },
            }
        ],
        engagement="acme",
        created_by="analyst",
        source_episode_id="tc-real",
    )

    # The rows array we passed into the Cypher MERGE must not contain
    # the reserved fields in its props blob — they have to come from
    # the middleware-supplied named params instead.
    assert captured, "expected at least one tx.run call"
    for params in captured:
        rows = params.get("rows", [])
        for row in rows:
            row_props = row.get("props", {})
            assert "engagement" not in row_props
            assert "firstseen" not in row_props
            assert "lastupdated" not in row_props
            assert "created_by" not in row_props
            assert "source_episode_id" not in row_props
        # The trusted provenance is bound separately as named params.
        assert params.get("engagement") == "acme"
        assert params.get("created_by") == "analyst"
        assert params.get("source_episode_id") == "tc-real"
        assert isinstance(params.get("now"), int)

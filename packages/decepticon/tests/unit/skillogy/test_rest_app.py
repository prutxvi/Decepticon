"""Tests for the FastAPI REST app."""

from __future__ import annotations

import pytest

from decepticon.skillogy.server.app import build_app
from decepticon.skillogy.server.registry import SkillRegistry

_BODY = """---
name: t1
description: a test skill
metadata:
  subdomain: test
  tags: alpha, beta
  mitre_attack: T1190
---

# Body
"""


@pytest.fixture()
def client():
    pytest.importorskip("fastapi")
    pytest.importorskip("httpx")
    from fastapi.testclient import TestClient  # noqa: PLC0415

    reg = SkillRegistry()
    reg.ingest("/skills/t/SKILL.md", _BODY)
    return TestClient(build_app(reg))


def test_health(client):
    r = client.get("/v1/health")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "ok"
    assert data["skill_count"] == 1
    assert data["uptime_seconds"] >= 0


def test_list_returns_paginated_skills(client):
    r = client.post(
        "/v1/skills:list",
        json={"page_size": 10},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["total_count"] == 1
    assert len(data["skills"]) == 1
    assert data["skills"][0]["name"] == "t1"


def test_list_filters_by_mitre(client):
    r = client.post("/v1/skills:list", json={"mitre_filter": ["T1190"]})
    assert r.status_code == 200
    assert r.json()["total_count"] == 1
    r = client.post("/v1/skills:list", json={"mitre_filter": ["T9999"]})
    assert r.status_code == 200
    assert r.json()["total_count"] == 0


def test_load_returns_body(client):
    r = client.post("/v1/skills:load", json={"path": "/skills/t/SKILL.md"})
    assert r.status_code == 200
    skill = r.json()["skill"]
    assert "# Body" in skill["body"]
    assert skill["meta"]["subdomain"] == "test"


def test_load_404_on_missing(client):
    r = client.post("/v1/skills:load", json={"path": "/skills/nope"})
    assert r.status_code == 404


def test_ingest_creates_then_idempotent(client):
    body = "---\nname: ingested\ndescription: x\n---\nhello"
    r1 = client.post("/v1/skills:ingest", json={"path": "/skills/new", "body": body})
    assert r1.status_code == 200
    assert r1.json()["created"] is True
    r2 = client.post("/v1/skills:ingest", json={"path": "/skills/new", "body": body})
    assert r2.status_code == 200
    assert r2.json()["created"] is False
    r3 = client.post(
        "/v1/skills:ingest",
        json={"path": "/skills/new", "body": body + "\n## More"},
    )
    assert r3.json()["created"] is True


def test_openapi_schema_is_generated(client):
    r = client.get("/openapi.json")
    assert r.status_code == 200
    schema = r.json()
    assert schema["info"]["title"] == "Skillogy"
    assert "/v1/health" in schema["paths"]
    assert "/v1/skills:list" in schema["paths"]
    assert "/v1/skills:load" in schema["paths"]
    assert "/v1/skills:ingest" in schema["paths"]

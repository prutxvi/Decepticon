"""Tests for decepticon.skillogy.server.registry."""

from __future__ import annotations

from decepticon.skillogy.proto import SkillListRequest
from decepticon.skillogy.server.registry import (
    SkillRegistry,
    _coerce_list,
    _parse_frontmatter,
)

_BASIC_SKILL = """---
name: kerberoast-roast
description: Use when an SPN-bound account exists in the target domain.
metadata:
  subdomain: active-directory
  tags: kerberos, ad, hash-extraction
  mitre_attack: T1558.003
---

# Kerberoasting

Request TGS for an SPN; extract the encrypted blob; crack offline.
"""


def test_parse_frontmatter_strips_and_returns_meta():
    fm, body = _parse_frontmatter(_BASIC_SKILL)
    assert fm["name"] == "kerberoast-roast"
    assert "Request TGS" in body
    assert "---" not in body[:5]


def test_parse_frontmatter_handles_no_frontmatter():
    fm, body = _parse_frontmatter("# Just a body, no frontmatter\n")
    assert fm == {}
    assert "Just a body" in body


def test_coerce_list_accepts_csv():
    assert _coerce_list("a, b ,c") == ["a", "b", "c"]


def test_coerce_list_accepts_list():
    assert _coerce_list(["x", "y"]) == ["x", "y"]


def test_coerce_list_handles_none():
    assert _coerce_list(None) == []


def test_ingest_populates_meta_from_frontmatter():
    reg = SkillRegistry()
    resp = reg.ingest("/skills/ad/kerb/SKILL.md", _BASIC_SKILL)
    assert resp.created
    assert resp.content_sha256.startswith("sha256:")
    env = reg.load("/skills/ad/kerb/SKILL.md")
    assert env is not None
    assert env.meta.name == "kerberoast-roast"
    assert env.meta.subdomain == "active-directory"
    assert "T1558.003" in env.meta.mitre_attack
    assert "kerberos" in env.meta.tags


def test_ingest_idempotent_on_same_hash():
    reg = SkillRegistry()
    a = reg.ingest("/skills/a", _BASIC_SKILL)
    b = reg.ingest("/skills/a", _BASIC_SKILL)
    assert a.created
    assert not b.created
    assert a.content_sha256 == b.content_sha256


def test_ingest_marks_created_when_body_changes():
    reg = SkillRegistry()
    reg.ingest("/skills/a", _BASIC_SKILL)
    new_body = _BASIC_SKILL + "\n## More content\n"
    second = reg.ingest("/skills/a", new_body)
    assert second.created
    env = reg.load("/skills/a")
    assert env is not None
    assert "## More content" in env.body


def test_list_returns_total_count_and_pages():
    reg = SkillRegistry()
    for i in range(10):
        reg.ingest(f"/skills/n{i}", _BASIC_SKILL)
    resp = reg.list(SkillListRequest(page_size=3))
    assert resp.total_count == 10
    assert len(resp.skills) == 3
    assert resp.next_page_token == "3"


def test_list_filter_by_subdomain():
    reg = SkillRegistry()
    reg.ingest("/skills/ad/x", _BASIC_SKILL)
    other = _BASIC_SKILL.replace("active-directory", "web-recon")
    reg.ingest("/skills/web/y", other)
    resp = reg.list(SkillListRequest(subdomain_filter=["active-directory"]))
    assert resp.total_count == 1
    assert resp.skills[0].subdomain == "active-directory"


def test_list_filter_by_mitre_overlap():
    reg = SkillRegistry()
    reg.ingest("/skills/a", _BASIC_SKILL)
    nodata = _BASIC_SKILL.replace("T1558.003", "T1190")
    reg.ingest("/skills/b", nodata)
    resp = reg.list(SkillListRequest(mitre_filter=["T1190"]))
    assert resp.total_count == 1


def test_list_excludes_safety_critical_when_opted_out():
    reg = SkillRegistry()
    sc_body = """---
name: critical-skill
description: ICS write op
metadata:
  subdomain: ics
  safety_critical: true
---

body
"""
    reg.ingest("/skills/ics/sc", sc_body)
    reg.ingest("/skills/x", _BASIC_SKILL)
    incl = reg.list(SkillListRequest())
    excl = reg.list(SkillListRequest(include_safety_critical=False))
    assert incl.total_count == 2
    assert excl.total_count == 1
    assert not any(s.safety_critical for s in excl.skills)


def test_list_excludes_gated_when_opted_out():
    reg = SkillRegistry()
    gated_body = """---
name: phish-only
description: phishing-only skill
metadata:
  subdomain: phish
  gated_by_conops: phishing_engagement
---

body
"""
    reg.ingest("/skills/phish/p", gated_body)
    reg.ingest("/skills/x", _BASIC_SKILL)
    excl = reg.list(SkillListRequest(include_gated=False))
    assert excl.total_count == 1
    assert all(not s.gated_by_conops for s in excl.skills)


def test_registry_thread_safe_under_concurrent_ingest():
    import threading

    reg = SkillRegistry()

    def _worker(start: int):
        for i in range(start, start + 50):
            reg.ingest(f"/skills/n{i}", _BASIC_SKILL)

    threads = [threading.Thread(target=_worker, args=(i * 50,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(reg) == 200

"""In-memory skill registry — the canonical store behind both transports.

Backed by a dict today; a database-backed implementation (Postgres) is a
drop-in replacement once multi-tenant deployments need persistence
beyond container restart. The registry's public methods are the same in
both cases.
"""

from __future__ import annotations

import hashlib
import logging
import re
import threading
from typing import Iterable

import yaml

from decepticon.skillogy.proto import (
    SkillEnvelope,
    SkillIngestResponse,
    SkillListRequest,
    SkillListResponse,
    SkillMeta,
)

log = logging.getLogger(__name__)


_FRONTMATTER_RE = re.compile(r"^---\s*\n(.*?)\n---\s*\n(.*)\Z", re.DOTALL)


def _parse_frontmatter(body: str) -> tuple[dict, str]:
    """Return (frontmatter_dict, body_without_frontmatter)."""
    match = _FRONTMATTER_RE.match(body)
    if not match:
        return {}, body
    try:
        meta = yaml.safe_load(match.group(1)) or {}
    except yaml.YAMLError as exc:
        log.warning("frontmatter YAML parse failed: %s", exc)
        meta = {}
    return (meta if isinstance(meta, dict) else {}), match.group(2)


def _coerce_list(value) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(v) for v in value]
    if isinstance(value, str):
        return [v.strip() for v in value.split(",") if v.strip()]
    return [str(value)]


def _build_meta(path: str, frontmatter: dict, body_hash: str, size: int) -> SkillMeta:
    meta_block = frontmatter.get("metadata") or {}
    if not isinstance(meta_block, dict):
        meta_block = {}
    return SkillMeta(
        name=str(frontmatter.get("name", "")),
        description=str(frontmatter.get("description", "")),
        subdomain=str(meta_block.get("subdomain", "")),
        tags=_coerce_list(meta_block.get("tags")),
        mitre_attack=_coerce_list(meta_block.get("mitre_attack")),
        path=path,
        content_sha256=body_hash,
        size_bytes=size,
        safety_critical=bool(meta_block.get("safety_critical", False)),
        gated_by_conops=str(meta_block.get("gated_by_conops", "")),
    )


class SkillRegistry:
    """Thread-safe in-memory store of SkillEnvelope by path."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._by_path: dict[str, SkillEnvelope] = {}

    def ingest(
        self,
        path: str,
        body: str,
        *,
        references: dict[str, bytes] | None = None,
        scripts: dict[str, bytes] | None = None,
    ) -> SkillIngestResponse:
        body_bytes = body.encode("utf-8")
        body_hash = "sha256:" + hashlib.sha256(body_bytes).hexdigest()
        frontmatter, _stripped = _parse_frontmatter(body)
        meta = _build_meta(path, frontmatter, body_hash, len(body_bytes))
        envelope = SkillEnvelope(
            meta=meta,
            body=body,
            references=dict(references or {}),
            scripts=dict(scripts or {}),
        )
        with self._lock:
            existing = self._by_path.get(path)
            created = existing is None or existing.meta.content_sha256 != body_hash
            self._by_path[path] = envelope
        return SkillIngestResponse(path=path, content_sha256=body_hash, created=created)

    def load(self, path: str) -> SkillEnvelope | None:
        with self._lock:
            return self._by_path.get(path)

    def list(self, req: SkillListRequest) -> SkillListResponse:
        with self._lock:
            metas = [env.meta for env in self._by_path.values()]
        filtered = list(self._filter(metas, req))
        page_size = max(1, min(req.page_size or 100, 1000))
        try:
            start = int(req.page_token) if req.page_token else 0
        except ValueError:
            start = 0
        page = filtered[start : start + page_size]
        next_token = str(start + page_size) if (start + page_size) < len(filtered) else ""
        return SkillListResponse(
            skills=page, next_page_token=next_token, total_count=len(filtered)
        )

    @staticmethod
    def _filter(metas: Iterable[SkillMeta], req: SkillListRequest):
        sub_set = {s.lower() for s in req.subdomain_filter or []}
        tag_set = {t.lower() for t in req.tag_filter or []}
        mitre_set = {m.upper() for m in req.mitre_filter or []}
        for m in metas:
            if not req.include_safety_critical and m.safety_critical:
                continue
            if not req.include_gated and m.gated_by_conops:
                continue
            if sub_set and m.subdomain.lower() not in sub_set:
                continue
            if tag_set and not (set(t.lower() for t in m.tags) & tag_set):
                continue
            if mitre_set and not (set(x.upper() for x in m.mitre_attack) & mitre_set):
                continue
            yield m

    def __len__(self) -> int:
        with self._lock:
            return len(self._by_path)

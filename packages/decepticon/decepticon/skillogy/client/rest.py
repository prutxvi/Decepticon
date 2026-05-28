"""REST client for the Skillogy service.

httpx-based; sync + async. The middleware uses the async path so it
doesn't block the agent event loop.
"""

from __future__ import annotations

import logging
from typing import Any

from decepticon.skillogy.proto import (
    SkillEnvelope,
    SkillIngestResponse,
    SkillListResponse,
    SkillMeta,
)

log = logging.getLogger(__name__)


class SkillogyClientError(RuntimeError):
    """Raised on any non-2xx response from the Skillogy server."""


def _meta_from_dict(d: dict) -> SkillMeta:
    return SkillMeta(
        name=d.get("name") or "",
        description=d.get("description") or "",
        subdomain=d.get("subdomain") or "",
        tags=list(d.get("tags") or []),
        mitre_attack=list(d.get("mitre_attack") or []),
        path=d.get("path") or "",
        content_sha256=d.get("content_sha256") or "",
        size_bytes=int(d.get("size_bytes") or 0),
        safety_critical=bool(d.get("safety_critical", False)),
        gated_by_conops=str(d.get("gated_by_conops") or ""),
    )


def _envelope_from_dict(d: dict) -> SkillEnvelope:
    return SkillEnvelope(
        meta=_meta_from_dict(d.get("meta") or {}),
        body=d.get("body") or "",
        references={k: (v.encode("utf-8") if isinstance(v, str) else v) for k, v in (d.get("references") or {}).items()},
        scripts={k: (v.encode("utf-8") if isinstance(v, str) else v) for k, v in (d.get("scripts") or {}).items()},
    )


class RestSkillogyClient:
    """Thin async REST client. One per agent process; shares an httpx session."""

    def __init__(
        self,
        base_url: str = "http://skillogy:9100",
        *,
        timeout: float = 10.0,
        api_key: str | None = None,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._timeout = timeout
        self._headers = {"Content-Type": "application/json"}
        if api_key:
            self._headers["Authorization"] = f"Bearer {api_key}"

    async def _post_json(self, path: str, payload: dict) -> dict:
        try:
            import httpx  # noqa: PLC0415
        except ImportError as exc:
            raise SkillogyClientError("httpx not installed") from exc
        url = f"{self._base}{path}"
        async with httpx.AsyncClient(timeout=self._timeout) as cx:
            resp = await cx.post(url, json=payload, headers=self._headers)
            if resp.status_code >= 400:
                raise SkillogyClientError(
                    f"POST {path} returned HTTP {resp.status_code}: {resp.text[:500]}"
                )
            return resp.json()

    async def _get_json(self, path: str) -> dict:
        try:
            import httpx  # noqa: PLC0415
        except ImportError as exc:
            raise SkillogyClientError("httpx not installed") from exc
        url = f"{self._base}{path}"
        async with httpx.AsyncClient(timeout=self._timeout) as cx:
            resp = await cx.get(url, headers=self._headers)
            if resp.status_code >= 400:
                raise SkillogyClientError(
                    f"GET {path} returned HTTP {resp.status_code}: {resp.text[:500]}"
                )
            return resp.json()

    async def health(self) -> dict[str, Any]:
        return await self._get_json("/v1/health")

    async def list_skills(
        self,
        *,
        subdomain_filter: list[str] | None = None,
        tag_filter: list[str] | None = None,
        mitre_filter: list[str] | None = None,
        include_safety_critical: bool = True,
        include_gated: bool = True,
        page_size: int = 200,
    ) -> SkillListResponse:
        body = {
            "subdomain_filter": subdomain_filter or [],
            "tag_filter": tag_filter or [],
            "mitre_filter": mitre_filter or [],
            "include_safety_critical": include_safety_critical,
            "include_gated": include_gated,
            "page_size": page_size,
            "page_token": "",
        }
        all_skills: list[SkillMeta] = []
        total = 0
        next_token = ""
        while True:
            body["page_token"] = next_token
            data = await self._post_json("/v1/skills:list", body)
            for s in data.get("skills") or []:
                all_skills.append(_meta_from_dict(s))
            total = int(data.get("total_count") or 0)
            next_token = data.get("next_page_token") or ""
            if not next_token:
                break
        return SkillListResponse(skills=all_skills, next_page_token="", total_count=total)

    async def load_skill(
        self, path: str, *, include_references: bool = True, include_scripts: bool = True
    ) -> SkillEnvelope:
        data = await self._post_json(
            "/v1/skills:load",
            {
                "path": path,
                "include_references": include_references,
                "include_scripts": include_scripts,
            },
        )
        return _envelope_from_dict(data.get("skill") or {})

    async def ingest_skill(
        self,
        *,
        path: str,
        body: str,
        references: dict[str, bytes] | None = None,
        scripts: dict[str, bytes] | None = None,
    ) -> SkillIngestResponse:
        data = await self._post_json(
            "/v1/skills:ingest",
            {
                "path": path,
                "body": body,
                "references": {
                    k: v.decode("utf-8", errors="replace") for k, v in (references or {}).items()
                },
                "scripts": {
                    k: v.decode("utf-8", errors="replace") for k, v in (scripts or {}).items()
                },
            },
        )
        return SkillIngestResponse(
            path=str(data.get("path") or ""),
            content_sha256=str(data.get("content_sha256") or ""),
            created=bool(data.get("created", False)),
        )

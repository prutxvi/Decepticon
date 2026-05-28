"""FastAPI REST app + gRPC service for Skillogy.

REST endpoints (mirror gRPC methods 1:1):
- ``POST /v1/skills:list``        -> ListSkills
- ``POST /v1/skills:load``        -> LoadSkill
- ``POST /v1/skills:ingest``      -> IngestSkill
- ``GET  /v1/health``             -> Health
- ``GET  /openapi.json``          -> generated OpenAPI 3.1 schema

The gRPC service is exposed when grpcio is installed; the REST app
runs standalone without grpcio so the CLI / test paths don't require
the heavier dependency. Both share the same SkillRegistry instance.
"""

from __future__ import annotations

import logging
import time
from dataclasses import asdict
from typing import Any

from decepticon.skillogy.proto import (
    SkillEnvelope,
    SkillListRequest,
    SkillMeta,
)
from decepticon.skillogy.server.registry import SkillRegistry

log = logging.getLogger(__name__)


def _envelope_to_payload(env: SkillEnvelope, include_refs: bool, include_scripts: bool) -> dict:
    return {
        "meta": asdict(env.meta),
        "body": env.body,
        "references": {k: v.decode("utf-8", errors="replace") for k, v in env.references.items()} if include_refs else {},
        "scripts": {k: v.decode("utf-8", errors="replace") for k, v in env.scripts.items()} if include_scripts else {},
    }


try:
    from pydantic import BaseModel
except ImportError:
    BaseModel = None  # type: ignore[assignment,misc]


if BaseModel is not None:

    class ListReq(BaseModel):
        subdomain_filter: list[str] = []
        tag_filter: list[str] = []
        mitre_filter: list[str] = []
        include_safety_critical: bool = True
        include_gated: bool = True
        page_size: int = 100
        page_token: str = ""

    class LoadReq(BaseModel):
        path: str
        include_references: bool = True
        include_scripts: bool = True

    class IngestReq(BaseModel):
        path: str
        body: str
        references: dict[str, str] = {}
        scripts: dict[str, str] = {}


def build_app(registry: SkillRegistry, *, started_at: float | None = None):
    """Construct the FastAPI app bound to ``registry``.

    The FastAPI import is lazy so this module can be imported in
    environments without FastAPI (test fixtures, CLI ingester).
    """
    try:
        from fastapi import FastAPI, HTTPException  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "Skillogy server requires FastAPI + Pydantic. Install with: "
            "pip install fastapi pydantic uvicorn"
        ) from exc

    app = FastAPI(
        title="Skillogy",
        version="0.1.0",
        description="Decepticon skill catalog service. Speaks REST and gRPC.",
    )
    boot_time = started_at or time.time()

    @app.get("/v1/health")
    async def health() -> dict[str, Any]:
        return {
            "status": "ok",
            "skill_count": len(registry),
            "uptime_seconds": int(time.time() - boot_time),
        }

    @app.post("/v1/skills:list")
    async def list_skills(req: ListReq) -> dict[str, Any]:
        resp = registry.list(
            SkillListRequest(
                subdomain_filter=req.subdomain_filter,
                tag_filter=req.tag_filter,
                mitre_filter=req.mitre_filter,
                include_safety_critical=req.include_safety_critical,
                include_gated=req.include_gated,
                page_size=req.page_size,
                page_token=req.page_token,
            )
        )
        return {
            "skills": [asdict(s) for s in resp.skills],
            "next_page_token": resp.next_page_token,
            "total_count": resp.total_count,
        }

    @app.post("/v1/skills:load")
    async def load_skill(req: LoadReq) -> dict[str, Any]:
        env = registry.load(req.path)
        if env is None:
            raise HTTPException(status_code=404, detail=f"skill not found: {req.path}")
        return {"skill": _envelope_to_payload(env, req.include_references, req.include_scripts)}

    @app.post("/v1/skills:ingest")
    async def ingest_skill(req: IngestReq) -> dict[str, Any]:
        refs = {k: v.encode("utf-8") for k, v in req.references.items()}
        scripts = {k: v.encode("utf-8") for k, v in req.scripts.items()}
        resp = registry.ingest(req.path, req.body, references=refs, scripts=scripts)
        return asdict(resp)

    return app


def build_grpc_server(registry: SkillRegistry, *, port: int = 50051):
    """Construct a grpcio Server bound to ``registry``. Lazy-imports grpcio.

    Returns a ``grpc.Server`` instance the caller starts / waits / stops.
    Falls back to ``RuntimeError`` if grpcio is unavailable.
    """
    try:
        import grpc  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "Skillogy gRPC requires grpcio. Install with: pip install grpcio grpcio-tools"
        ) from exc

    class _RawSkillogyServicer:
        def ListSkills(self, request, _context):
            return _RawResponse(
                registry.list(
                    SkillListRequest(
                        subdomain_filter=list(getattr(request, "subdomain_filter", []) or []),
                        tag_filter=list(getattr(request, "tag_filter", []) or []),
                        mitre_filter=list(getattr(request, "mitre_filter", []) or []),
                        include_safety_critical=getattr(request, "include_safety_critical", True),
                        include_gated=getattr(request, "include_gated", True),
                        page_size=getattr(request, "page_size", 100),
                        page_token=getattr(request, "page_token", "") or "",
                    )
                )
            )

        def LoadSkill(self, request, _context):
            return registry.load(getattr(request, "path", "")) or SkillEnvelope(meta=SkillMeta())

        def IngestSkill(self, request, _context):
            return registry.ingest(
                getattr(request, "path", ""),
                getattr(request, "body", ""),
                references=dict(getattr(request, "references", {}) or {}),
                scripts=dict(getattr(request, "scripts", {}) or {}),
            )

        def Health(self, _request, _context):
            return _HealthResp(status="ok", skill_count=len(registry))

    server = grpc.server(
        thread_pool=__import__("concurrent.futures").futures.ThreadPoolExecutor(max_workers=10)
    )
    server.add_insecure_port(f"0.0.0.0:{port}")
    return server, _RawSkillogyServicer()


class _RawResponse:
    def __init__(self, list_resp):
        self.skills = list_resp.skills
        self.next_page_token = list_resp.next_page_token
        self.total_count = list_resp.total_count


class _HealthResp:
    def __init__(self, status, skill_count):
        self.status = status
        self.skill_count = skill_count

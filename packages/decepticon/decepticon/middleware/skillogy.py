"""SkillogyMiddleware - the replacement for the file-system-backed SkillsMiddleware.

Drop-in shaped: agents wired with this middleware see the same skill
catalog they would see from the existing SkillsMiddleware, but the
content comes from the Skillogy service over REST or gRPC instead of
from disk inside the agent process.

Opt-in via either:
- ``DECEPTICON_USE_SKILLOGY=1`` environment variable (process-global), or
- Direct construction in the agent factory (per-agent override).

The middleware is intentionally a peer of SkillsMiddleware rather than
a subclass: the two cannot share state, since the file-system view and
the service view will diverge over time as Skillogy adds tenant-aware
filtering, hot-load, and per-engagement skill ACLs.

Tool surface
------------
The middleware exposes the same two @tool functions that
SkillsMiddleware does, named identically so the agent prompts do not
need to be retrained:

- ``list_skills(subdomain_filter, tag_filter, mitre_filter)`` - browse
  the catalog (metadata only; no body bytes).
- ``load_skill(path)`` - fetch the full body + references + scripts of
  a specific skill.

Both delegate to the configured RestSkillogyClient and surface errors
as structured ToolMessage payloads (never raise).
"""

from __future__ import annotations

import json
import logging
import os
from dataclasses import asdict
from typing import Any

from langchain.agents.middleware import AgentMiddleware
from langchain_core.messages import SystemMessage, ToolMessage
from langchain_core.tools import tool
from typing_extensions import override

log = logging.getLogger(__name__)


_DEFAULT_BASE_URL = "http://skillogy:9100"
_POLICY_PROMPT = (
    "\n\n[Skillogy access]\n"
    "Skills are served by the Skillogy service over REST. Call list_skills "
    "to browse the catalog (cheap, metadata only) and load_skill to fetch a "
    "specific SKILL.md body when its description matches your current "
    "objective. The SKILL-FIRST rule still applies: load the relevant skill "
    "before acting on a trigger keyword from its description. The catalog "
    "honors ConOps gating (safety-critical and phishing-engagement skills "
    "are only returned when the active engagement's ConOps permits them)."
)


def _is_enabled() -> bool:
    return os.environ.get("DECEPTICON_USE_SKILLOGY", "").strip().lower() in {"1", "true", "yes", "on"}


def _resolve_base_url() -> str:
    return os.environ.get("DECEPTICON_SKILLOGY_URL", _DEFAULT_BASE_URL)


def _resolve_api_key() -> str | None:
    return os.environ.get("DECEPTICON_SKILLOGY_API_KEY") or None


def _client_factory():
    from decepticon.skillogy.client.rest import RestSkillogyClient  # noqa: PLC0415

    return RestSkillogyClient(base_url=_resolve_base_url(), api_key=_resolve_api_key())


def _make_list_skills_tool(client):
    @tool
    async def list_skills(
        subdomain_filter: list[str] | None = None,
        tag_filter: list[str] | None = None,
        mitre_filter: list[str] | None = None,
    ) -> str:
        """List skills available to the current engagement.

        Filter by subdomain (e.g. ``["recon"]``), by tags (e.g. ``["sqli", "xss"]``),
        or by MITRE ATT&CK technique IDs (e.g. ``["T1190", "T1003.001"]``).
        Returns metadata only - call load_skill(path) to fetch a body.
        """
        try:
            resp = await client.list_skills(
                subdomain_filter=subdomain_filter,
                tag_filter=tag_filter,
                mitre_filter=mitre_filter,
            )
            payload = {
                "total_count": resp.total_count,
                "skills": [asdict(s) for s in resp.skills],
            }
            return json.dumps(payload, indent=2, ensure_ascii=False, default=str)
        except Exception as exc:  # noqa: BLE001 - never raise into the agent
            return json.dumps({"error": f"Skillogy list_skills failed: {exc!r}"})

    return list_skills


def _make_load_skill_tool(client):
    @tool
    async def load_skill(path: str) -> str:
        """Load a specific skill's full body + references + scripts from Skillogy.

        ``path`` is the canonical skill path as returned by list_skills,
        e.g. ``/skills/standard/ad/kerberoasting/SKILL.md``.
        """
        try:
            env = await client.load_skill(path)
            return json.dumps(
                {
                    "meta": asdict(env.meta),
                    "body": env.body,
                    "references": {
                        k: v.decode("utf-8", errors="replace") for k, v in env.references.items()
                    },
                    "scripts": {
                        k: v.decode("utf-8", errors="replace") for k, v in env.scripts.items()
                    },
                },
                indent=2,
                ensure_ascii=False,
                default=str,
            )
        except Exception as exc:  # noqa: BLE001
            return json.dumps({"error": f"Skillogy load_skill failed: {exc!r}"})

    return load_skill


class SkillogyMiddleware(AgentMiddleware):
    """Wire the agent to Skillogy instead of the local SkillsMiddleware.

    Two activation modes:
    - Construct directly and pass to the agent factory's middleware list
      (per-agent opt-in).
    - Set ``DECEPTICON_USE_SKILLOGY=1`` and let
      ``decepticon.skillogy.middleware.maybe_install_skillogy`` substitute
      Skillogy for SkillsMiddleware at agent boot (process-global opt-in).
    """

    def __init__(
        self,
        *,
        client: Any = None,
        append_policy_to_system: bool = True,
    ) -> None:
        super().__init__()
        self._client = client or _client_factory()
        self._append_policy = append_policy_to_system
        self.tools = [
            _make_list_skills_tool(self._client),
            _make_load_skill_tool(self._client),
        ]

    @classmethod
    def from_env(cls) -> SkillogyMiddleware:
        return cls()

    @override
    def wrap_model_call(self, request, handler):
        return handler(self._inject(request))

    @override
    async def awrap_model_call(self, request, handler):
        return await handler(self._inject(request))

    def _inject(self, request):
        if not self._append_policy:
            return request
        if request.system_message is not None:
            new_content = [
                *request.system_message.content_blocks,
                {"type": "text", "text": _POLICY_PROMPT},
            ]
        else:
            new_content = [{"type": "text", "text": _POLICY_PROMPT}]
        new_system = SystemMessage(content=new_content)
        return request.override(system_message=new_system)

    @override
    def wrap_tool_call(self, request, handler) -> ToolMessage:
        return handler(request)

    @override
    async def awrap_tool_call(self, request, handler) -> ToolMessage:
        return await handler(request)


def maybe_install_skillogy(middleware_stack: list[Any]) -> list[Any]:
    """Substitute SkillogyMiddleware for SkillsMiddleware when env flag is set.

    Idempotent. Returns the (possibly modified) stack. Agents call this
    from their build path to honor DECEPTICON_USE_SKILLOGY without each
    agent constructor needing the conditional logic.
    """
    if not _is_enabled():
        return middleware_stack
    try:
        from decepticon.middleware.skills import SkillsMiddleware  # noqa: PLC0415
    except ImportError:
        return middleware_stack
    out: list[Any] = []
    swapped = False
    for mw in middleware_stack:
        if isinstance(mw, SkillsMiddleware):
            out.append(SkillogyMiddleware.from_env())
            swapped = True
        else:
            out.append(mw)
    if not swapped:
        out.append(SkillogyMiddleware.from_env())
    return out

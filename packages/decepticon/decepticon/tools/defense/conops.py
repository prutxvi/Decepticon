# -*- coding: utf-8 -*-
"""Read SIEM target endpoints from the engagement's ConOps document.

The ConOps lives at ``/workspace/conops.json``. The schema looked up here
is::

    {
      "blue_team": {
        "splunk":     {"url": "...", "auth": "hec_token:<env-var-name>"},
        "sentinel":   {"workspace_id": "...", "auth": "shared_key:<env>"},
        "elastic":    {"url": "...", "auth": "api_key:<env>"},
        "defender":   {"tenant_id": "...", "auth": "oauth:<env>"},
        "crowdstrike":{"url": "...", "auth": "oauth:<env>"}
      }
    }

The ``auth`` field is ALWAYS a reference to an env var, never the secret
inline. Agents and tools never see plaintext credentials in conops.json.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any


class ConOpsLookupError(RuntimeError):
    """Raised when a tool tries to push to an undeclared SIEM target."""


_CONOPS_FILENAMES = ("conops.json", "ConOps.json", "rules-of-engagement/conops.json")


def _resolve_workspace() -> Path:
    return Path(os.environ.get("DECEPTICON_ENGAGEMENT_WORKSPACE") or "/workspace")


def _load_conops() -> dict[str, Any]:
    workspace = _resolve_workspace()
    for candidate in _CONOPS_FILENAMES:
        path = workspace / candidate
        if path.exists():
            try:
                return json.loads(path.read_text(encoding="utf-8"))
            except json.JSONDecodeError as exc:
                raise ConOpsLookupError(f"ConOps at {path} is not valid JSON: {exc.msg}") from exc
    raise ConOpsLookupError(
        f"No conops.json found under {workspace}. Soundwave must generate the "
        "engagement package before defense tools can push to a SIEM."
    )


def resolve_siem_target(name: str) -> dict[str, Any]:
    """Return ConOps ``blue_team.<name>`` entry or raise ConOpsLookupError."""
    conops = _load_conops()
    blue_team = conops.get("blue_team")
    if not isinstance(blue_team, dict):
        raise ConOpsLookupError(
            "ConOps has no ``blue_team`` section — Defender output cannot be "
            "pushed until the operator declares SIEM endpoints in ConOps."
        )
    target = blue_team.get(name)
    if not isinstance(target, dict):
        raise ConOpsLookupError(
            f"ConOps.blue_team has no entry for ``{name}``. Available targets: "
            f"{sorted(blue_team.keys())}"
        )
    return target


def list_targets() -> list[str]:
    """Return the names of every blue-team SIEM endpoint declared in ConOps."""
    try:
        conops = _load_conops()
    except ConOpsLookupError:
        return []
    blue_team = conops.get("blue_team") or {}
    if not isinstance(blue_team, dict):
        return []
    return sorted(blue_team.keys())


def resolve_auth_value(auth_spec: str) -> str:
    """Resolve a ConOps auth reference (``<kind>:<env-var-name>``) to its value.

    Raises ConOpsLookupError if the spec is malformed or the env var is missing.
    """
    if ":" not in auth_spec:
        raise ConOpsLookupError(
            f"auth spec {auth_spec!r} is malformed; expected ``<kind>:<env-var-name>``"
        )
    _kind, env_var = auth_spec.split(":", 1)
    value = os.environ.get(env_var, "")
    if not value:
        raise ConOpsLookupError(
            f"env var {env_var} is unset; cannot resolve auth for the SIEM push. "
            "Set the variable in .env and restart the langgraph container."
        )
    return value


def engagement_slug() -> str:
    """Return the engagement slug used to tag pushed rules."""
    slug = os.environ.get("DECEPTICON_ENGAGEMENT_SLUG", "")
    if slug:
        return slug
    try:
        conops = _load_conops()
    except ConOpsLookupError:
        return "unscoped"
    name = conops.get("engagement_name") or conops.get("slug") or "unscoped"
    return str(name).lower().replace(" ", "-")

# -*- coding: utf-8 -*-
"""Per-engagement active-label contextvar.

The active-engagement label identifies which red-team engagement the
current call belongs to. Multi-tenant deployments use the label to scope
writes and reads — see ``docs/security/neo4j-hardening.md`` for the
broader rationale.

This module owns the contextvar and the label-format validator. Setting
the value is the launcher's responsibility — ``EngagementContextMiddleware``
resolves ``engagement_name`` from ``config.configurable`` on the first
turn and calls ``set_active_engagement(...)`` before tool dispatch.

The legacy KG tool stack lived under ``decepticon.tools.research`` and
previously owned this contextvar. It is being removed; the contextvar
moved here so the planned KG middleware can keep using it after the
removal lands.
"""

from __future__ import annotations

import contextvars
import os
import re

_active_engagement: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "decepticon_active_engagement",
    default=None,
)


_ENGAGEMENT_LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,127}$")


def is_valid_engagement_label(label: str) -> bool:
    """Return True if ``label`` is a safe engagement identifier.

    Characters are restricted to ASCII alphanumeric plus ``.``, ``-``,
    ``_``. The first character must be alphanumeric. Length 1-128.
    """
    return bool(label and _ENGAGEMENT_LABEL_RE.match(label))


def set_active_engagement(label: str | None) -> contextvars.Token[str | None]:
    """Set the active engagement label for the current context."""
    if label is not None and not is_valid_engagement_label(label):
        raise ValueError(
            f"invalid engagement label {label!r}; must match [A-Za-z0-9][A-Za-z0-9._-]{{0,127}}"
        )
    return _active_engagement.set(label)


def reset_active_engagement(token: contextvars.Token[str | None]) -> None:
    """Reset the active engagement to the value before ``set_active_engagement``."""
    _active_engagement.reset(token)


def get_active_engagement() -> str | None:
    """Return the active engagement label, or ``None`` if unset.

    Resolution order (first non-empty wins):
      1. contextvar set by ``set_active_engagement``
      2. ``DECEPTICON_ENGAGEMENT`` environment variable
      3. ``None`` (caller should treat as "no scoping configured")
    """
    label = _active_engagement.get()
    if label:
        return label
    env_label = os.environ.get("DECEPTICON_ENGAGEMENT", "").strip()
    if env_label and is_valid_engagement_label(env_label):
        return env_label
    return None

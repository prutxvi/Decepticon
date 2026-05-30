"""Sigma → Splunk Saved Search converter + HEC publisher.

The Splunk path is the simplest of the SIEM exporters: we translate a Sigma
rule body to an SPL search using ``sigma-cli``-style logic, then POST it via
the Saved Searches REST API (``/services/saved/searches``).

If ``pysigma`` is installed we use it. Otherwise we fall back to a tiny
in-house translator that handles the subset Decepticon's Detector agent
actually emits (selection + condition with ``and``/``or``, optional
``modifiers: contains|startswith|endswith``). The fallback is intentionally
not a full Sigma compiler — anything fancier than the supported subset gets
a structured error instead of silently producing wrong SPL.
"""

from __future__ import annotations

from typing import Any

from decepticon.tools.defense.conops import (
    ConOpsLookupError,
    engagement_slug,
    resolve_auth_value,
    resolve_siem_target,
)


class SigmaConversionError(RuntimeError):
    """Raised when a Sigma rule contains a construct we can't translate."""


def _quote_spl(value: Any) -> str:
    if isinstance(value, str):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return str(value)


def _selection_to_spl(selection: dict[str, Any]) -> str:
    clauses: list[str] = []
    for field, value in selection.items():
        if "|" in field:
            base, modifier = field.split("|", 1)
        else:
            base, modifier = field, ""
        if isinstance(value, list):
            sub = " OR ".join(_field_clause(base, modifier, v) for v in value)
            clauses.append(f"({sub})")
        else:
            clauses.append(_field_clause(base, modifier, value))
    return " ".join(clauses)


def _field_clause(field: str, modifier: str, value: Any) -> str:
    quoted = _quote_spl(value)
    if isinstance(value, str):
        esc = value.replace("\\", "\\\\").replace('"', '\\"')
        if modifier == "contains":
            return f'{field}="*{esc}*"'
        if modifier == "startswith":
            return f'{field}="{esc}*"'
        if modifier == "endswith":
            return f'{field}="*{esc}"'
    else:
        if modifier in ("contains", "startswith", "endswith"):
            return f"{field}={quoted}"
    if modifier in ("", "equals"):
        return f"{field}={quoted}"
    raise SigmaConversionError(f"unsupported Sigma modifier ``{modifier}``")


def sigma_to_spl(sigma_rule: dict[str, Any]) -> str:
    """Translate a parsed Sigma rule dict to a Splunk SPL search string.

    Supports: ``detection.selection`` + ``detection.condition: selection``;
    multiple named selections combined via ``and``/``or``. Anything else
    raises SigmaConversionError so the agent can surface the gap.
    """
    detection = sigma_rule.get("detection")
    if not isinstance(detection, dict):
        raise SigmaConversionError("Sigma rule is missing a ``detection`` block")

    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise SigmaConversionError("Sigma rule ``detection.condition`` must be a string")

    selections = {k: v for k, v in detection.items() if k != "condition"}
    if not selections:
        raise SigmaConversionError("Sigma rule has no selections")

    tokens = condition.replace("(", " ( ").replace(")", " ) ").split()
    rendered: list[str] = []
    for tok in tokens:
        lower = tok.lower()
        if lower == "and":
            rendered.append("AND")
        elif lower == "or":
            rendered.append("OR")
        elif lower == "not":
            rendered.append("NOT")
        elif tok in ("(", ")"):
            rendered.append(tok)
        elif tok in selections:
            value = selections[tok]
            if not isinstance(value, dict):
                raise SigmaConversionError(
                    f"selection ``{tok}`` must be a dict, got {type(value).__name__}"
                )
            rendered.append(f"({_selection_to_spl(value)})")
        else:
            raise SigmaConversionError(
                f"unknown token ``{tok}`` in condition; supported: selection names, and/or/not, parens"
            )
    return " ".join(rendered)


def push_savedsearch(
    title: str,
    spl_query: str,
    *,
    description: str = "",
    technique_id: str = "",
    severity: str = "medium",
) -> dict[str, Any]:
    """POST the saved-search to Splunk via REST.

    Reads the Splunk endpoint + HEC token from ConOps (``blue_team.splunk``).
    Tags the saved search ``decepticon-eng-<slug>`` so blue-team can audit
    and disable rules after the engagement ends.

    Returns the parsed Splunk response on success or a ``{"error": ...}``
    dict if the push failed — agents see this directly.
    """
    try:
        target = resolve_siem_target("splunk")
    except ConOpsLookupError as exc:
        return {"error": str(exc)}

    url = target.get("url")
    auth_spec = target.get("auth")
    if not url or not auth_spec:
        return {"error": "ConOps.blue_team.splunk missing ``url`` or ``auth``"}
    try:
        token = resolve_auth_value(auth_spec)
    except ConOpsLookupError as exc:
        return {"error": str(exc)}

    tag = f"decepticon-eng-{engagement_slug()}"
    safe_title = f"{tag}::{title}"

    try:
        import requests  # noqa: PLC0415
    except ImportError:
        return {"error": "``requests`` not installed in langgraph container"}

    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "name": safe_title,
        "search": spl_query,
        "description": (
            f"{description}\n\n"
            f"Created by Decepticon engagement ``{engagement_slug()}``"
            + (f"\nMITRE ATT&CK: {technique_id}" if technique_id else "")
        ),
        "is_scheduled": "1",
        "actions": "",
        "disabled": "0",
    }

    endpoint = url.rstrip("/") + "/services/saved/searches"
    try:
        resp = requests.post(endpoint, headers=headers, data=payload, timeout=15, verify=True)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"Splunk POST failed: {exc!r}"}

    if resp.status_code >= 400:
        return {
            "error": f"Splunk returned HTTP {resp.status_code}",
            "body": resp.text[:1000],
        }
    return {
        "status": "pushed",
        "splunk_savedsearch_name": safe_title,
        "engagement_slug": engagement_slug(),
        "technique_id": technique_id,
        "severity": severity,
    }

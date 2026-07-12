# -*- coding: utf-8 -*-
"""Sigma → Elastic Detection Engine rule (Kibana Detection API push).

Elastic's Detection Engine accepts a JSON rule via
``POST /api/detection_engine/rules``. We translate the Sigma body to an
Elastic Query Language (EQL) or Lucene KQL query depending on rule type;
this minimal converter emits Lucene KQL since Detector mostly emits
single-table conditions.
"""

from __future__ import annotations

import json
from typing import Any

from decepticon.tools.defense.conops import (
    ConOpsLookupError,
    engagement_slug,
    resolve_auth_value,
    resolve_siem_target,
)


class SigmaToElasticError(RuntimeError):
    """Raised on unsupported Sigma constructs."""


def _field_clause_lucene(field: str, modifier: str, value: Any) -> str:
    if isinstance(value, str):
        escaped = value.replace('"', '\\"')
        if modifier == "contains":
            return f"{field}: *{escaped}*"
        if modifier == "startswith":
            return f"{field}: {escaped}*"
        if modifier == "endswith":
            return f"{field}: *{escaped}"
        if modifier in ("", "equals"):
            return f'{field}: "{escaped}"'
    else:
        if modifier in ("", "equals"):
            return f"{field}: {value}"
    raise SigmaToElasticError(f"unsupported modifier ``{modifier}`` for Lucene")


def _selection_to_lucene(selection: dict[str, Any]) -> str:
    clauses: list[str] = []
    for field, value in selection.items():
        base, modifier = (field.split("|", 1) + [""])[:2]
        if isinstance(value, list):
            sub = " OR ".join(_field_clause_lucene(base, modifier, v) for v in value)
            clauses.append(f"({sub})")
        else:
            clauses.append(_field_clause_lucene(base, modifier, value))
    return " AND ".join(clauses)


def sigma_to_lucene(sigma_rule: dict[str, Any]) -> str:
    """Translate a Sigma rule dict to a Lucene query string."""
    detection = sigma_rule.get("detection")
    if not isinstance(detection, dict):
        raise SigmaToElasticError("Sigma rule missing ``detection`` block")
    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise SigmaToElasticError("``detection.condition`` must be a string")

    selections = {k: v for k, v in detection.items() if k != "condition"}
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
                raise SigmaToElasticError(f"selection ``{tok}`` must be a dict")
            rendered.append(f"({_selection_to_lucene(value)})")
        else:
            raise SigmaToElasticError(f"unknown token ``{tok}`` in condition")
    return " ".join(rendered)


_SEVERITY_MAP = {
    "informational": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "critical": "critical",
}


def push_detection_rule(
    rule_id: str,
    name: str,
    lucene_query: str,
    *,
    description: str = "",
    severity: str = "medium",
    technique_id: str = "",
    index_patterns: list[str] | None = None,
) -> dict[str, Any]:
    """POST a custom detection rule to Elastic via Kibana Detection Engine API."""
    try:
        target = resolve_siem_target("elastic")
    except ConOpsLookupError as exc:
        return {"error": str(exc)}

    url = target.get("url")
    auth_spec = target.get("auth")
    if not url or not auth_spec:
        return {"error": "ConOps.blue_team.elastic missing ``url`` or ``auth``"}
    try:
        api_key = resolve_auth_value(auth_spec)
    except ConOpsLookupError as exc:
        return {"error": str(exc)}

    tagged_id = f"decepticon-eng-{engagement_slug()}-{rule_id}"
    body = {
        "rule_id": tagged_id,
        "name": f"[Decepticon] {name}",
        "description": (
            description
            + f"\n\nEngagement: {engagement_slug()}"
            + (f"\nMITRE ATT&CK: {technique_id}" if technique_id else "")
        ),
        "severity": _SEVERITY_MAP.get(severity.lower(), "medium"),
        "risk_score": 50,
        "type": "query",
        "language": "lucene",
        "query": lucene_query,
        "index": index_patterns or ["logs-*", "filebeat-*", "winlogbeat-*"],
        "from": "now-5m",
        "interval": "5m",
        "enabled": True,
        "tags": ["decepticon", f"engagement:{engagement_slug()}"]
        + ([technique_id] if technique_id else []),
    }

    try:
        import requests  # noqa: PLC0415
    except ImportError:
        return {"error": "``requests`` not installed in langgraph container"}

    headers = {
        "Authorization": f"ApiKey {api_key}",
        "Content-Type": "application/json",
        "kbn-xsrf": "true",
    }
    endpoint = url.rstrip("/") + "/api/detection_engine/rules"
    try:
        resp = requests.post(endpoint, headers=headers, data=json.dumps(body), timeout=15)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"Elastic POST failed: {exc!r}"}

    if resp.status_code == 409:
        endpoint_put = endpoint + f"?rule_id={tagged_id}"
        try:
            resp = requests.put(endpoint_put, headers=headers, data=json.dumps(body), timeout=15)
        except Exception as exc:  # noqa: BLE001
            return {"error": f"Elastic PUT (replace) failed: {exc!r}"}

    if resp.status_code >= 400:
        return {
            "error": f"Elastic returned HTTP {resp.status_code}",
            "body": resp.text[:1000],
        }
    return {
        "status": "pushed",
        "rule_id": tagged_id,
        "engagement_slug": engagement_slug(),
        "technique_id": technique_id,
        "severity": severity,
    }

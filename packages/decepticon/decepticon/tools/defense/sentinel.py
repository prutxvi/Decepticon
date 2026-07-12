# -*- coding: utf-8 -*-
"""Sigma → Microsoft Sentinel Analytic Rule (ARM-based push).

Sentinel Analytic Rules live under
``Microsoft.SecurityInsights/scheduledAlertRules``. We assemble a minimal
ARM resource and PUT it via the Azure Management REST API.

Authentication: ConOps.blue_team.sentinel.auth = "oauth:AZURE_BEARER_TOKEN".
The bearer token is acquired by the operator out-of-band (via
``az account get-access-token --resource https://management.azure.com``)
and exported into the env var named in the ConOps auth spec.

We translate the Sigma detection body to KQL using the same selection
semantics as Splunk's SPL converter — full pysigma support comes later
if the agent emits a rule we can't translate.
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


class SigmaToKqlError(RuntimeError):
    """Raised when Sigma → KQL conversion fails on an unsupported construct."""


_LOGSOURCE_TO_TABLE = {
    ("windows", "process_creation"): "SecurityEvent",
    ("windows", "powershell"): "SecurityEvent",
    ("windows", "sysmon"): "SecurityEvent",
    ("linux", "process_creation"): "Syslog",
    ("linux", "syslog"): "Syslog",
    ("network", "firewall"): "AzureDiagnostics",
    ("network", "dns"): "DnsEvents",
    ("cloud", "azure"): "AzureActivity",
    ("cloud", "aws"): "AWSCloudTrail",
}


def _table_for_logsource(logsource: dict[str, Any]) -> str:
    product = (logsource.get("product") or "").lower()
    category = (logsource.get("category") or "").lower()
    return _LOGSOURCE_TO_TABLE.get((product, category), "Syslog")


def _field_clause_kql(field: str, modifier: str, value: Any) -> str:
    if isinstance(value, str):
        escaped = value.replace('"', '\\"')
        if modifier == "contains":
            return f'{field} contains "{escaped}"'
        if modifier == "startswith":
            return f'{field} startswith "{escaped}"'
        if modifier == "endswith":
            return f'{field} endswith "{escaped}"'
        if modifier in ("", "equals"):
            return f'{field} == "{escaped}"'
    else:
        if modifier in ("", "equals"):
            return f"{field} == {value}"
    raise SigmaToKqlError(f"unsupported Sigma modifier ``{modifier}`` for KQL")


def _selection_to_kql(selection: dict[str, Any]) -> str:
    clauses: list[str] = []
    for field, value in selection.items():
        base, modifier = (field.split("|", 1) + [""])[:2]
        if isinstance(value, list):
            sub = " or ".join(_field_clause_kql(base, modifier, v) for v in value)
            clauses.append(f"({sub})")
        else:
            clauses.append(_field_clause_kql(base, modifier, value))
    return " and ".join(clauses)


def sigma_to_kql(sigma_rule: dict[str, Any]) -> str:
    """Translate a Sigma rule dict to a KQL query string for Sentinel."""
    detection = sigma_rule.get("detection")
    if not isinstance(detection, dict):
        raise SigmaToKqlError("Sigma rule missing ``detection`` block")
    logsource = sigma_rule.get("logsource") or {}
    table = _table_for_logsource(logsource)

    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise SigmaToKqlError("Sigma rule ``detection.condition`` must be a string")

    selections = {k: v for k, v in detection.items() if k != "condition"}
    tokens = condition.replace("(", " ( ").replace(")", " ) ").split()
    rendered: list[str] = []
    for tok in tokens:
        lower = tok.lower()
        if lower == "and":
            rendered.append("and")
        elif lower == "or":
            rendered.append("or")
        elif lower == "not":
            rendered.append("not")
        elif tok in ("(", ")"):
            rendered.append(tok)
        elif tok in selections:
            value = selections[tok]
            if not isinstance(value, dict):
                raise SigmaToKqlError(f"selection ``{tok}`` must be a dict")
            rendered.append(f"({_selection_to_kql(value)})")
        else:
            raise SigmaToKqlError(f"unknown token ``{tok}`` in condition")
    where_clause = " ".join(rendered)
    return f"{table}\n| where {where_clause}"


_SEVERITY_MAP = {
    "informational": "Informational",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "High",
}


def push_analytic_rule(
    rule_id: str,
    display_name: str,
    kql_query: str,
    *,
    description: str = "",
    severity: str = "medium",
    technique_id: str = "",
) -> dict[str, Any]:
    """PUT a Scheduled Analytic Rule into Microsoft Sentinel via Azure Management REST."""
    try:
        target = resolve_siem_target("sentinel")
    except ConOpsLookupError as exc:
        return {"error": str(exc)}

    subscription = target.get("subscription_id")
    resource_group = target.get("resource_group")
    workspace = target.get("workspace_name")
    auth_spec = target.get("auth")
    if not all([subscription, resource_group, workspace, auth_spec]):
        return {
            "error": (
                "ConOps.blue_team.sentinel must define subscription_id, "
                "resource_group, workspace_name, and auth"
            )
        }
    try:
        bearer = resolve_auth_value(auth_spec)
    except ConOpsLookupError as exc:
        return {"error": str(exc)}

    tagged_id = f"decepticon-eng-{engagement_slug()}-{rule_id}"
    api_version = "2024-09-01"
    url = (
        f"https://management.azure.com/subscriptions/{subscription}"
        f"/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights"
        f"/workspaces/{workspace}/providers/Microsoft.SecurityInsights"
        f"/alertRules/{tagged_id}?api-version={api_version}"
    )

    body: dict[str, Any] = {
        "kind": "Scheduled",
        "properties": {
            "displayName": f"[Decepticon] {display_name}",
            "description": (
                description
                + f"\n\nEngagement: {engagement_slug()}"
                + (f"\nMITRE ATT&CK: {technique_id}" if technique_id else "")
            ),
            "severity": _SEVERITY_MAP.get(severity.lower(), "Medium"),
            "enabled": True,
            "query": kql_query,
            "queryFrequency": "PT5M",
            "queryPeriod": "PT5M",
            "triggerOperator": "GreaterThan",
            "triggerThreshold": 0,
            "suppressionDuration": "PT5H",
            "suppressionEnabled": False,
            "tactics": [],
        },
    }
    if technique_id:
        body["properties"]["techniques"] = [technique_id]

    try:
        import requests  # noqa: PLC0415
    except ImportError:
        return {"error": "``requests`` not installed in langgraph container"}

    headers = {
        "Authorization": f"Bearer {bearer}",
        "Content-Type": "application/json",
    }
    try:
        resp = requests.put(url, headers=headers, data=json.dumps(body), timeout=15)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"Sentinel PUT failed: {exc!r}"}

    if resp.status_code >= 400:
        return {
            "error": f"Sentinel returned HTTP {resp.status_code}",
            "body": resp.text[:1000],
        }
    return {
        "status": "pushed",
        "rule_id": tagged_id,
        "engagement_slug": engagement_slug(),
        "technique_id": technique_id,
        "severity": severity,
    }

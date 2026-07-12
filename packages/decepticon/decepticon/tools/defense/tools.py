# -*- coding: utf-8 -*-
"""LangChain ``@tool`` wrappers for the defense exporter bundle.

Each tool follows the Decepticon convention: returns a JSON string so the
agent can parse it deterministically. Sigma input is accepted both as a
parsed dict (recommended — Detector emits dicts) and as a YAML string
(convenience — operator-supplied rules from disk).
"""

from __future__ import annotations

import json
from typing import Any

from langchain_core.tools import tool

from decepticon.tools.defense import conops as conops_mod
from decepticon.tools.defense import edr, elastic, sentinel, splunk


def _coerce_sigma(rule: dict[str, Any] | str) -> dict[str, Any]:
    if isinstance(rule, dict):
        return rule
    try:
        import yaml  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "PyYAML not installed; pass Sigma rules as parsed dicts instead of YAML strings"
        ) from exc
    parsed = yaml.safe_load(rule)
    if not isinstance(parsed, dict):
        raise RuntimeError("Sigma YAML did not parse into a dict")
    return parsed


def _json(data: Any) -> str:
    return json.dumps(data, indent=2, default=str, ensure_ascii=False)


@tool
def list_siem_targets() -> str:
    """List SIEM/EDR push targets declared in the engagement's ConOps.

    Returns a JSON list of target names (``splunk``, ``sentinel``, ``elastic``,
    ``defender``, ``crowdstrike``). Use this before calling a push tool to
    confirm the target is wired — the push tools return a structured error
    when the target is undeclared, but checking first avoids a round-trip.
    """
    return _json({"targets": conops_mod.list_targets()})


@tool
def sigma_to_splunk_savedsearch(
    sigma_rule: dict[str, Any] | str,
    title: str,
    description: str = "",
    technique_id: str = "",
    severity: str = "medium",
) -> str:
    """Convert a Sigma rule to SPL and push it to Splunk as a saved search.

    Requires ConOps.blue_team.splunk with ``url`` + ``auth`` (HEC token via env).
    The rule name will be prefixed with ``decepticon-eng-<slug>::`` so the
    blue team can identify and revoke after engagement end.
    """
    try:
        rule_dict = _coerce_sigma(sigma_rule)
    except Exception as exc:  # noqa: BLE001
        return _json({"error": f"sigma rule parse failed: {exc!r}"})
    try:
        spl = splunk.sigma_to_spl(rule_dict)
    except splunk.SigmaConversionError as exc:
        return _json({"error": f"sigma→SPL conversion failed: {exc}"})
    result = splunk.push_savedsearch(
        title=title,
        spl_query=spl,
        description=description,
        technique_id=technique_id,
        severity=severity,
    )
    return _json(result)


@tool
def sigma_to_sentinel_analyticrule(
    sigma_rule: dict[str, Any] | str,
    rule_id: str,
    display_name: str,
    description: str = "",
    severity: str = "medium",
    technique_id: str = "",
) -> str:
    """Convert a Sigma rule to KQL and push it to Microsoft Sentinel as a Scheduled Analytic Rule.

    Requires ConOps.blue_team.sentinel with subscription_id, resource_group,
    workspace_name, and auth (bearer token via env). The rule_id is suffixed
    onto a ``decepticon-eng-<slug>`` prefix for blue-team auditability.
    """
    try:
        rule_dict = _coerce_sigma(sigma_rule)
    except Exception as exc:  # noqa: BLE001
        return _json({"error": f"sigma rule parse failed: {exc!r}"})
    try:
        kql = sentinel.sigma_to_kql(rule_dict)
    except sentinel.SigmaToKqlError as exc:
        return _json({"error": f"sigma→KQL conversion failed: {exc}"})
    result = sentinel.push_analytic_rule(
        rule_id=rule_id,
        display_name=display_name,
        kql_query=kql,
        description=description,
        severity=severity,
        technique_id=technique_id,
    )
    return _json(result)


@tool
def sigma_to_elastic_detection_rule(
    sigma_rule: dict[str, Any] | str,
    rule_id: str,
    name: str,
    description: str = "",
    severity: str = "medium",
    technique_id: str = "",
    index_patterns: list[str] | None = None,
) -> str:
    """Convert a Sigma rule to Lucene and push it to Elastic Detection Engine.

    Requires ConOps.blue_team.elastic with ``url`` (Kibana base URL) + ``auth``
    (API key via env). ``index_patterns`` defaults to the common
    ``logs-*``/``filebeat-*``/``winlogbeat-*`` set.
    """
    try:
        rule_dict = _coerce_sigma(sigma_rule)
    except Exception as exc:  # noqa: BLE001
        return _json({"error": f"sigma rule parse failed: {exc!r}"})
    try:
        lucene = elastic.sigma_to_lucene(rule_dict)
    except elastic.SigmaToElasticError as exc:
        return _json({"error": f"sigma→Lucene conversion failed: {exc}"})
    result = elastic.push_detection_rule(
        rule_id=rule_id,
        name=name,
        lucene_query=lucene,
        description=description,
        severity=severity,
        technique_id=technique_id,
        index_patterns=index_patterns,
    )
    return _json(result)


@tool
def yara_to_defender_xdr_custom_detection(
    yara_rule: str,
    rule_name: str,
    description: str = "",
    severity: str = "medium",
    technique_id: str = "",
) -> str:
    """Push a YARA rule to Microsoft Defender XDR as a custom advanced-hunting detection.

    The YARA rule's ``meta`` block is mined for tags. Requires
    ConOps.blue_team.defender with auth (Graph bearer via env).
    """
    return _json(
        edr.push_defender_xdr_detection(
            rule_name=rule_name,
            yara_rule=yara_rule,
            description=description,
            severity=severity,
            technique_id=technique_id,
        )
    )


@tool
def yara_to_crowdstrike_ioa(
    yara_rule: str,
    description: str = "",
    severity: str = "medium",
    technique_id: str = "",
) -> str:
    """Extract IOC fields from a YARA rule's meta block and push as CrowdStrike IOA.

    The YARA rule must declare ``indicator_type`` (sha256/sha1/md5/ipv4/ipv6/
    domain/filename) and ``indicator_value`` in its ``meta`` block. Pure
    byte-pattern YARA rules can't be expressed as IOAs — the tool returns
    a structured error in that case so the agent can pick a different target.
    """
    return _json(
        edr.push_crowdstrike_ioa(
            yara_rule=yara_rule,
            description=description,
            severity=severity,
            technique_id=technique_id,
        )
    )


DEFENSE_TOOLS = [
    list_siem_targets,
    sigma_to_splunk_savedsearch,
    sigma_to_sentinel_analyticrule,
    sigma_to_elastic_detection_rule,
    yara_to_defender_xdr_custom_detection,
    yara_to_crowdstrike_ioa,
]

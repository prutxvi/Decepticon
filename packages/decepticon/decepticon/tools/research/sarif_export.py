# -*- coding: utf-8 -*-
"""KnowledgeGraph findings → SARIF v2.1.0 export.

The inverse of :mod:`decepticon.tools.research.sarif` (which ingests SARIF
from semgrep/codeql/etc into the graph): this module produces a SARIF v2.1.0
JSON document from an engagement's Finding nodes, suitable for:

- Uploading to GitHub Code Scanning (``github/codeql-action/upload-sarif``).
- Importing into DefectDojo / Snyk Code / Polaris / Veracode.
- Driving CI-pipeline pass/fail gates with severity thresholds.

SARIF spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html

Mapping
-------
Decepticon Finding → SARIF result. Vulnerability/CVE/Weakness nodes
attached via ``VALIDATES`` / ``MAPS_TO`` / ``INSTANCE_OF`` edges enrich
the result's ``ruleId``, ``properties.security-severity`` (CVSS), and
``taxa`` (CWE).

Severity:

  Decepticon → SARIF level     → security-severity
  critical    error             10.0
  high        error              7.0
  medium      warning            5.0
  low         note               3.0
  info        none               0.0
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

_TOOL_NAME = "Decepticon"
_TOOL_INFORMATION_URI = "https://decepticon.red"

_LEVEL_MAP = {
    "critical": ("error", 10.0),
    "high": ("error", 7.0),
    "medium": ("warning", 5.0),
    "low": ("note", 3.0),
    "info": ("none", 0.0),
    "informational": ("none", 0.0),
}


def _severity_to_sarif(sev: str | None) -> tuple[str, float]:
    if not sev:
        return _LEVEL_MAP["medium"]
    return _LEVEL_MAP.get(sev.lower(), _LEVEL_MAP["medium"])


def _string_or_empty(value: Any) -> str:
    return str(value) if value else ""


def _finding_rule_id(node: Any, props: dict[str, Any]) -> str:
    cwe = props.get("cwe") or ""
    cve = props.get("cve") or ""
    technique = props.get("mitre_attack") or props.get("technique_id") or ""
    klass = props.get("vuln_class") or ""
    if cve:
        return f"decepticon/{cve}"
    if cwe:
        return (
            f"decepticon/CWE-{cwe}"
            if not str(cwe).upper().startswith("CWE-")
            else f"decepticon/{cwe}"
        )
    if klass:
        return f"decepticon/{klass}"
    if technique:
        return f"decepticon/{technique}"
    label = getattr(node, "label", None) or props.get("title") or "finding"
    sanitized = "".join(c if c.isalnum() or c in "-_." else "_" for c in str(label))
    return f"decepticon/{sanitized}"


def _result_locations(props: dict[str, Any]) -> list[dict[str, Any]]:
    file_path = props.get("file") or props.get("uri") or props.get("file_path")
    if not file_path:
        return []
    region: dict[str, Any] = {}
    start_line = props.get("start_line") or props.get("line")
    end_line = props.get("end_line")
    if start_line is not None:
        try:
            region["startLine"] = int(start_line)
        except (TypeError, ValueError):
            pass
    if end_line is not None:
        try:
            region["endLine"] = int(end_line)
        except (TypeError, ValueError):
            pass
    location: dict[str, Any] = {
        "physicalLocation": {
            "artifactLocation": {"uri": str(file_path)},
        }
    }
    if region:
        location["physicalLocation"]["region"] = region
    return [location]


def _build_rule(rule_id: str, finding_props: dict[str, Any]) -> dict[str, Any]:
    description = finding_props.get("description") or finding_props.get("title") or rule_id
    _, security_severity = _severity_to_sarif(finding_props.get("severity"))
    rule: dict[str, Any] = {
        "id": rule_id,
        "name": finding_props.get("title") or rule_id,
        "shortDescription": {"text": _string_or_empty(finding_props.get("title")) or rule_id},
        "fullDescription": {"text": _string_or_empty(description)},
        "helpUri": _TOOL_INFORMATION_URI,
        "properties": {
            "security-severity": f"{security_severity:.1f}",
            "tags": [
                tag
                for tag in [
                    finding_props.get("vuln_class"),
                    finding_props.get("mitre_attack"),
                    finding_props.get("severity"),
                ]
                if tag
            ],
        },
    }
    return rule


_FINDING_KINDS = frozenset({"finding", "vulnerability", "candidate"})


def _kind_label(kind: Any) -> str:
    """Reduce a node kind to a lowercase string so enum and str inputs compare equal."""
    if kind is None:
        return ""
    name = getattr(kind, "name", None) or getattr(kind, "value", None) or kind
    return str(name).lower()


def _iter_findings(graph: Any):
    """Yield (node, props) pairs for every Finding-like node in the graph.

    Accepts both decepticon_core ``NodeKind`` enum values and string kinds
    on the input nodes; classification is by lowercase string equivalence
    so duck-typed test doubles work without importing decepticon_core.
    """
    nodes = getattr(graph, "nodes", None)
    if nodes is None:
        return
    for node in nodes.values() if hasattr(nodes, "values") else nodes:
        if _kind_label(getattr(node, "kind", None)) not in _FINDING_KINDS:
            continue
        props = dict(getattr(node, "props", None) or getattr(node, "properties", {}) or {})
        if not props.get("severity"):
            props["severity"] = "medium"
        yield node, props


def export_findings_to_sarif(
    graph: Any,
    *,
    engagement_name: str = "Decepticon Engagement",
    tool_version: str = "0.0.0",
) -> dict[str, Any]:
    """Build a SARIF v2.1.0 document from a KnowledgeGraph's findings.

    The graph argument is duck-typed (``.nodes`` returns Node-like objects
    carrying ``kind``, ``label``, ``properties``) so this module doesn't
    pull in the heavyweight decepticon_core import path until call time.
    """
    rules_by_id: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for node, props in _iter_findings(graph):
        rule_id = _finding_rule_id(node, props)
        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = _build_rule(rule_id, props)
        level, security_severity = _severity_to_sarif(props.get("severity"))
        message_text = (
            props.get("description")
            or props.get("title")
            or getattr(node, "label", None)
            or rule_id
        )
        result: dict[str, Any] = {
            "ruleId": rule_id,
            "level": level,
            "message": {"text": str(message_text)},
            "properties": {
                "security-severity": f"{security_severity:.1f}",
                "decepticon-finding-id": getattr(node, "id", None),
                "decepticon-engagement": engagement_name,
            },
        }
        locations = _result_locations(props)
        if locations:
            result["locations"] = locations
        results.append(result)

    document: dict[str, Any] = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": tool_version,
                        "informationUri": _TOOL_INFORMATION_URI,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
                "properties": {
                    "decepticon-engagement": engagement_name,
                    "decepticon-finding-count": len(results),
                },
            }
        ],
    }
    return document


def write_sarif(
    graph: Any,
    output_path: str | Path,
    *,
    engagement_name: str = "Decepticon Engagement",
    tool_version: str = "0.0.0",
) -> Path:
    """Serialize :func:`export_findings_to_sarif` to ``output_path``."""
    doc = export_findings_to_sarif(
        graph, engagement_name=engagement_name, tool_version=tool_version
    )
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(doc, indent=2, ensure_ascii=False), encoding="utf-8")
    return out


def severity_threshold_breach(document: dict[str, Any], *, fail_on: str = "high") -> bool:
    """Return True when the SARIF doc contains a result at or above ``fail_on``.

    Used by CI gates: ``decepticon scan ... --fail-on high`` → exit non-zero
    when any finding hits high or critical.
    """
    threshold = _LEVEL_MAP.get(fail_on.lower(), _LEVEL_MAP["high"])[1]
    for run in document.get("runs") or []:
        for result in run.get("results") or []:
            props = result.get("properties") or {}
            try:
                sev = float(props.get("security-severity") or 0.0)
            except (TypeError, ValueError):
                sev = 0.0
            if sev >= threshold:
                return True
    return False

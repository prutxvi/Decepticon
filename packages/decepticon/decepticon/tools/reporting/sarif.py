"""SARIF v2.1.0 report renderer for the engagement knowledge graph.

Emits a SARIF log that GitHub code scanning, DefectDojo, and other
SARIF-aware aggregators can ingest. The renderer reuses the same
graph state populated from ``workspace/findings/FIND-NNN.md`` so it
stays consistent with HackerOne / Bugcrowd / executive exports.

Field mapping follows the SARIF v2.1.0 OASIS spec:
https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Iterable
from typing import Any

from decepticon_core.types.kg import KnowledgeGraph, Node, NodeKind

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)
DRIVER_NAME = "Decepticon"
DRIVER_INFORMATION_URI = "https://github.com/PurpleAILAB/Decepticon"

_DEFAULT_INCLUDE_KINDS: tuple[NodeKind, ...] = (NodeKind.VULNERABILITY, NodeKind.FINDING)
_RULE_ID_SAFE = re.compile(r"[^A-Za-z0-9_.\-:]+")


def render_sarif(
    graph: KnowledgeGraph,
    *,
    engagement_id: str = "Engagement",
    include_kinds: Iterable[NodeKind] = _DEFAULT_INCLUDE_KINDS,
) -> str:
    """Render the matching graph nodes as SARIF v2.1.0 JSON text.

    Returned text is UTF-8 JSON. The structure passes the SARIF v2.1.0
    schema validation and the GitHub ``upload-sarif`` action's parser.
    """
    include_set = set(include_kinds)
    nodes = [
        n for n in sorted(graph.nodes.values(), key=lambda x: x.created_at) if n.kind in include_set
    ]

    rules, rule_index_by_id = _build_rules(nodes)
    results = [_result_for(node, rule_index_by_id) for node in nodes]

    sarif_log: dict[str, Any] = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": DRIVER_NAME,
                        "informationUri": DRIVER_INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "automationDetails": {"id": f"{engagement_id}/sarif"},
                "results": results,
            }
        ],
    }
    return json.dumps(sarif_log, indent=2, ensure_ascii=False)


def _build_rules(
    nodes: Iterable[Node],
) -> tuple[list[dict[str, Any]], dict[str, int]]:
    rules: list[dict[str, Any]] = []
    index_by_id: dict[str, int] = {}
    for node in nodes:
        rule_id = _stable_rule_id(node)
        if rule_id in index_by_id:
            continue
        title = _node_title(node)
        description = _node_description(node) or title
        rules.append(
            {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": title},
                "fullDescription": {"text": description},
                "defaultConfiguration": {
                    "level": _sarif_level(node.props.get("severity"), node.props.get("cvss_score"))
                },
            }
        )
        index_by_id[rule_id] = len(rules) - 1
    return rules, index_by_id


def _result_for(node: Node, rule_index_by_id: dict[str, int]) -> dict[str, Any]:
    rule_id = _stable_rule_id(node)
    rule_index = rule_index_by_id.get(rule_id, 0)
    level = _sarif_level(node.props.get("severity"), node.props.get("cvss_score"))
    message_text = _node_description(node) or _node_title(node)

    result: dict[str, Any] = {
        "ruleId": rule_id,
        "ruleIndex": rule_index,
        "level": level,
        "message": {"text": message_text},
        "locations": [_location_for(node)],
        "partialFingerprints": _partial_fingerprints(node),
    }
    tags = _result_tags(node)
    if tags:
        result["properties"] = {"tags": tags}
    return result


def _sarif_level(severity: Any, cvss_score: Any) -> str:
    """Map severity / CVSS to SARIF ``level`` (``error`` / ``warning`` / ``note``).

    Severity has precedence. When severity is missing, fall back to
    numeric CVSS bands (>=7 → error, >=4 → warning, <4 → note).
    """
    if isinstance(severity, str):
        normalized = severity.strip().lower()
        if normalized in ("critical", "high"):
            return "error"
        if normalized == "medium":
            return "warning"
        if normalized in ("low", "info", "informational"):
            return "note"
    try:
        score = float(cvss_score) if cvss_score is not None else None
    except (TypeError, ValueError):
        score = None
    if score is None:
        return "note"
    if score >= 7.0:
        return "error"
    if score >= 4.0:
        return "warning"
    return "note"


def _node_title(node: Node) -> str:
    return str(node.props.get("title") or node.label or node.id)


def _node_description(node: Node) -> str:
    return str(node.props.get("description") or node.props.get("summary") or "")


def _stable_rule_id(node: Node) -> str:
    """Choose a deterministic SARIF rule id for a finding node.

    Preference order: first CWE tag, then sanitized title, then ``node.id``.
    SARIF ``ruleId`` allows any string but de-duplication is by exact match,
    so a stable derivation keeps rule lists tight across runs.
    """
    cwe = node.props.get("cwe")
    if isinstance(cwe, (list, tuple)) and cwe:
        first = str(cwe[0]).strip()
        if first:
            return _normalize_rule_id(first)
    if isinstance(cwe, str) and cwe.strip():
        return _normalize_rule_id(cwe.strip())
    title = _node_title(node).strip()
    if title:
        return _normalize_rule_id(title) or node.id
    return node.id


def _normalize_rule_id(text: str) -> str:
    cleaned = _RULE_ID_SAFE.sub("-", text).strip("-")
    return cleaned[:120] or "rule"


def _location_for(node: Node) -> dict[str, Any]:
    uri = _location_uri(node)
    physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
    line = node.props.get("line")
    if isinstance(line, int) and line > 0:
        physical["region"] = {"startLine": line}
    else:
        try:
            line_int = int(str(line))
            if line_int > 0:
                physical["region"] = {"startLine": line_int}
        except (TypeError, ValueError):
            pass
    return {"physicalLocation": physical}


def _location_uri(node: Node) -> str:
    file_path = node.props.get("file")
    if isinstance(file_path, str) and file_path.strip():
        return file_path.strip()
    url = node.props.get("url")
    if isinstance(url, str) and url.strip():
        return url.strip()
    return f"workspace/findings/{node.id}.md"


def _result_tags(node: Node) -> list[str]:
    tags: list[str] = []
    severity = node.props.get("severity")
    if isinstance(severity, str) and severity.strip():
        tags.append(f"severity:{severity.strip().lower()}")
    cwe = node.props.get("cwe")
    if isinstance(cwe, (list, tuple)):
        for entry in cwe:
            text = str(entry).strip()
            if text:
                tags.append(text)
    elif isinstance(cwe, str) and cwe.strip():
        tags.append(cwe.strip())
    mitre = node.props.get("mitre")
    if isinstance(mitre, (list, tuple)):
        for entry in mitre:
            text = str(entry).strip()
            if text:
                tags.append(text)
    elif isinstance(mitre, str) and mitre.strip():
        tags.append(mitre.strip())
    cvss_vector = node.props.get("cvss_vector")
    if isinstance(cvss_vector, str) and cvss_vector.strip():
        tags.append(cvss_vector.strip())
    return tags


def _partial_fingerprints(node: Node) -> dict[str, str]:
    """Compute deterministic fingerprints so re-runs do not duplicate alerts.

    GitHub code scanning uses ``partialFingerprints`` for alert correlation;
    stable fingerprints prevent the same finding from appearing as a new
    alert on every run.
    """
    cwe = node.props.get("cwe") or []
    cwe_text = ",".join(str(c) for c in cwe) if isinstance(cwe, (list, tuple)) else str(cwe)
    raw = "|".join(
        [
            node.id,
            _node_title(node),
            str(node.props.get("severity", "")),
            str(node.props.get("file") or node.props.get("url") or ""),
            cwe_text,
            str(node.props.get("cvss_vector", "")),
        ]
    )
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return {
        "decepticonFindingId": node.id,
        "decepticonStableHash": digest,
    }

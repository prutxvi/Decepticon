"""YARA → Microsoft Defender XDR + CrowdStrike Falcon custom-detection push.

Microsoft Defender XDR exposes "Custom Detection Rules" via Graph Security
API. We POST the YARA rule body as a custom indicator under the
``customDetections`` resource. The translation step is light — Defender
accepts YARA-style content matching on file properties.

CrowdStrike Falcon exposes IOA-style custom indicators via the ``/iocs``
endpoint. We extract the indicator (hash, filename, IP, domain) from the
YARA rule's metadata and POST it. Pure YARA byte-pattern rules can't be
fully expressed as Falcon IOAs — we surface that as a structured error.
"""

from __future__ import annotations

import json
import re
from typing import Any

from decepticon.tools.defense.conops import (
    ConOpsLookupError,
    engagement_slug,
    resolve_auth_value,
    resolve_siem_target,
)

_YARA_META_PATTERN = re.compile(r"meta\s*:\s*((?:[^{}]|\{[^{}]*\})*)", re.DOTALL)
_YARA_KV_PATTERN = re.compile(r"(\w+)\s*=\s*\"([^\"]*)\"")


def _extract_yara_metadata(yara_text: str) -> dict[str, str]:
    """Return a dict of ``meta`` key=value pairs from a YARA rule body."""
    block_match = _YARA_META_PATTERN.search(yara_text)
    if not block_match:
        return {}
    block = block_match.group(1)
    return {k: v for k, v in _YARA_KV_PATTERN.findall(block)}


def push_defender_xdr_detection(
    rule_name: str,
    yara_rule: str,
    *,
    description: str = "",
    severity: str = "medium",
    technique_id: str = "",
) -> dict[str, Any]:
    """POST a custom detection to Microsoft Defender XDR (Graph Security API)."""
    try:
        target = resolve_siem_target("defender")
    except ConOpsLookupError as exc:
        return {"error": str(exc)}

    auth_spec = target.get("auth")
    if not auth_spec:
        return {"error": "ConOps.blue_team.defender missing ``auth``"}
    try:
        bearer = resolve_auth_value(auth_spec)
    except ConOpsLookupError as exc:
        return {"error": str(exc)}

    tagged = f"decepticon-eng-{engagement_slug()}-{rule_name}"
    meta = _extract_yara_metadata(yara_rule)

    sha256 = meta.get("sha256") or meta.get("hash")
    if sha256:
        kql_query = f'DeviceFileEvents | where SHA256 == "{sha256}"'
    else:
        return {"error": "YARA rule has no extractable indicator for Defender KQL translation"}

    body = {
        "displayName": f"[Decepticon] {rule_name}",
        "description": (
            description
            + f"\n\nEngagement: {engagement_slug()}"
            + (f"\nMITRE ATT&CK: {technique_id}" if technique_id else "")
        ),
        "severity": severity,
        "ruleType": "advancedHunting",
        "queryCondition": {
            "queryLanguage": "kql",
            "queryText": kql_query,
        },
        "tags": [
            f"decepticon-eng-{engagement_slug()}",
            *(meta.get("tags", "").split(",") if meta.get("tags") else []),
            *([technique_id] if technique_id else []),
        ],
    }

    try:
        import requests  # noqa: PLC0415
    except ImportError:
        return {"error": "``requests`` not installed in langgraph container"}

    headers = {
        "Authorization": f"Bearer {bearer}",
        "Content-Type": "application/json",
    }
    url = "https://graph.microsoft.com/beta/security/rules/detectionRules"
    try:
        resp = requests.post(url, headers=headers, data=json.dumps(body), timeout=15)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"Defender POST failed: {exc!r}"}

    if resp.status_code >= 400:
        return {
            "error": f"Defender returned HTTP {resp.status_code}",
            "body": resp.text[:1000],
        }
    return {
        "status": "pushed",
        "rule_id": tagged,
        "engagement_slug": engagement_slug(),
        "technique_id": technique_id,
        "severity": severity,
    }


_CROWDSTRIKE_TYPE_MAP = {
    "sha256": "sha256",
    "sha1": "sha1",
    "md5": "md5",
    "ip": "ipv4",
    "ipv4": "ipv4",
    "ipv6": "ipv6",
    "domain": "domain",
    "url": "domain",
    "filename": "filename",
}


def push_crowdstrike_ioa(
    yara_rule: str,
    *,
    description: str = "",
    severity: str = "medium",
    technique_id: str = "",
) -> dict[str, Any]:
    """POST an IOA-style indicator extracted from a YARA rule to CrowdStrike Falcon."""
    try:
        target = resolve_siem_target("crowdstrike")
    except ConOpsLookupError as exc:
        return {"error": str(exc)}

    base_url = target.get("url")
    auth_spec = target.get("auth")
    if not base_url or not auth_spec:
        return {"error": "ConOps.blue_team.crowdstrike missing ``url`` or ``auth``"}
    try:
        bearer = resolve_auth_value(auth_spec)
    except ConOpsLookupError as exc:
        return {"error": str(exc)}

    meta = _extract_yara_metadata(yara_rule)
    indicator_type_raw = (meta.get("indicator_type") or "").lower()
    indicator_value = meta.get("indicator_value") or meta.get("ioc") or ""

    if not indicator_type_raw or not indicator_value:
        return {
            "error": (
                "CrowdStrike IOA push requires YARA meta ``indicator_type`` and "
                "``indicator_value`` keys. Pure byte-pattern YARA rules cannot be "
                "expressed as IOAs — use a different EDR target."
            )
        }
    cs_type = _CROWDSTRIKE_TYPE_MAP.get(indicator_type_raw)
    if not cs_type:
        return {
            "error": f"indicator_type ``{indicator_type_raw}`` is not in CrowdStrike's supported set"
        }

    body = {
        "indicators": [
            {
                "type": cs_type,
                "value": indicator_value,
                "action": "detect",
                "severity": severity,
                "description": (
                    description
                    + f"\n\nEngagement: {engagement_slug()}"
                    + (f"\nMITRE ATT&CK: {technique_id}" if technique_id else "")
                ),
                "tags": [
                    f"decepticon-eng-{engagement_slug()}",
                    *([technique_id] if technique_id else []),
                ],
                "platforms": ["windows", "mac", "linux"],
                "source": "decepticon",
            }
        ]
    }

    try:
        import requests  # noqa: PLC0415
    except ImportError:
        return {"error": "``requests`` not installed in langgraph container"}

    headers = {
        "Authorization": f"Bearer {bearer}",
        "Content-Type": "application/json",
    }
    endpoint = base_url.rstrip("/") + "/iocs/entities/indicators/v1"
    try:
        resp = requests.post(endpoint, headers=headers, data=json.dumps(body), timeout=15)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"CrowdStrike POST failed: {exc!r}"}

    if resp.status_code >= 400:
        return {
            "error": f"CrowdStrike returned HTTP {resp.status_code}",
            "body": resp.text[:1000],
        }
    return {
        "status": "pushed",
        "indicator_type": cs_type,
        "indicator_value": indicator_value,
        "engagement_slug": engagement_slug(),
        "technique_id": technique_id,
        "severity": severity,
    }

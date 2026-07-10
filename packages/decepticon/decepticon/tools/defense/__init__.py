from __future__ import annotations
"""Defense tool bundle — push Detector/Patcher output to live blue-team stacks.

The Offensive Vaccine pipeline generates Sigma rules, YARA signatures, and
recommended patches as engagement artifacts. Historically those artifacts
landed in markdown files and waited for a human to type them into Splunk /
Sentinel / Elastic by hand. This package gives Defender + Patcher agents
@tool functions that push directly to the customer's SIEM / EDR, with the
deconfliction metadata (engagement slug, target scope, technique ID)
already embedded in the rule.

Tool inventory
--------------
- ``sigma_to_splunk_savedsearch`` — push a Sigma rule into Splunk via HEC.
- ``sigma_to_sentinel_analyticrule`` — push a Sigma rule into Azure Sentinel.
- ``sigma_to_elastic_detection_rule`` — push a Sigma rule into Elastic
  Detection Engine via Kibana API.
- ``yara_to_defender_xdr_custom_detection`` — push a YARA rule into
  Microsoft Defender XDR as a custom detection.
- ``yara_to_crowdstrike_ioa`` — push a YARA rule into CrowdStrike Falcon
  as an IOA-style custom indicator.
- ``list_siem_targets`` — read-only enumeration of which SIEM endpoints
  the current engagement's ConOps has wired credentials for.

All push tools share a contract:

- ConOps must declare the SIEM endpoint (URL + auth method) under
  ``conops.blue_team.<target>``. Tools refuse to push to undeclared
  endpoints; the agent gets a structured error pointing at the missing
  ConOps key.
- Every pushed rule carries a Decepticon-scoped tag prefix
  (``decepticon-eng-<slug>``) so blue-team operators can identify and
  disable the rule after the engagement ends.
- Tools are idempotent: re-pushing the same rule replaces the prior copy
  by rule_id rather than duplicating.
"""

from decepticon.tools.defense.tools import DEFENSE_TOOLS

__all__ = ["DEFENSE_TOOLS"]

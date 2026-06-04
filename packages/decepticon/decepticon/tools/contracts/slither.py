"""Slither ``--json`` → KGStore observations (engagement-scoped).

Slither (https://github.com/crytic/slither) is the de-facto Solidity
static analyser. Its ``--json -`` output carries a
``results.detectors`` array of structured findings (~85 detectors
across 5 impact tiers). This module parses that payload, builds
observation dicts conforming to :meth:`KGStore.record_observations`,
and writes them in a single atomic batch.

Compared to the legacy ``KnowledgeGraph`` -based ingest this replaces,
the rewrite addresses six of the load-bearing traps catalogued in
``docs/design/2026-06-04-slither-kgstore-mapping.md`` §2.6:

  1. **Same vuln, multiple elements** — one finding can list N
     elements (a reentrancy spans the call site + storage write +
     function). The legacy ingest only kept the first element. We
     now emit one ``Vulnerability`` node + N ``AFFECTS`` edges, one
     per element.
  2. **Stable detector id used as the dedup key** — Slither emits a
     SHA3-256 hash over the element descriptions per finding that is
     stable across reruns of the same source. The legacy ingest
     keyed on ``check::file::line`` (which churned when the file
     gained a blank line above the finding); we now use the Slither
     hash directly so re-ingest is idempotent.
  3. **Recursive parent walk** — ``element.type_specific_fields.parent``
     nests arbitrarily (node → function → contract). The legacy code
     looked one level deep only; we recurse until ``type=="contract"``
     so the owning contract is correctly identified.
  4. **``lines`` is a list of individual line numbers** — not a
     ``[start, end]`` range. Iterating it as a range silently misses
     multi-line functions with gaps. We preserve the raw list as the
     ``lines`` prop on the source-mapped node.
  5. **Optimization impact normalised** — some Slither versions emit
     ``Optimization`` lowercased in JSON. We normalise via
     ``str.title()`` before mapping to severity.
  6. **``success=False`` short-circuit + ``upgradeability-check``
     skip** — a failed Slither run carries an ``error`` string and
     no detector data; the upgradeability-check block lives parallel
     to ``detectors`` with a different (proxy/impl diff) schema. We
     never partial-ingest from a failed run, and we never feed the
     upgradeability block through the detector pipeline.

Every Solidity element lands under its **dedicated V003 NodeKind**
(``Function`` / ``StateVar`` / ``Event`` / ``CustomError`` /
``Enum`` / ``Struct`` / ``Pragma``). ``Contract`` and ``SourceFile``
were already on dedicated labels. The ``element_type`` prop is
preserved on every node so consumers that still filter by
``element_type`` (e.g. AST ``node`` entries that fall back to
``CodeLocation``) keep working. Slither RFC §4.6 endgame for the
contract-auditor side.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from decepticon.middleware.kg_internal.store import KGStore
from decepticon_core.types.kg import EdgeKind, NodeKind, Severity
from decepticon_core.utils.logging import get_logger

log = get_logger("contracts.slither")


_IMPACT_TO_SEVERITY: dict[str, Severity] = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
    "Optimization": Severity.INFO,
}


# Element types Slither emits in ``finding.elements[]``. Each maps
# to its dedicated Solidity NodeKind from V003 (Option A). AST
# ``node`` and ``modifier`` entries fall back to ``CODE_LOCATION``
# / ``SOLIDITY_FUNCTION`` respectively — they don't carry a
# distinct V003 label and folding them into the closest semantic
# kind keeps Cypher queries readable. The ``element_type`` prop
# survives on every node so downstream queries can still
# distinguish a modifier from a regular function.
_ELEMENT_KIND_MAP: dict[str, NodeKind] = {
    "contract": NodeKind.CONTRACT,
    "function": NodeKind.SOLIDITY_FUNCTION,
    "modifier": NodeKind.SOLIDITY_FUNCTION,
    "variable": NodeKind.SOLIDITY_STATE_VAR,
    "node": NodeKind.CODE_LOCATION,
    "pragma": NodeKind.SOLIDITY_PRAGMA,
    "event": NodeKind.SOLIDITY_EVENT,
    "custom_error": NodeKind.SOLIDITY_CUSTOM_ERROR,
    "enum": NodeKind.SOLIDITY_ENUM,
    "struct": NodeKind.SOLIDITY_STRUCT,
    "file": NodeKind.SOURCE_FILE,
}


@dataclass
class _IngestState:
    """Observation accumulator.

    Mutated in place by per-finding helpers; flushed in a single
    ``record_observations`` call when the parse finishes.
    """

    obs_by_key: dict[str, dict[str, Any]] = field(default_factory=dict)
    finding_count: int = 0
    edge_count: int = 0

    def upsert_observation(
        self,
        *,
        kind: NodeKind,
        key: str,
        label: str,
        props: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        existing = self.obs_by_key.get(key)
        if existing is None:
            obs: dict[str, Any] = {
                "kind": kind.value,
                "key": key,
                "label": label,
                "props": {k: v for k, v in (props or {}).items() if v is not None},
                "edges_out": [],
            }
            self.obs_by_key[key] = obs
            return obs
        if props:
            existing.setdefault("props", {}).update(
                {k: v for k, v in props.items() if v is not None}
            )
        if label and not existing.get("label"):
            existing["label"] = label
        return existing

    def add_edge(
        self,
        *,
        src_key: str,
        dst_key: str,
        kind: EdgeKind,
        props: dict[str, Any] | None = None,
    ) -> None:
        src_obs = self.obs_by_key.get(src_key)
        if src_obs is None:
            return
        src_obs.setdefault("edges_out", []).append(
            {
                "to_key": dst_key,
                "kind": kind.value,
                "weight": 1.0,
                "props": props or {},
            }
        )
        self.edge_count += 1


# ── Key builders ────────────────────────────────────────────────────


def _vuln_key(check: str, slither_id: str) -> str:
    """Slither's per-finding ``id`` is a stable sha3-256 hash; we
    prefix with ``slither::vuln::{check}::`` to keep human-readable
    scanning of the graph easy."""
    return f"slither::vuln::{check}::{slither_id}"


def _file_key(filename_relative: str) -> str:
    return f"slither::file::{filename_relative}"


def _element_key(element_type: str, filename: str, name: str, src_start: Any) -> str:
    """Element keys are composed of (element_type, filename, name) so
    the same function across re-ingest dedups to one node; we also
    fold the source ``start`` offset for elements that share a name
    across overload (e.g. constructor overload arms)."""
    return f"slither::el::{element_type}::{filename}::{name}::{src_start}"


# ── Element walker ──────────────────────────────────────────────────


def _walk_parent_to_contract(element: dict[str, Any]) -> str | None:
    """Recurse through ``type_specific_fields.parent`` until a contract
    is found. Returns the contract name, or ``None`` if the chain
    never lands on a contract (pragma / file elements legitimately
    have no contract context)."""
    type_specific = element.get("type_specific_fields")
    if not isinstance(type_specific, dict):
        return None
    parent = type_specific.get("parent")
    while isinstance(parent, dict):
        if parent.get("type") == "contract":
            name = parent.get("name")
            return name if isinstance(name, str) else None
        nested = parent.get("type_specific_fields")
        if not isinstance(nested, dict):
            return None
        parent = nested.get("parent")
    return None


def _ingest_element(
    state: _IngestState,
    *,
    element: dict[str, Any],
    vuln_key: str,
) -> None:
    """Emit a node for one ``finding.elements[i]`` + an ``AFFECTS``
    edge from the vuln. Returns silently when the element has no
    recognisable type or source mapping."""
    element_type = element.get("type")
    if not isinstance(element_type, str):
        return
    kind = _ELEMENT_KIND_MAP.get(element_type, NodeKind.CODE_LOCATION)
    source_mapping = element.get("source_mapping")
    source_mapping = source_mapping if isinstance(source_mapping, dict) else {}

    # Trap 3: prefer ``filename_relative`` over absolute / used /
    # short. Absolute leaks host fs into engagement-scoped data;
    # filename_used may be IDE-normalised.
    filename = (
        source_mapping.get("filename_relative")
        or source_mapping.get("filename_short")
        or source_mapping.get("filename_used")
        or source_mapping.get("filename_absolute")
        or ""
    )
    if not isinstance(filename, str):
        filename = ""

    name = element.get("name")
    name = name if isinstance(name, str) else ""
    src_start = source_mapping.get("start")

    # Pragmas attach directly to a SourceFile; everything else
    # carries a parent_contract derived by walking the parent chain.
    parent_contract = _walk_parent_to_contract(element)

    type_specific = element.get("type_specific_fields")
    type_specific = type_specific if isinstance(type_specific, dict) else {}
    signature = type_specific.get("signature")
    directive = type_specific.get("directive")

    # ``lines`` is a list of individual numbers, not a range — see
    # trap 4. We store the raw list and a convenience ``first_line``
    # so the analyst can sort without re-parsing.
    lines = source_mapping.get("lines")
    lines = lines if isinstance(lines, list) else []
    first_line = lines[0] if lines else None

    if element_type == "file":
        # ``file`` elements describe the SourceFile itself; reuse the
        # file key so the AFFECTS edge lands on the canonical node.
        if not filename:
            return
        key = _file_key(filename)
        label = filename
        props: dict[str, Any] = {
            "element_type": element_type,
            "path": filename,
        }
    else:
        key = _element_key(element_type, filename, name, src_start)
        label = (
            signature
            if isinstance(signature, str) and signature
            else f"{element_type}:{name}"
            if name
            else element_type
        )
        props = {
            "element_type": element_type,
            "name": name or None,
            "signature": signature if isinstance(signature, str) else None,
            "directive": directive if isinstance(directive, str) else None,
            "filename": filename or None,
            "parent_contract": parent_contract,
            "lines": lines or None,
            "first_line": first_line,
            "src_start": src_start,
            "src_length": source_mapping.get("length"),
        }

    state.upsert_observation(kind=kind, key=key, label=label, props=props)

    # Vuln -[AFFECTS]-> element
    state.add_edge(
        src_key=vuln_key,
        dst_key=key,
        kind=EdgeKind.AFFECTS,
        props={"element_type": element_type},
    )

    # Element -[CONTAINED_IN]-> SourceFile (filename-bearing only)
    if filename and element_type != "file":
        file_key = _file_key(filename)
        state.upsert_observation(
            kind=NodeKind.SOURCE_FILE,
            key=file_key,
            label=filename,
            props={"path": filename, "element_type": "file"},
        )
        state.add_edge(
            src_key=key,
            dst_key=file_key,
            kind=EdgeKind.DEFINED_IN,
            props={"reason": "source_file"},
        )

    # Function / variable / event / ... -[DEFINED_IN]-> contract
    if parent_contract and element_type not in {"contract", "file", "pragma"}:
        contract_key = _element_key("contract", filename, parent_contract, None)
        state.upsert_observation(
            kind=NodeKind.CONTRACT,
            key=contract_key,
            label=parent_contract,
            props={
                "element_type": "contract",
                "name": parent_contract,
                "filename": filename or None,
            },
        )
        state.add_edge(
            src_key=key,
            dst_key=contract_key,
            kind=EdgeKind.DEFINED_IN,
            props={"reason": "owning_contract"},
        )


# ── Finding-level ingest ────────────────────────────────────────────


def _ingest_finding(state: _IngestState, finding: dict[str, Any]) -> None:
    check = finding.get("check") or "unknown"
    if not isinstance(check, str):
        return

    # Slither's stable per-finding id (sha3-256 over element
    # descriptions). The upstream schema has emitted this for every
    # finding since 2020; fail-fast if it is missing so the operator
    # can pin a Slither version that does emit it instead of silently
    # creating churning Vulnerability nodes on every re-ingest.
    slither_id = finding.get("id")
    if not isinstance(slither_id, str) or not slither_id:
        raise ValueError(
            f"slither finding for check={check!r} is missing the stable 'id' field; "
            "upgrade slither to a version that emits per-finding sha3-256 ids "
            "(any release since 2020)."
        )

    raw_impact = finding.get("impact") or "Medium"
    if isinstance(raw_impact, str):
        # Trap 5: some Slither builds emit ``optimization`` lowercased.
        normalized_impact = raw_impact.title() if raw_impact else "Medium"
    else:
        normalized_impact = "Medium"
    severity = _IMPACT_TO_SEVERITY.get(normalized_impact, Severity.MEDIUM)
    confidence = finding.get("confidence") or "Medium"
    description = finding.get("description") or ""
    markdown = finding.get("markdown") or ""
    first_md_el = finding.get("first_markdown_element") or ""

    # Single source of truth for the finding's key.
    vuln_key = _vuln_key(check, slither_id)

    # First-line description as a human-readable suffix on the label.
    first_line = description.strip().splitlines()[0][:80] if description else check
    label = f"[slither:{check}] {first_line}"

    additional_fields = finding.get("additional_fields")
    additional_fields = additional_fields if isinstance(additional_fields, dict) else {}

    state.upsert_observation(
        kind=NodeKind.VULNERABILITY,
        key=vuln_key,
        label=label,
        props={
            "scanner": "slither",
            "rule_id": check,
            "slither_id": slither_id,
            "severity": severity.value,
            "impact": normalized_impact,
            "confidence": confidence,
            "description": description,
            "markdown": markdown[:2000],
            "first_markdown_element": first_md_el,
            "additional_fields": (
                json.dumps(additional_fields, default=str) if additional_fields else None
            ),
        },
    )
    state.finding_count += 1

    # Trap 1: emit one observation per element instead of collapsing
    # onto the first one. Each element becomes an ``AFFECTS`` edge.
    elements = finding.get("elements") or []
    if isinstance(elements, list):
        for element in elements:
            if isinstance(element, dict):
                _ingest_element(state, element=element, vuln_key=vuln_key)


# ── Public API ──────────────────────────────────────────────────────


def ingest_slither_json(
    data: str | dict[str, Any],
    *,
    engagement: str,
    store: KGStore | None = None,
    source_episode_id: str = "slither_ingest",
) -> int:
    """Merge one Slither ``--json`` payload into the engagement KG.

    Returns the count of detector findings successfully ingested.
    Short-circuits to 0 when Slither reports ``success=false`` — a
    failed run does not partial-ingest.
    """
    if isinstance(data, str):
        try:
            payload = json.loads(data)
        except json.JSONDecodeError as exc:
            log.warning("slither json parse failed: %s", exc)
            return 0
    else:
        payload = data

    if not isinstance(payload, dict):
        return 0

    # Trap 6: ``success=false`` carries no detector data. Refuse to
    # partial-ingest from a failed run.
    if payload.get("success") is False:
        log.warning(
            "slither run reported success=false; skipping ingest: %s",
            payload.get("error"),
        )
        return 0

    results = payload.get("results")
    results = results if isinstance(results, dict) else {}
    # ``upgradeability-check`` lives parallel to ``detectors`` with a
    # different schema; do NOT feed it through the detector pipeline.
    detectors = results.get("detectors")
    if not isinstance(detectors, list) or not detectors:
        return 0

    state = _IngestState()
    for finding in detectors:
        if isinstance(finding, dict):
            _ingest_finding(state, finding)

    observations = list(state.obs_by_key.values())
    if not observations:
        return 0

    owned_store = store is None
    target_store = store if store is not None else KGStore.from_env()
    try:
        target_store.record_observations(
            observations,
            engagement=engagement,
            created_by="slither_ingest",
            source_episode_id=source_episode_id,
        )
    finally:
        if owned_store:
            target_store.close()

    return state.finding_count


def ingest_slither_file(
    path: str | Path,
    *,
    engagement: str,
    store: KGStore | None = None,
    source_episode_id: str = "slither_ingest",
) -> int:
    """Convenience wrapper: read JSON from disk and ingest."""
    p = Path(path)
    try:
        data = p.read_text(encoding="utf-8")
    except OSError as exc:
        log.warning("slither file read failed: %s", exc)
        return 0
    return ingest_slither_json(
        data,
        engagement=engagement,
        store=store,
        source_episode_id=source_episode_id,
    )

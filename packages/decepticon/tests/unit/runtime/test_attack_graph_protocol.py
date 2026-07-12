# -*- coding: utf-8 -*-
"""Structural tests for :class:`AttackGraphProtocol`.

The protocol is the CART ↔ KGMiddleware contract — any object that
exposes ``revision(*, engagement)`` and ``snapshot(*, engagement)``
must satisfy ``isinstance(obj, AttackGraphProtocol)``. Filling in the
docstring vaporware that lived in ``cart.py`` since the module's first
commit.
"""

from __future__ import annotations

from typing import Any

from decepticon.runtime.cart import AttackGraphProtocol, EngagementSnapshot


class _Conforming:
    """Minimal implementation that should satisfy the Protocol."""

    def revision(self, *, engagement: str) -> str:
        return f"rev-{engagement}-1"

    def snapshot(self, *, engagement: str) -> EngagementSnapshot:
        return EngagementSnapshot(
            snapshot_id="s-1",
            captured_at=0.0,
            nodes={},
            edges={},
        )


class _MissingSnapshot:
    """Has revision but not snapshot — should NOT satisfy the Protocol."""

    def revision(self, *, engagement: str) -> str:
        return "rev-1"


class _MissingRevision:
    """Has snapshot but not revision — should NOT satisfy the Protocol."""

    def snapshot(self, *, engagement: str) -> EngagementSnapshot:
        return EngagementSnapshot(snapshot_id="s-1", captured_at=0.0, nodes={}, edges={})


def test_conforming_instance_satisfies_protocol() -> None:
    """A class with both required methods registers as the Protocol."""
    instance: Any = _Conforming()
    assert isinstance(instance, AttackGraphProtocol)


def test_missing_snapshot_rejected() -> None:
    """Missing ``snapshot`` invalidates structural conformance."""
    instance: Any = _MissingSnapshot()
    assert not isinstance(instance, AttackGraphProtocol)


def test_missing_revision_rejected() -> None:
    """Missing ``revision`` invalidates structural conformance."""
    instance: Any = _MissingRevision()
    assert not isinstance(instance, AttackGraphProtocol)


def test_revision_returns_string() -> None:
    """The revision token is opaque but must be a string for hashing/comparison."""
    store = _Conforming()
    rev = store.revision(engagement="acme-q2")
    assert isinstance(rev, str)
    assert rev  # non-empty


def test_snapshot_returns_engagement_snapshot() -> None:
    """The snapshot return type matches :class:`EngagementSnapshot` for diffability."""
    store = _Conforming()
    snap = store.snapshot(engagement="acme-q2")
    assert isinstance(snap, EngagementSnapshot)
    assert snap.snapshot_id
    assert isinstance(snap.nodes, dict)
    assert isinstance(snap.edges, dict)


def test_revision_changes_with_engagement_arg() -> None:
    """Each engagement gets its own revision token; CART relies on this for scoping."""
    store = _Conforming()
    assert store.revision(engagement="acme-q2") != store.revision(engagement="other-eng")


def test_protocol_is_runtime_checkable() -> None:
    """``isinstance(obj, AttackGraphProtocol)`` must not raise on arbitrary objects."""
    # If the Protocol were not @runtime_checkable, the next line would raise.
    assert isinstance(_Conforming(), AttackGraphProtocol)
    assert not isinstance("a plain string", AttackGraphProtocol)
    assert not isinstance(42, AttackGraphProtocol)

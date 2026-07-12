# -*- coding: utf-8 -*-
"""PluginRegistry behavior — entry-point walk + collision detection.

Closes spec §14 acceptance #9: ``PluginRegistry.detect_collisions()``
returns a non-empty list when two test plugins both register the
same key in the same entry-point group.

Uses monkeypatch against ``importlib.metadata.entry_points`` to
simulate plugins without installing actual wheel packages.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

import pytest

from decepticon_core.registry import (
    PluginConflictWarning,
    PluginInfo,
    PluginRegistry,
)
from decepticon_core.registry import plugins as plugins_module


@dataclass(frozen=True)
class _FakeDist:
    """Minimal stand-in for ``importlib.metadata.Distribution``."""

    name: str


@dataclass(frozen=True)
class _FakeEntryPoint:
    """Minimal stand-in for ``importlib.metadata.EntryPoint`` carrying
    just the attributes ``PluginRegistry._build_singleton`` reads."""

    name: str
    value: str
    dist: _FakeDist | None


def _patch_entry_points(
    monkeypatch: pytest.MonkeyPatch,
    by_group: dict[str, list[_FakeEntryPoint]],
) -> None:
    """Replace ``importlib.metadata.entry_points`` in plugins.py with a
    closure that returns the fake list for the requested group."""

    def fake(*args: Any, group: str | None = None, **kwargs: Any) -> Iterator[_FakeEntryPoint]:
        del args, kwargs
        return iter(by_group.get(group or "", []))

    monkeypatch.setattr(plugins_module, "entry_points", fake)
    PluginRegistry.reset()


def test_no_plugins_means_no_collisions(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_entry_points(monkeypatch, {})
    reg = PluginRegistry.load()
    assert reg.list_plugins() == ()
    assert reg.detect_collisions() == ()


def test_single_plugin_per_group_yields_one_plugin_info(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch_entry_points(
        monkeypatch,
        {
            "decepticon.tools": [
                _FakeEntryPoint("scan", "pkg_scan:tools", _FakeDist("pkg-scan")),
            ],
        },
    )
    reg = PluginRegistry.load()
    plugins = reg.list_plugins()
    assert plugins == (
        PluginInfo(
            name="scan",
            package="pkg-scan",
            bundle=None,
            groups=("decepticon.tools",),
        ),
    )
    assert reg.detect_collisions() == ()


def test_same_name_in_same_group_from_different_packages_collides(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Spec §14 #9 — two plugins registering ``bash`` under
    ``decepticon.tools`` must surface a PluginConflictWarning."""
    _patch_entry_points(
        monkeypatch,
        {
            "decepticon.tools": [
                _FakeEntryPoint("bash", "pkg_a:tools", _FakeDist("pkg-a")),
                _FakeEntryPoint("bash", "pkg_b:tools", _FakeDist("pkg-b")),
            ],
        },
    )
    reg = PluginRegistry.load()
    collisions = reg.detect_collisions()
    assert len(collisions) == 1
    c = collisions[0]
    assert isinstance(c, PluginConflictWarning)
    assert c.key == "bash"
    assert c.kind == "decepticon.tools"
    assert c.previous_owner == "pkg-a"
    assert c.owner == "pkg-b"


def test_same_name_same_package_does_not_collide(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A plugin registering under multiple groups is one PluginInfo,
    not a collision."""
    _patch_entry_points(
        monkeypatch,
        {
            "decepticon.tools": [
                _FakeEntryPoint("audit", "pkg:tools", _FakeDist("pkg")),
            ],
            "decepticon.middleware": [
                _FakeEntryPoint("audit", "pkg:middleware", _FakeDist("pkg")),
            ],
        },
    )
    reg = PluginRegistry.load()
    assert reg.detect_collisions() == ()
    plugins = reg.list_plugins()
    assert len(plugins) == 1
    assert plugins[0].name == "audit"
    assert plugins[0].package == "pkg"
    assert plugins[0].groups == ("decepticon.middleware", "decepticon.tools")


def test_get_plugin_by_name(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch_entry_points(
        monkeypatch,
        {
            "decepticon.subagents": [
                _FakeEntryPoint("recon", "pkg:recon", _FakeDist("pkg-recon")),
            ],
        },
    )
    reg = PluginRegistry.load()
    info = reg.get_plugin("recon")
    assert info is not None
    assert info.name == "recon"
    assert reg.get_plugin("nonexistent") is None

# -*- coding: utf-8 -*-
"""Cross-package import discipline (spec §11.4).

``decepticon-core`` is the contract layer. By design it must NEVER
import ``langchain`` / ``langgraph`` / ``deepagents`` / ``httpx`` /
``fastapi``. Plugin authors pin core without dragging the framework
runtime in.

Runs the discipline check in a **fresh subprocess** so pytest's own
test-collection imports (which can transitively load ``httpx`` via
the framework's tests) don't pollute the result. The subprocess
imports every submodule of ``decepticon_core`` and reports any
forbidden module that ended up in ``sys.modules``.

Defence in depth: a future Ruff ``flake8-tidy-imports.banned-api``
rule will catch import-statement violations at lint time. This test
catches transitive pulls — a module that imports ``something_safe``
which in turn imports ``httpx``.
"""

from __future__ import annotations

import subprocess
import sys

_PROBE_SCRIPT = """
import importlib
import pkgutil
import sys

import decepticon_core

before = set(sys.modules)
for module_info in pkgutil.walk_packages(
    decepticon_core.__path__,
    prefix='decepticon_core.',
):
    importlib.import_module(module_info.name)

forbidden = {
    'langchain', 'langchain_core', 'langchain_anthropic', 'langchain_openai',
    'langgraph', 'deepagents',
    'httpx', 'fastapi', 'uvicorn',
}
new = set(sys.modules) - before
# Account for the modules pulled in by `import decepticon_core` itself
# at the top of this probe — those are part of the contract layer's
# direct dependency surface and should also be free of forbidden imports.
leak = forbidden & set(sys.modules)
if leak:
    print(','.join(sorted(leak)))
    sys.exit(1)
sys.exit(0)
"""


def test_core_has_no_runtime_deps() -> None:
    """Spec §11.4 — decepticon_core must not transitively pull in
    langchain / langgraph / deepagents / httpx / fastapi.

    Defends the contract layer's pure-pydantic-plus-stdlib promise so
    plugin authors that depend on ``decepticon-core`` only never
    accidentally inherit the framework's heavyweight runtime.
    """
    result = subprocess.run(
        [sys.executable, "-c", _PROBE_SCRIPT],
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert result.returncode == 0, (
        f"decepticon-core leaked runtime imports for {result.stdout.strip()!r}; "
        "the contract layer must stay langchain/langgraph/deepagents-free "
        f"(spec §11.4). stderr:\n{result.stderr}"
    )

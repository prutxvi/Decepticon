"""Custom tool contributed to Decepticon."""

from __future__ import annotations

from decepticon_sdk import ToolProtocol


class HelloTool:
    """Minimal ToolProtocol-compliant tool."""

    name = "decepticon_example_tool"
    description = "Hello-world tool scaffolded by decepticon-sdk."

    def invoke(self, input: object, *, config: object | None = None) -> object:
        del config
        return f"hello from {self.name}: {input}"


def get_tools(role: str | None = None, **_: object) -> list[ToolProtocol]:
    """Plugin factory called by the framework's tool loader."""
    del role
    return [HelloTool()]

__all__ = []

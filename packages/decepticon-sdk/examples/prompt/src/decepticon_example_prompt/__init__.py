"""Prompt fragments contributed to one or more roles."""

from __future__ import annotations

from decepticon_sdk import PromptContribution


def get_contribution() -> PromptContribution:
    """Plugin factory called by the framework's prompt loader."""
    return PromptContribution(
        fragments={"recon": "<decepticon_example_prompt>...</decepticon_example_prompt>"},
        mode="append",
        roles=("recon",),
    )

__all__ = []

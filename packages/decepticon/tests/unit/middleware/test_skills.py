"""Tests for SkillsMiddleware defensive paths (issue #157 regression).

The base ``SkillsMiddleware`` is exercised through deepagents' own tests,
but the decepticon subclass adds a custom prompt template with an
``except (KeyError, IndexError)`` shield around ``.format(...)`` that is
worth pinning so a future placeholder change cannot silently regress.

Workflow loading was removed from this middleware in Skillogy Amendment
v0.2.2 — ``workflow.md`` was renamed ``<role>.md`` and moved to
``decepticon/agents/prompts/workflows/`` so ``PromptBuilder`` can
concatenate it into the cacheable static prefix at agent factory time.
The MED #7 ``_read_workflow_for_source`` tests that lived here no
longer apply because the helper they pinned was deleted with the
middleware-side workflow loader.

Surviving finding:
  - MED #8: ``self.system_prompt_template.format(...)`` is wrapped in
    ``except (KeyError, IndexError)``. Pre-fix, a template edit that
    introduced a placeholder mismatch crashed every model step from
    that point on; the fix logs and falls through to the original
    system message instead.
"""

from __future__ import annotations

from typing import Any

from langchain_core.messages import SystemMessage

from decepticon.middleware.skills import SkillsMiddleware


class _Backend:
    """Minimal stand-in — the new middleware does not call any backend
    read paths from ``modify_request``, so this is a no-op shape."""


class _FakeRequest:
    """Minimal duck-typed request — same pattern as test_engagement.py."""

    def __init__(
        self,
        state: dict[str, Any] | None = None,
        system_message: SystemMessage | None = None,
    ) -> None:
        self.state = state or {}
        self.system_message = system_message

    def override(self, system_message: SystemMessage) -> "_FakeRequest":
        return _FakeRequest(state=self.state, system_message=system_message)


def _make_middleware() -> SkillsMiddleware:
    """Build a SkillsMiddleware against a stub backend with one source."""
    return SkillsMiddleware(backend=_Backend(), sources=["/skills/standard/recon/"])


# ── MED #8 — template format failures are swallowed ────────────────────


class TestModifyRequestTemplateFormatFailures:
    """``modify_request`` wraps ``self.system_prompt_template.format(...)``
    in ``except (KeyError, IndexError)``. A user/subclass that overrides
    the template with a bad placeholder must not crash every model step.
    """

    def test_keyerror_falls_through_to_original_request(self) -> None:
        """Template referencing an unknown placeholder must not raise.

        The contract: log a warning, return the original request
        untouched, so the agent step continues with the baked-in system
        message rather than failing the whole inference.
        """
        mw = _make_middleware()
        # Inject a bad template — references a placeholder we never pass.
        mw.system_prompt_template = "broken {nonexistent_placeholder}"

        original_msg = SystemMessage(content="original system msg")
        request = _FakeRequest(
            state={"skills_metadata": []},
            system_message=original_msg,
        )

        out = mw.modify_request(request)

        # On format failure, the contract is to return the request as-is.
        # ``out is request`` is the literal "untouched" guarantee.
        assert out is request, (
            "format failure must return request unchanged — see issue #157 MED #8"
        )

    def test_indexerror_also_caught(self) -> None:
        """Positional placeholder ``{0}`` is also a format-bomb path —
        Python raises IndexError here, not KeyError, so the except clause
        must cover both.
        """
        mw = _make_middleware()
        mw.system_prompt_template = "broken {0}"

        original_msg = SystemMessage(content="original")
        request = _FakeRequest(
            state={"skills_metadata": []},
            system_message=original_msg,
        )

        out = mw.modify_request(request)
        assert out is request

    def test_valid_template_still_overrides_system_message(self) -> None:
        """Positive control: a working template still does its job —
        otherwise the swallow-on-error contract would mask all failures.
        """
        mw = _make_middleware()
        # Minimal template that references only the surviving placeholders.
        # ``{workflow}`` is gone — workflow lives in PromptBuilder now.
        mw.system_prompt_template = (
            "skills_locations={skills_locations}|skills_list={skills_list}|MARKER"
        )

        request = _FakeRequest(
            state={"skills_metadata": []},
            system_message=SystemMessage(content="original"),
        )

        out = mw.modify_request(request)

        # The override path was taken: out is a *new* request with a
        # different system_message that includes our marker.
        assert out is not request
        # Narrow the type for the type checker.
        assert out.system_message is not None
        content = out.system_message.content
        flattened = (
            content
            if isinstance(content, str)
            else "".join(
                block.get("text", "") if isinstance(block, dict) else str(block)
                for block in content
            )
        )
        assert "MARKER" in flattened

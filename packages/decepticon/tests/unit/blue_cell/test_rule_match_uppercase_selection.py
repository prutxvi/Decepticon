from __future__ import annotations

from decepticon.blue_cell.rule_match import DetectionRule, RuleMatcher, _evaluate_condition


def _event(cmd: str, ts: float = 1000.0) -> dict:
    return {
        "ts": ts,
        "source": "sandbox.tmux.main",
        "actor": {"process": "", "command_line": cmd},
        "raw": cmd,
    }


class TestMixedCaseSelectionNames:
    def test_uppercase_single_selection_fires(self) -> None:
        rule = DetectionRule(
            id="uc-1",
            title="kerberoast uppercase",
            selections={"Kerberoast": {"actor.command_line": "GetUserSPNs"}},
            condition="Kerberoast",
        )
        matcher = RuleMatcher([rule])
        hits = matcher.match(_event("impacket-GetUserSPNs corp/user@dc"), now_ts=1001.0)
        assert len(hits) == 1
        assert hits[0].rule.id == "uc-1"

    def test_uppercase_selection_no_match_does_not_fire(self) -> None:
        rule = DetectionRule(
            id="uc-2",
            title="kerberoast uppercase miss",
            selections={"Kerberoast": {"actor.command_line": "GetUserSPNs"}},
            condition="Kerberoast",
        )
        matcher = RuleMatcher([rule])
        hits = matcher.match(_event("net user"), now_ts=1001.0)
        assert hits == []

    def test_mixed_case_and_condition_fires(self) -> None:
        rule = DetectionRule(
            id="uc-3",
            title="tool and flag uppercase",
            selections={
                "Tool": {"actor.command_line": "bloodhound"},
                "Flag": {"actor.command_line": "-c"},
            },
            condition="Tool and Flag",
        )
        matcher = RuleMatcher([rule])
        assert matcher.match(_event("bloodhound -c all"), now_ts=1.0)
        assert not matcher.match(_event("bloodhound --help"), now_ts=1.0)

    def test_mixed_case_or_condition(self) -> None:
        rule = DetectionRule(
            id="uc-4",
            title="impacket tools",
            selections={
                "SecretsDump": {"actor.command_line": "secretsdump"},
                "GetSPNs": {"actor.command_line": "GetUserSPNs"},
            },
            condition="SecretsDump or GetSPNs",
        )
        matcher = RuleMatcher([rule])
        assert matcher.match(_event("impacket-secretsdump corp/admin@dc"), now_ts=1.0)
        assert matcher.match(_event("impacket-GetUserSPNs corp/user@dc"), now_ts=1.0)
        assert not matcher.match(_event("ls"), now_ts=1.0)

    def test_mixed_case_not_condition(self) -> None:
        rule = DetectionRule(
            id="uc-5",
            title="curl not allowlisted uppercase",
            selections={
                "CurlTool": {"actor.command_line": "curl"},
                "AllowListed": {"actor.command_line": "internal.corp.local"},
            },
            condition="CurlTool and not AllowListed",
        )
        matcher = RuleMatcher([rule])
        assert matcher.match(_event("curl https://evil.example/"), now_ts=1.0)
        assert not matcher.match(_event("curl https://internal.corp.local/api"), now_ts=1.0)

    def test_evaluate_condition_case_insensitive_operators(self) -> None:
        results = {"MySelection": True}
        assert _evaluate_condition("MySelection", results) is True
        assert _evaluate_condition("NOT MySelection", {"MySelection": False}) is True
        assert _evaluate_condition("myselection", {"myselection": True}) is True

    def test_lowercase_names_still_work(self) -> None:
        rule = DetectionRule(
            id="uc-6",
            title="all lowercase unchanged",
            selections={"tool": {"actor.command_line": "nmap"}},
            condition="tool",
        )
        matcher = RuleMatcher([rule])
        assert matcher.match(_event("nmap 10.0.0.1"), now_ts=1.0)

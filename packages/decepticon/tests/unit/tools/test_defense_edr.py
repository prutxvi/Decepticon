from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from decepticon.tools.defense.edr import (
    _CROWDSTRIKE_TYPE_MAP,
    push_crowdstrike_ioa,
    push_defender_xdr_detection,
)

_SHA256 = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899"

_YARA_RULE_WITH_META = (
    "\nrule test_rule {\n"
    "  meta:\n"
    '    author = "decepticon"\n'
    f'    sha256 = "{_SHA256}"\n'
    '    indicator_type = "sha256"\n'
    '    indicator_value = "deadbeef1234"\n'
    '    tags = "a,b"\n'
    "  strings:\n"
    '    $a = "malware"\n'
    "  condition:\n"
    "    $a\n"
    "}\n"
)

# sha256 meta satisfies #417's Defender KQL indicator gate (else the push
# short-circuits before POST); no ``tags`` meta so tags stay engagement-only.
_YARA_RULE_INDICATOR_NO_TAGS = (
    "\nrule indicator_only {\n"
    "  meta:\n"
    f'    sha256 = "{_SHA256}"\n'
    "  strings:\n"
    '    $a = "malware"\n'
    "  condition:\n"
    "    $a\n"
    "}\n"
)

_YARA_RULE_NO_META = 'rule bare { strings: $a = "x" condition: $a }'


def _write_defender_conops(tmp_path: Path, defender_cfg: dict) -> None:
    conops = {"blue_team": {"defender": defender_cfg}}
    (tmp_path / "conops.json").write_text(json.dumps(conops))


def _write_crowdstrike_conops(tmp_path: Path, crowdstrike_cfg: dict) -> None:
    conops = {"blue_team": {"crowdstrike": crowdstrike_cfg}}
    (tmp_path / "conops.json").write_text(json.dumps(conops))


class TestPushDefenderXdrDetectionSuccess:
    def test_success_path_returns_pushed_status_with_correct_fields(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_defender_conops(tmp_path, {"auth": "oauth:DEF_TOKEN"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("DEF_TOKEN", "tok")
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_SLUG", "eng1")
        captured: dict = {}

        def fake_post(url, *, headers, data, timeout):  # type: ignore[no-untyped-def]
            captured["url"] = url
            captured["headers"] = headers
            captured["data"] = data
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            return mock_resp

        monkeypatch.setattr("requests.post", fake_post)
        result = push_defender_xdr_detection(
            "myrule", _YARA_RULE_WITH_META, technique_id="T1059", severity="high"
        )
        assert result == {
            "status": "pushed",
            "rule_id": "decepticon-eng-eng1-myrule",
            "engagement_slug": "eng1",
            "technique_id": "T1059",
            "severity": "high",
        }
        assert captured["url"] == "https://graph.microsoft.com/beta/security/rules/detectionRules"
        assert captured["headers"]["Authorization"] == "Bearer tok"
        body = json.loads(captured["data"])
        assert body["displayName"] == "[Decepticon] myrule"
        assert (
            body["queryCondition"]["queryText"] == f'DeviceFileEvents | where SHA256 == "{_SHA256}"'
        )

    def test_tags_include_yara_meta_tags_split_and_technique_id(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_defender_conops(tmp_path, {"auth": "oauth:DEF_TOKEN"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("DEF_TOKEN", "tok")
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_SLUG", "eng1")
        captured: dict = {}

        def fake_post(url, *, headers, data, timeout):  # type: ignore[no-untyped-def]
            captured["data"] = data
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            return mock_resp

        monkeypatch.setattr("requests.post", fake_post)
        push_defender_xdr_detection("myrule", _YARA_RULE_WITH_META, technique_id="T1")
        body = json.loads(captured["data"])
        assert body["tags"] == ["decepticon-eng-eng1", "a", "b", "T1"]

    def test_tags_with_no_meta_tags_and_no_technique_id(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_defender_conops(tmp_path, {"auth": "oauth:DEF_TOKEN"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("DEF_TOKEN", "tok")
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_SLUG", "eng1")
        captured: dict = {}

        def fake_post(url, *, headers, data, timeout):  # type: ignore[no-untyped-def]
            captured["data"] = data
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            return mock_resp

        monkeypatch.setattr("requests.post", fake_post)
        push_defender_xdr_detection("myrule", _YARA_RULE_INDICATOR_NO_TAGS)
        body = json.loads(captured["data"])
        assert body["tags"] == ["decepticon-eng-eng1"]
        assert "MITRE" not in body["description"]


class TestPushDefenderXdrDetectionErrorBranches:
    def test_missing_conops_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        result = push_defender_xdr_detection("myrule", _YARA_RULE_NO_META)
        assert "error" in result
        assert "conops" in result["error"].lower() or "conops.json" in result["error"].lower()

    def test_missing_auth_key_in_defender_config_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_defender_conops(tmp_path, {})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        result = push_defender_xdr_detection("myrule", _YARA_RULE_NO_META)
        assert result == {"error": "ConOps.blue_team.defender missing ``auth``"}

    def test_auth_env_var_unset_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_defender_conops(tmp_path, {"auth": "oauth:UNSET_VAR_XYZ"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.delenv("UNSET_VAR_XYZ", raising=False)
        result = push_defender_xdr_detection("myrule", _YARA_RULE_NO_META)
        assert "error" in result
        assert "UNSET_VAR_XYZ" in result["error"]

    def test_requests_not_installed_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_defender_conops(tmp_path, {"auth": "oauth:DEF_TOKEN"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("DEF_TOKEN", "tok")
        monkeypatch.setitem(sys.modules, "requests", None)  # type: ignore[call-overload]
        result = push_defender_xdr_detection("myrule", _YARA_RULE_INDICATOR_NO_TAGS)
        assert result == {"error": "``requests`` not installed in langgraph container"}

    def test_requests_post_raises_exception_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_defender_conops(tmp_path, {"auth": "oauth:DEF_TOKEN"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("DEF_TOKEN", "tok")

        def boom(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise RuntimeError("boom")

        monkeypatch.setattr("requests.post", boom)
        result = push_defender_xdr_detection("myrule", _YARA_RULE_INDICATOR_NO_TAGS)
        assert result["error"].startswith("Defender POST failed:")
        assert "boom" in result["error"]

    def test_http_400_or_above_returns_error_with_body_truncated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_defender_conops(tmp_path, {"auth": "oauth:DEF_TOKEN"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("DEF_TOKEN", "tok")

        def fake_post(url, *, headers, data, timeout):  # type: ignore[no-untyped-def]
            mock_resp = MagicMock()
            mock_resp.status_code = 403
            mock_resp.text = "denied" * 500
            return mock_resp

        monkeypatch.setattr("requests.post", fake_post)
        result = push_defender_xdr_detection("myrule", _YARA_RULE_INDICATOR_NO_TAGS)
        assert result["error"] == "Defender returned HTTP 403"
        assert "body" in result
        assert len(result["body"]) <= 1000


class TestPushCrowdstrikeIoaSuccess:
    def test_success_path_returns_pushed_status_with_correct_indicator_fields(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_crowdstrike_conops(
            tmp_path, {"url": "https://cs.example/", "auth": "oauth:CS_TOKEN"}
        )
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("CS_TOKEN", "cstok")
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_SLUG", "eng1")
        captured: dict = {}

        def fake_post(url, *, headers, data, timeout):  # type: ignore[no-untyped-def]
            captured["url"] = url
            captured["data"] = data
            mock_resp = MagicMock()
            mock_resp.status_code = 201
            return mock_resp

        monkeypatch.setattr("requests.post", fake_post)
        result = push_crowdstrike_ioa(_YARA_RULE_WITH_META)
        assert result == {
            "status": "pushed",
            "indicator_type": "sha256",
            "indicator_value": "deadbeef1234",
            "engagement_slug": "eng1",
            "technique_id": "",
            "severity": "medium",
        }
        assert captured["url"] == "https://cs.example/iocs/entities/indicators/v1"
        body = json.loads(captured["data"])
        assert body["indicators"][0]["type"] == "sha256"

    def test_indicator_value_falls_back_to_ioc_meta_key(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_crowdstrike_conops(tmp_path, {"url": "https://cs.example", "auth": "oauth:CS_TOKEN"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("CS_TOKEN", "cstok")
        yara = (
            "\nrule t {\n"
            "  meta:\n"
            '    indicator_type = "md5"\n'
            '    ioc = "abcd1234"\n'
            "  condition: true\n"
            "}\n"
        )
        captured: dict = {}

        def fake_post(url, *, headers, data, timeout):  # type: ignore[no-untyped-def]
            captured["data"] = data
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            return mock_resp

        monkeypatch.setattr("requests.post", fake_post)
        result = push_crowdstrike_ioa(yara)
        assert result["indicator_type"] == "md5"
        assert result["indicator_value"] == "abcd1234"

    @pytest.mark.parametrize(
        "indicator_type,expected_cs_type",
        [
            ("ip", "ipv4"),
            ("url", "domain"),
            ("domain", "domain"),
            ("ipv6", "ipv6"),
            ("filename", "filename"),
        ],
    )
    def test_type_mapping_for_ip_url_domain_aliases(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        indicator_type: str,
        expected_cs_type: str,
    ) -> None:
        _write_crowdstrike_conops(tmp_path, {"url": "https://cs.example", "auth": "oauth:CS_TOKEN"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("CS_TOKEN", "cstok")
        yara = (
            "\nrule t {\n"
            "  meta:\n"
            f'    indicator_type = "{indicator_type}"\n'
            '    indicator_value = "somevalue"\n'
            "  condition: true\n"
            "}\n"
        )

        def fake_post(url, *, headers, data, timeout):  # type: ignore[no-untyped-def]
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            return mock_resp

        monkeypatch.setattr("requests.post", fake_post)
        result = push_crowdstrike_ioa(yara)
        assert result.get("indicator_type") == expected_cs_type


class TestPushCrowdstrikeIoaErrorBranches:
    def test_missing_conops_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        result = push_crowdstrike_ioa(_YARA_RULE_WITH_META)
        assert "error" in result

    def test_missing_url_in_crowdstrike_config_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_crowdstrike_conops(tmp_path, {"auth": "oauth:CS_TOKEN"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        result = push_crowdstrike_ioa(_YARA_RULE_WITH_META)
        assert result == {"error": "ConOps.blue_team.crowdstrike missing ``url`` or ``auth``"}

    def test_missing_auth_in_crowdstrike_config_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_crowdstrike_conops(tmp_path, {"url": "https://cs.example"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        result = push_crowdstrike_ioa(_YARA_RULE_WITH_META)
        assert result == {"error": "ConOps.blue_team.crowdstrike missing ``url`` or ``auth``"}

    def test_auth_env_var_unset_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_crowdstrike_conops(
            tmp_path, {"url": "https://cs.example", "auth": "oauth:CS_UNSET_XYZ"}
        )
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.delenv("CS_UNSET_XYZ", raising=False)
        result = push_crowdstrike_ioa(_YARA_RULE_WITH_META)
        assert "error" in result
        assert "CS_UNSET_XYZ" in result["error"]

    def test_missing_indicator_meta_returns_structured_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_crowdstrike_conops(tmp_path, {"url": "https://cs.example", "auth": "oauth:CS_TOKEN"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("CS_TOKEN", "cstok")
        result = push_crowdstrike_ioa(_YARA_RULE_NO_META)
        assert "error" in result
        assert "Pure byte-pattern YARA rules" in result["error"]

    def test_missing_indicator_value_with_type_present_returns_structured_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_crowdstrike_conops(tmp_path, {"url": "https://cs.example", "auth": "oauth:CS_TOKEN"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("CS_TOKEN", "cstok")
        yara = '\nrule t {\n  meta:\n    indicator_type = "sha256"\n  condition: true\n}\n'
        result = push_crowdstrike_ioa(yara)
        assert "error" in result
        assert "Pure byte-pattern YARA rules" in result["error"]

    def test_unsupported_indicator_type_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_crowdstrike_conops(tmp_path, {"url": "https://cs.example", "auth": "oauth:CS_TOKEN"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("CS_TOKEN", "cstok")
        yara = (
            "\nrule t {\n"
            "  meta:\n"
            '    indicator_type = "registry"\n'
            '    indicator_value = "somekey"\n'
            "  condition: true\n"
            "}\n"
        )
        result = push_crowdstrike_ioa(yara)
        assert result == {
            "error": "indicator_type ``registry`` is not in CrowdStrike's supported set"
        }

    def test_requests_not_installed_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_crowdstrike_conops(tmp_path, {"url": "https://cs.example", "auth": "oauth:CS_TOKEN"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("CS_TOKEN", "cstok")
        monkeypatch.setitem(sys.modules, "requests", None)  # type: ignore[call-overload]
        result = push_crowdstrike_ioa(_YARA_RULE_WITH_META)
        assert result == {"error": "``requests`` not installed in langgraph container"}

    def test_requests_post_raises_exception_returns_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_crowdstrike_conops(tmp_path, {"url": "https://cs.example", "auth": "oauth:CS_TOKEN"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("CS_TOKEN", "cstok")

        def boom(*args, **kwargs):  # type: ignore[no-untyped-def]
            raise ConnectionError("conn refused")

        monkeypatch.setattr("requests.post", boom)
        result = push_crowdstrike_ioa(_YARA_RULE_WITH_META)
        assert result["error"].startswith("CrowdStrike POST failed:")

    def test_http_400_or_above_returns_error_with_body_truncated(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _write_crowdstrike_conops(tmp_path, {"url": "https://cs.example", "auth": "oauth:CS_TOKEN"})
        monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
        monkeypatch.setenv("CS_TOKEN", "cstok")

        def fake_post(url, *, headers, data, timeout):  # type: ignore[no-untyped-def]
            mock_resp = MagicMock()
            mock_resp.status_code = 400
            mock_resp.text = "x" * 2000
            return mock_resp

        monkeypatch.setattr("requests.post", fake_post)
        result = push_crowdstrike_ioa(_YARA_RULE_WITH_META)
        assert result["error"] == "CrowdStrike returned HTTP 400"
        assert "body" in result
        assert len(result["body"]) == 1000


class TestCrowdstrikeTypeMap:
    def test_type_map_contains_expected_keys_and_values(self) -> None:
        assert _CROWDSTRIKE_TYPE_MAP["ip"] == "ipv4"
        assert _CROWDSTRIKE_TYPE_MAP["url"] == "domain"
        assert _CROWDSTRIKE_TYPE_MAP["sha256"] == "sha256"
        assert _CROWDSTRIKE_TYPE_MAP["domain"] == "domain"

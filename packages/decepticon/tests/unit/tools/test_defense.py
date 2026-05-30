"""Tests for decepticon.tools.defense."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from decepticon.tools.defense import conops as conops_mod
from decepticon.tools.defense.edr import _extract_yara_metadata, push_defender_xdr_detection
from decepticon.tools.defense.elastic import (
    SigmaToElasticError,
    sigma_to_lucene,
)
from decepticon.tools.defense.sentinel import (
    SigmaToKqlError,
    sigma_to_kql,
)
from decepticon.tools.defense.splunk import (
    SigmaConversionError,
    sigma_to_spl,
)


def _basic_sigma() -> dict:
    return {
        "title": "test-rule",
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "selection": {
                "Image|endswith": "\\powershell.exe",
                "CommandLine|contains": "DownloadString",
            },
            "condition": "selection",
        },
    }


def test_sigma_to_spl_basic():
    spl = sigma_to_spl(_basic_sigma())
    assert 'Image="*\\\\powershell.exe"' in spl
    assert 'CommandLine="*DownloadString*"' in spl


def test_sigma_to_spl_with_or_condition():
    rule = {
        "detection": {
            "selA": {"a": "1"},
            "selB": {"b": "2"},
            "condition": "selA or selB",
        }
    }
    spl = sigma_to_spl(rule)
    assert "OR" in spl
    assert "a=" in spl and "b=" in spl


def test_sigma_to_spl_with_list_value():
    rule = {
        "detection": {
            "sel": {"Image|endswith": ["\\cmd.exe", "\\powershell.exe"]},
            "condition": "sel",
        }
    }
    spl = sigma_to_spl(rule)
    assert 'Image="*\\\\cmd.exe"' in spl
    assert 'Image="*\\\\powershell.exe"' in spl


def test_sigma_to_spl_unknown_modifier_raises():
    rule = {
        "detection": {
            "sel": {"field|exotic_modifier": "x"},
            "condition": "sel",
        }
    }
    with pytest.raises(SigmaConversionError):
        sigma_to_spl(rule)


def test_sigma_to_spl_unknown_selection_raises():
    rule = {
        "detection": {
            "selA": {"a": "1"},
            "condition": "missing_selection",
        }
    }
    with pytest.raises(SigmaConversionError):
        sigma_to_spl(rule)


def test_sigma_to_kql_picks_security_event_for_windows():
    kql = sigma_to_kql(_basic_sigma())
    assert kql.startswith("SecurityEvent")
    assert "where" in kql
    assert 'endswith "\\\\powershell.exe"' in kql or "endswith" in kql


def test_sigma_to_kql_unknown_modifier_raises():
    rule = {
        "logsource": {"product": "windows", "category": "process_creation"},
        "detection": {
            "sel": {"field|nope": "x"},
            "condition": "sel",
        },
    }
    with pytest.raises(SigmaToKqlError):
        sigma_to_kql(rule)


def test_sigma_to_lucene_basic():
    lucene = sigma_to_lucene(_basic_sigma())
    assert "Image: *\\powershell.exe" in lucene
    assert "CommandLine: *DownloadString*" in lucene


def test_sigma_to_lucene_unknown_token_raises():
    rule = {
        "detection": {
            "sel": {"a": "1"},
            "condition": "sel xor what",
        }
    }
    with pytest.raises(SigmaToElasticError):
        sigma_to_lucene(rule)


def test_extract_yara_metadata_pulls_meta_kvs():
    yara = """
    rule foo {
      meta:
        author = "decepticon"
        indicator_type = "sha256"
        indicator_value = "deadbeef"
      strings:
        $a = "x"
      condition:
        $a
    }
    """
    meta = _extract_yara_metadata(yara)
    assert meta["author"] == "decepticon"
    assert meta["indicator_type"] == "sha256"
    assert meta["indicator_value"] == "deadbeef"


def test_extract_yara_metadata_empty_when_no_meta_block():
    yara = 'rule bar { strings: $a = "x" condition: $a }'
    assert _extract_yara_metadata(yara) == {}


def test_resolve_siem_target_missing_conops_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
    with pytest.raises(conops_mod.ConOpsLookupError):
        conops_mod.resolve_siem_target("splunk")


def test_resolve_siem_target_missing_target_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / "conops.json").write_text(json.dumps({"blue_team": {}}))
    monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
    with pytest.raises(conops_mod.ConOpsLookupError):
        conops_mod.resolve_siem_target("splunk")


def test_resolve_siem_target_success(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    (tmp_path / "conops.json").write_text(
        json.dumps(
            {
                "blue_team": {
                    "splunk": {"url": "https://splunk.example", "auth": "hec_token:HEC_TOKEN"}
                }
            }
        )
    )
    monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
    target = conops_mod.resolve_siem_target("splunk")
    assert target["url"] == "https://splunk.example"


def test_resolve_auth_value_missing_env_raises(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("NOT_SET_AT_ALL", raising=False)
    with pytest.raises(conops_mod.ConOpsLookupError):
        conops_mod.resolve_auth_value("hec_token:NOT_SET_AT_ALL")


def test_resolve_auth_value_success(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SOME_TOKEN", "supersecret")
    assert conops_mod.resolve_auth_value("hec_token:SOME_TOKEN") == "supersecret"


def test_sigma_to_spl_contains_with_spaces_stays_quoted():
    rule = {
        "detection": {
            "sel": {"CommandLine|contains": "cmd.exe /c whoami"},
            "condition": "sel",
        }
    }
    spl = sigma_to_spl(rule)
    assert 'CommandLine="*cmd.exe /c whoami*"' in spl


def test_sigma_to_spl_contains_with_special_chars_escaped():
    rule = {
        "detection": {
            "sel": {"CommandLine|contains": 'say "hello" and\\or'},
            "condition": "sel",
        }
    }
    spl = sigma_to_spl(rule)
    assert 'CommandLine="*say \\"hello\\" and\\\\or*"' in spl


def _yara_with_sha256(sha256: str) -> str:
    return f"""
    rule test_rule {{
      meta:
        sha256 = "{sha256}"
      strings:
        $a = "malware"
      condition:
        $a
    }}
    """


def _yara_no_indicator() -> str:
    return """
    rule test_rule {
      meta:
        author = "tester"
      strings:
        $a = "malware"
      condition:
        $a
    }
    """


def test_push_defender_xdr_kql_built_from_sha256(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    sha = "abc123def456" * 4 + "abcd"
    yara = _yara_with_sha256(sha)

    (tmp_path / "conops.json").write_text(
        json.dumps(
            {
                "blue_team": {"defender": {"auth": "bearer_token:DEFENDER_TOKEN"}},
                "engagement": {"slug": "test-eng"},
            }
        )
    )
    monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("DEFENDER_TOKEN", "fake-token")

    mock_resp = MagicMock()
    mock_resp.status_code = 201
    mock_resp.text = "{}"

    with patch("requests.post", return_value=mock_resp) as mock_post:
        result = push_defender_xdr_detection("test-rule", yara)

    assert result.get("status") == "pushed"
    posted_body = json.loads(mock_post.call_args.kwargs.get("data", "{}"))
    query_text = posted_body["queryCondition"]["queryText"]
    assert "DeviceFileEvents" in query_text
    assert "where SHA256 ==" in query_text
    assert sha in query_text
    assert "rule test_rule" not in query_text


def test_push_defender_xdr_no_indicator_returns_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    yara = _yara_no_indicator()

    (tmp_path / "conops.json").write_text(
        json.dumps(
            {
                "blue_team": {"defender": {"auth": "bearer_token:DEFENDER_TOKEN"}},
                "engagement": {"slug": "test-eng"},
            }
        )
    )
    monkeypatch.setenv("DECEPTICON_ENGAGEMENT_WORKSPACE", str(tmp_path))
    monkeypatch.setenv("DEFENDER_TOKEN", "fake-token")

    with patch("requests.post") as mock_post:
        result = push_defender_xdr_detection("test-rule", yara)

    mock_post.assert_not_called()
    assert "error" in result
    assert "no extractable indicator" in result["error"]

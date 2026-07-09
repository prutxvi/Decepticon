"""test_k8s_branches module."""

from __future__ import annotations

import json

import pytest

from decepticon.tools.cloud.k8s import K8sFinding, analyze_k8s_manifest


class TestK8sFindingToDict:
    def test_to_dict_returns_all_seven_keys_with_correct_values(self) -> None:
        f = K8sFinding(
            id="x",
            severity="high",
            kind="Pod",
            name="n",
            title="t",
            detail="d",
            namespace="ns",
        )
        result = f.to_dict()
        assert result["id"] == "x"
        assert result["severity"] == "high"
        assert result["kind"] == "Pod"
        assert result["name"] == "n"
        assert result["namespace"] == "ns"
        assert result["title"] == "t"
        assert result["detail"] == "d"

    def test_to_dict_namespace_none_when_not_set(self) -> None:
        f = K8sFinding(id="y", severity="info", kind="?", name="?", title="t", detail="d")
        result = f.to_dict()
        assert result["namespace"] is None
        assert set(result.keys()) == {
            "id",
            "severity",
            "kind",
            "name",
            "namespace",
            "title",
            "detail",
        }


class TestAnalyzeK8sManifestStrInput:
    def test_valid_json_string_input_finds_privileged(self) -> None:
        manifest_str = json.dumps(
            {
                "kind": "Pod",
                "metadata": {"name": "p"},
                "spec": {"containers": [{"name": "c", "securityContext": {"privileged": True}}]},
            }
        )
        findings = analyze_k8s_manifest(manifest_str)
        assert any("privileged" in f.title for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_malformed_json_string_returns_parse_error_finding(self) -> None:
        findings = analyze_k8s_manifest("{not json")
        assert len(findings) == 1
        assert findings[0].id == "k8s.parse-error"
        assert findings[0].severity == "info"
        assert findings[0].kind == "?"
        assert findings[0].name == "?"


class TestIterDocumentsListInput:
    def test_list_input_filters_non_dict_entries(self) -> None:
        pod = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {"containers": [{"name": "c", "securityContext": {"privileged": True}}]},
        }
        findings = analyze_k8s_manifest([pod, "garbage", 42, None])
        assert any("privileged" in f.title for f in findings)

    def test_list_input_multiple_dicts_all_analyzed(self) -> None:
        pod1 = {
            "kind": "Pod",
            "metadata": {"name": "p1"},
            "spec": {"containers": [{"name": "c1", "securityContext": {"privileged": True}}]},
        }
        pod2 = {
            "kind": "Pod",
            "metadata": {"name": "p2"},
            "spec": {
                "containers": [
                    {"name": "c2", "securityContext": {"allowPrivilegeEscalation": True}}
                ]
            },
        }
        findings = analyze_k8s_manifest([pod1, pod2])
        titles = [f.title for f in findings]
        assert any("privileged" in t for t in titles)
        assert any("allowPrivilegeEscalation" in t for t in titles)


class TestIterDocumentsKindList:
    def test_kind_list_wrapper_items_analyzed(self) -> None:
        pod = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {"containers": [{"name": "c", "securityContext": {"privileged": True}}]},
        }
        wrapper = {"kind": "List", "items": [pod]}
        findings = analyze_k8s_manifest(wrapper)
        assert any("privileged" in f.title for f in findings)

    def test_kind_list_items_none_returns_empty(self) -> None:
        wrapper = {"kind": "List", "items": None}
        findings = analyze_k8s_manifest(wrapper)
        assert findings == []

    def test_kind_list_items_empty_returns_empty(self) -> None:
        wrapper = {"kind": "List", "items": []}
        findings = analyze_k8s_manifest(wrapper)
        assert findings == []


class TestIterDocumentsFallthrough:
    def test_non_str_non_dict_non_list_returns_empty(self) -> None:
        findings = analyze_k8s_manifest(123)  # type: ignore[arg-type]
        assert findings == []

    def test_none_input_returns_empty(self) -> None:
        findings = analyze_k8s_manifest(None)  # type: ignore[arg-type]
        assert findings == []


class TestPodSpecWorkloadKinds:
    @pytest.mark.parametrize("kind", ["StatefulSet", "DaemonSet", "Job", "ReplicaSet"])
    def test_workload_kind_template_spec_finds_privileged(self, kind: str) -> None:
        m = {
            "kind": kind,
            "metadata": {"name": "w"},
            "spec": {
                "template": {
                    "spec": {"containers": [{"name": "c", "securityContext": {"privileged": True}}]}
                }
            },
        }
        findings = analyze_k8s_manifest(m)
        assert any("privileged" in f.title for f in findings)
        assert any(f.severity == "critical" for f in findings)

    def test_cronjob_job_template_path_finds_privileged(self) -> None:
        m = {
            "kind": "CronJob",
            "metadata": {"name": "cj"},
            "spec": {
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": {
                                "containers": [
                                    {"name": "c", "securityContext": {"privileged": True}}
                                ]
                            }
                        }
                    }
                }
            },
        }
        findings = analyze_k8s_manifest(m)
        assert any("privileged" in f.title for f in findings)

    def test_unknown_kind_returns_no_findings(self) -> None:
        m = {"kind": "Service", "metadata": {"name": "svc"}, "spec": {}}
        findings = analyze_k8s_manifest(m)
        assert findings == []


class TestContainersInitContainers:
    def test_init_container_privileged_is_detected(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {
                "containers": [],
                "initContainers": [{"name": "init-c", "securityContext": {"privileged": True}}],
            },
        }
        findings = analyze_k8s_manifest(m)
        assert any("privileged" in f.title for f in findings)
        assert any(f.severity == "critical" for f in findings)


class TestRBACWildcardVerbs:
    def test_wildcard_verbs_on_secrets_returns_high_severity(self) -> None:
        m = {
            "kind": "Role",
            "metadata": {"name": "r", "namespace": "ns"},
            "rules": [{"verbs": ["*"], "resources": ["secrets"]}],
        }
        findings = analyze_k8s_manifest(m)
        assert any(f.title == "Wildcard verbs on secrets" for f in findings)
        assert any(f.severity == "high" for f in findings)
        assert any(f.namespace == "ns" for f in findings)

    def test_wildcard_verbs_on_secrets_kind_role_preserved(self) -> None:
        m = {
            "kind": "Role",
            "metadata": {"name": "r"},
            "rules": [{"verbs": ["*"], "resources": ["secrets"]}],
        }
        findings = analyze_k8s_manifest(m)
        matching = [f for f in findings if f.title == "Wildcard verbs on secrets"]
        assert len(matching) == 1
        assert matching[0].kind == "Role"

    def test_impersonate_verb_returns_high_severity(self) -> None:
        m = {
            "kind": "ClusterRole",
            "metadata": {"name": "r"},
            "rules": [{"verbs": ["impersonate"], "resources": ["users"]}],
        }
        findings = analyze_k8s_manifest(m)
        assert any(f.title == "Impersonation allowed" for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_impersonate_verb_kind_clusterrole_preserved(self) -> None:
        m = {
            "kind": "ClusterRole",
            "metadata": {"name": "r"},
            "rules": [{"verbs": ["impersonate"], "resources": ["users"]}],
        }
        findings = analyze_k8s_manifest(m)
        matching = [f for f in findings if f.title == "Impersonation allowed"]
        assert len(matching) == 1
        assert matching[0].kind == "ClusterRole"


class TestHostNamespaceFlags:
    @pytest.mark.parametrize("flag", ["hostNetwork", "hostPID", "hostIPC"])
    def test_host_namespace_flag_true_returns_high_finding(self, flag: str) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {flag: True, "containers": [{"name": "c"}]},
        }
        findings = analyze_k8s_manifest(m)
        assert any(f.title == f"{flag} enabled" for f in findings)
        assert any(f.severity == "high" for f in findings)

    @pytest.mark.parametrize("flag", ["hostNetwork", "hostPID", "hostIPC"])
    def test_host_namespace_flag_truthy_non_true_does_not_trigger(self, flag: str) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {flag: "true", "containers": [{"name": "c"}]},
        }
        findings = analyze_k8s_manifest(m)
        assert not any(f.title == f"{flag} enabled" for f in findings)

    @pytest.mark.parametrize("flag", ["hostNetwork", "hostPID", "hostIPC"])
    def test_host_namespace_flag_integer_one_does_not_trigger(self, flag: str) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {flag: 1, "containers": [{"name": "c"}]},
        }
        findings = analyze_k8s_manifest(m)
        assert not any(f.title == f"{flag} enabled" for f in findings)


class TestHostPathVolumes:
    def test_hostpath_root_slash_returns_high_not_critical(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {
                "volumes": [{"hostPath": {"path": "/"}}],
                "containers": [{"name": "c"}],
            },
        }
        findings = analyze_k8s_manifest(m)
        matching = [f for f in findings if "hostPath" in f.title]
        assert len(matching) == 1
        assert matching[0].severity == "high"

    @pytest.mark.parametrize("path", ["/var/run/foo", "/proc/1", "/dev/sda"])
    def test_hostpath_dangerous_prefix_returns_high_severity(self, path: str) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {
                "volumes": [{"hostPath": {"path": path}}],
                "containers": [{"name": "c"}],
            },
        }
        findings = analyze_k8s_manifest(m)
        assert any("hostPath" in f.title for f in findings)
        assert any(f.severity == "high" for f in findings)

    def test_hostpath_safe_path_no_finding(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {
                "volumes": [{"hostPath": {"path": "/home/app"}}],
                "containers": [{"name": "c"}],
            },
        }
        findings = analyze_k8s_manifest(m)
        assert not any("hostPath" in f.title for f in findings)

    def test_hostpath_malformed_volume_entries_no_crash(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {
                "volumes": [None, "str", {"hostPath": None}, {"noHostPath": 1}],
                "containers": [{"name": "c"}],
            },
        }
        findings = analyze_k8s_manifest(m)
        assert not any("hostPath" in f.title for f in findings)


class TestAllowPrivilegeEscalation:
    def test_allow_privilege_escalation_true_returns_medium(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {
                "containers": [{"name": "c", "securityContext": {"allowPrivilegeEscalation": True}}]
            },
        }
        findings = analyze_k8s_manifest(m)
        assert any("allowPrivilegeEscalation" in f.title for f in findings)
        assert any(f.severity == "medium" for f in findings)

    def test_allow_privilege_escalation_false_no_finding(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {
                "containers": [
                    {"name": "c", "securityContext": {"allowPrivilegeEscalation": False}}
                ]
            },
        }
        findings = analyze_k8s_manifest(m)
        assert not any("allowPrivilegeEscalation" in f.title for f in findings)


class TestRunAsRootChecks:
    def test_run_as_user_zero_returns_medium_root_finding(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {"containers": [{"name": "c", "securityContext": {"runAsUser": 0}}]},
        }
        findings = analyze_k8s_manifest(m)
        assert any("runs as root" in f.title for f in findings)
        assert any(f.severity == "medium" for f in findings)

    def test_run_as_non_root_false_without_run_as_user_returns_medium(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {"containers": [{"name": "c", "securityContext": {"runAsNonRoot": False}}]},
        }
        findings = analyze_k8s_manifest(m)
        assert any("runs as root" in f.title for f in findings)
        assert any(f.severity == "medium" for f in findings)

    def test_run_as_non_root_false_with_nonzero_run_as_user_no_root_finding(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {
                "containers": [
                    {"name": "c", "securityContext": {"runAsNonRoot": False, "runAsUser": 1000}}
                ]
            },
        }
        findings = analyze_k8s_manifest(m)
        assert not any("runs as root" in f.title for f in findings)

    def test_run_as_user_nonzero_no_root_finding(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {"containers": [{"name": "c", "securityContext": {"runAsUser": 1000}}]},
        }
        findings = analyze_k8s_manifest(m)
        assert not any("runs as root" in f.title for f in findings)


class TestDangerousCapsCaseNormalization:
    def test_lowercase_sys_ptrace_is_detected(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {
                "containers": [
                    {
                        "name": "c",
                        "securityContext": {"capabilities": {"add": ["sys_ptrace"]}},
                    }
                ]
            },
        }
        findings = analyze_k8s_manifest(m)
        assert any("Dangerous capabilities" in f.title for f in findings)

    def test_non_dangerous_cap_net_bind_service_no_finding(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {
                "containers": [
                    {
                        "name": "c",
                        "securityContext": {"capabilities": {"add": ["NET_BIND_SERVICE"]}},
                    }
                ]
            },
        }
        findings = analyze_k8s_manifest(m)
        assert not any("Dangerous capabilities" in f.title for f in findings)


class TestPlainEnvSecretNegatives:
    def test_non_secret_env_name_no_finding(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {"containers": [{"name": "c", "env": [{"name": "PLAIN_VAR", "value": "x"}]}]},
        }
        findings = analyze_k8s_manifest(m)
        assert not any("PLAIN_VAR" in f.title for f in findings)

    def test_secret_name_without_value_no_finding(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {"containers": [{"name": "c", "env": [{"name": "API_KEY"}]}]},
        }
        findings = analyze_k8s_manifest(m)
        assert not any("API_KEY" in f.title for f in findings)

    def test_malformed_env_entries_no_crash(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {"containers": [{"name": "c", "env": [None, "str"]}]},
        }
        findings = analyze_k8s_manifest(m)
        assert isinstance(findings, list)

    def test_env_value_from_secret_key_ref_no_literal_value_no_finding(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {
                "containers": [
                    {
                        "name": "c",
                        "env": [
                            {
                                "name": "API_KEY",
                                "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}},
                            }
                        ],
                    }
                ]
            },
        }
        findings = analyze_k8s_manifest(m)
        assert not any("API_KEY" in f.title for f in findings)


class TestIdxSequencingAndIdFormat:
    def test_multiple_findings_have_sequential_zero_padded_ids(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {
                "hostNetwork": True,
                "hostPID": True,
                "containers": [{"name": "c", "securityContext": {"privileged": True}}],
            },
        }
        findings = analyze_k8s_manifest(m)
        ids = [f.id for f in findings]
        assert "k8s-0001" in ids
        assert "k8s-0002" in ids
        assert "k8s-0003" in ids

    def test_id_format_uses_four_digit_padding(self) -> None:
        m = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {"containers": [{"name": "c", "securityContext": {"privileged": True}}]},
        }
        findings = analyze_k8s_manifest(m)
        assert len(findings) >= 1
        assert findings[0].id == "k8s-0001"

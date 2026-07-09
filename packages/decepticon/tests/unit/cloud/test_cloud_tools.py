"""test_cloud_tools module."""

from __future__ import annotations

import json

from decepticon.tools.cloud import tools as T
from decepticon.tools.cloud.metadata import METADATA_ENDPOINTS


class TestIamPolicyAuditWrapper:
    def test_wildcard_action_resource_returns_critical_finding_with_expected_title(self) -> None:
        result = T.iam_policy_audit.invoke(
            {"policy_json": '{"Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'}
        )
        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) >= 1
        assert any("Wildcard Action" in f["title"] for f in data)
        assert any(f["severity"] == "critical" for f in data)

    def test_parse_error_json_returns_info_finding_with_parse_error_id(self) -> None:
        result = T.iam_policy_audit.invoke({"policy_json": "{not json"})
        data = json.loads(result)
        assert isinstance(data, list)
        assert len(data) == 1
        assert data[0]["id"] == "iam.parse-error"
        assert data[0]["severity"] == "info"


class TestS3BucketsFromTextWrapper:
    def test_multiple_bucket_styles_returns_correct_count_and_bucket_names(self) -> None:
        result = T.s3_buckets_from_text.invoke(
            {"text": "see s3://my-bucket/key and prod-data.s3.amazonaws.com/x"}
        )
        data = json.loads(result)
        assert "count" in data
        assert "buckets" in data
        assert data["count"] == len(data["buckets"])
        assert "my-bucket" in data["buckets"]
        assert "prod-data" in data["buckets"]

    def test_empty_text_returns_zero_count_and_empty_buckets_list(self) -> None:
        result = T.s3_buckets_from_text.invoke({"text": ""})
        data = json.loads(result)
        assert data["count"] == 0
        assert data["buckets"] == []


class TestUserDataSecretsWrapper:
    def test_aws_key_and_password_in_text_returns_hits_with_kind_and_snippet_keys(self) -> None:
        result = T.user_data_secrets.invoke(
            {"text": "AWS_KEY=AKIAIOSFODNN7EXAMPLE\nPASSWORD=supersecret123"}
        )
        data = json.loads(result)
        assert "count" in data
        assert "hits" in data
        assert data["count"] == len(data["hits"])
        for hit in data["hits"]:
            assert set(hit.keys()) == {"kind", "snippet"}
        assert any(h["kind"] == "aws_access_key" for h in data["hits"])

    def test_no_secrets_in_text_returns_zero_count_and_empty_hits(self) -> None:
        result = T.user_data_secrets.invoke({"text": "nothing secret here"})
        data = json.loads(result)
        assert data["count"] == 0
        assert data["hits"] == []


class TestK8sAuditWrapper:
    def test_privileged_pod_manifest_returns_critical_privileged_finding(self) -> None:
        manifest = {
            "kind": "Pod",
            "metadata": {"name": "p"},
            "spec": {"containers": [{"name": "c", "securityContext": {"privileged": True}}]},
        }
        result = T.k8s_audit.invoke({"manifest_json": json.dumps(manifest)})
        data = json.loads(result)
        assert isinstance(data, list)
        assert any("privileged" in f["title"] for f in data)
        assert any(f["severity"] == "critical" for f in data)


class TestTfstateAuditWrapper:
    def test_sensitive_output_and_plaintext_secret_resource_returns_expected_report_shape(
        self,
    ) -> None:
        tfstate = {
            "version": 4,
            "outputs": {"db_pw": {"value": "x", "sensitive": True}},
            "resources": [
                {
                    "mode": "managed",
                    "type": "aws_instance",
                    "name": "web",
                    "provider": "aws",
                    "instances": [{"attributes": {"password": "plain123"}}],
                }
            ],
        }
        result = T.tfstate_audit.invoke({"tfstate_json": json.dumps(tfstate)})
        data = json.loads(result)
        assert data["version"] == 4
        assert "db_pw" in data["sensitive_outputs"]
        assert data["secrets_found"] >= 1
        assert "aws" in data["providers"]
        assert any(f["kind"] in ("sensitive_output", "plaintext_secret") for f in data["findings"])


class TestMetadataEndpointsWrapper:
    def test_no_provider_filter_returns_all_metadata_endpoints(self) -> None:
        result = T.metadata_endpoints.invoke({})
        data = json.loads(result)
        assert data["count"] == len(METADATA_ENDPOINTS)
        assert data["count"] == len(data["endpoints"])
        for endpoint in data["endpoints"]:
            assert "provider" in endpoint
            assert "url" in endpoint
            assert "method" in endpoint
            assert "headers" in endpoint
            assert "yields" in endpoint
            assert "notes" in endpoint

    def test_empty_string_provider_returns_all_endpoints_same_as_no_filter(self) -> None:
        result = T.metadata_endpoints.invoke({"provider": ""})
        data = json.loads(result)
        assert data["count"] == len(METADATA_ENDPOINTS)

    def test_aws_provider_filter_returns_only_aws_endpoints(self) -> None:
        result = T.metadata_endpoints.invoke({"provider": "aws"})
        data = json.loads(result)
        assert data["count"] > 0
        assert all(e["provider"] == "aws" for e in data["endpoints"])
        expected_aws_count = sum(1 for e in METADATA_ENDPOINTS if e.provider == "aws")
        assert data["count"] == expected_aws_count

    def test_unknown_provider_returns_zero_count_and_empty_endpoints(self) -> None:
        result = T.metadata_endpoints.invoke({"provider": "nonexistent"})
        data = json.loads(result)
        assert data["count"] == 0
        assert data["endpoints"] == []

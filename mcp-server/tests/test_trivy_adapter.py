"""Fixture-backed tests for the Trivy Operator evidence adapter."""

import json
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from k8s_sec_mcp.adapters.trivy import parse_vulnerability_report
from k8s_sec_mcp.contract import InvalidSourceDataError
from k8s_sec_mcp.tools.vulns import list_vuln_reports, list_vuln_summary

FIXTURE = Path(__file__).parent / "fixtures" / "trivy-vulnerabilityreport-v1alpha1.json"


def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text())


class TrivyAdapterTests(unittest.TestCase):
    def test_preserves_source_identity_image_digest_and_freshness_inputs(self):
        evidence = parse_vulnerability_report(load_fixture())

        self.assertEqual("replicaset-api-7d9f6c-api", evidence.provenance.report_name)
        self.assertEqual("demo", evidence.provenance.report_namespace)
        self.assertEqual(
            "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            evidence.provenance.report_uid,
        )
        self.assertEqual("4815", evidence.provenance.resource_version)
        self.assertEqual(2, evidence.provenance.observed_generation)
        self.assertEqual("2026-09-03T08:04:00Z", evidence.provenance.observed_at)
        self.assertEqual("0.69.3", evidence.provenance.scanner_version)
        self.assertEqual("sha256:0123456789abcdef", evidence.image.digest)
        self.assertEqual("ReplicaSet", evidence.workload.kind)
        self.assertEqual("api-7d9f6c", evidence.workload.name)
        self.assertEqual("11111111-2222-3333-4444-555555555555", evidence.workload.uid)
        self.assertEqual("api", evidence.workload.container_name)
        self.assertEqual(1, len(evidence.workload.owner_references))

    def test_rejects_an_unadvertised_crd_version(self):
        report = load_fixture()
        report["apiVersion"] = "aquasecurity.github.io/v2"
        with self.assertRaises(InvalidSourceDataError):
            parse_vulnerability_report(report)

    def test_unknown_upstream_severity_is_normalized_without_guessing(self):
        report = load_fixture()
        report["report"]["vulnerabilities"][0]["severity"] = "future-severity"
        evidence = parse_vulnerability_report(report)
        self.assertEqual("UNKNOWN", evidence.findings[0].severity)


class VulnerabilityToolCompatibilityTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.api = Mock()
        self.api.list_cluster_custom_object.return_value = {"items": [load_fixture()]}

    async def test_detail_output_keeps_the_phase2a_shape(self):
        with patch("k8s_sec_mcp.tools.vulns._k8s_client", return_value=self.api):
            result = json.loads(await list_vuln_reports(severity="HIGH"))

        self.assertEqual(
            {
                "namespace": "demo",
                "name": "replicaset-api-7d9f6c-api",
                "image": "registry.example.test/team/api:1.4.2",
                "vulnerabilities": [
                    {
                        "id": "CVE-2026-10001",
                        "severity": "CRITICAL",
                        "resource": "libexample",
                        "installed": "3.2.1-r0",
                        "fixed": "3.2.1-r1",
                        "title": "Example memory safety issue",
                    },
                    {
                        "id": "CVE-2026-10002",
                        "severity": "HIGH",
                        "resource": "example-runtime",
                        "installed": "1.0.0",
                        "fixed": "",
                        "title": "Example unpatched issue",
                    },
                ],
            },
            result[0],
        )

    async def test_summary_uses_the_same_normalized_adapter(self):
        with patch("k8s_sec_mcp.tools.vulns._k8s_client", return_value=self.api):
            result = json.loads(await list_vuln_summary(severity="HIGH"))

        self.assertEqual("registry.example.test/team/api:1.4.2", result[0]["image"])
        self.assertEqual(1, result[0]["fixable_count"])
        self.assertEqual("CVE-2026-10002", result[0]["unfixable"][0]["id"])

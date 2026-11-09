"""Kubescape posture adapter tests."""

import json
import unittest
from unittest.mock import MagicMock, patch

from k8s_sec_mcp.tools.posture import list_compliance_reports


class KubescapePostureAdapterTests(unittest.IsolatedAsyncioTestCase):
    async def test_uses_kubescape_summary_api_and_preserves_workload_identity(self):
        api = MagicMock()
        detailed_item = {
            "metadata": {
                "name": "deployment-vulnerable-app",
                "namespace": "demo",
                "annotations": {
                    "kubescape.io/wlid": (
                        "wlid://cluster-local/namespace-demo/deployment-vulnerable-app"
                    )
                },
                "labels": {
                    "kubescape.io/workload-kind": "Deployment",
                    "kubescape.io/workload-name": "vulnerable-app",
                },
            },
            "spec": {
                "controls": {
                    "C-0012": {
                        "severity": {"severity": "High"},
                        "status": {"status": "passed"},
                    },
                    "C-0057": {
                        "severity": {"severity": "High"},
                        "status": {"status": "failed"},
                    },
                },
                "severities": {"critical": 0, "high": 1},
            },
        }
        api.list_cluster_custom_object.return_value = {
            "items": [
                {
                    "metadata": {
                        "name": "deployment-vulnerable-app",
                        "namespace": "demo",
                    },
                    "spec": {"controls": None},
                },
                {
                    "metadata": {"name": "deployment-other", "namespace": "other"},
                    "spec": {"controls": None, "severities": None},
                },
            ]
        }
        api.get_namespaced_custom_object.return_value = detailed_item

        with patch("k8s_sec_mcp.tools.posture._k8s_client", return_value=api):
            result = json.loads(await list_compliance_reports(namespace="demo"))

        api.list_cluster_custom_object.assert_called_once_with(
            group="spdx.softwarecomposition.kubescape.io",
            version="v1beta1",
            plural="workloadconfigurationscansummaries",
        )
        api.get_namespaced_custom_object.assert_called_once_with(
            group="spdx.softwarecomposition.kubescape.io",
            version="v1beta1",
            namespace="demo",
            plural="workloadconfigurationscansummaries",
            name="deployment-vulnerable-app",
        )
        self.assertEqual(1, len(result))
        self.assertEqual("demo", result[0]["namespace"])
        self.assertEqual("Deployment", result[0]["kind"])
        self.assertEqual("vulnerable-app", result[0]["workload"])
        self.assertEqual((1, 1), (result[0]["pass"], result[0]["fail"]))
        self.assertEqual(
            [{"id": "C-0057", "severity": "High"}],
            result[0]["failing_controls"],
        )


if __name__ == "__main__":
    unittest.main()

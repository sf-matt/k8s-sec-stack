from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO = Path(__file__).parents[2]
CHART = REPO / "charts" / "k8s-sec-stack"


class PhaseOneHelmTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("helm"):
            raise unittest.SkipTest("helm is not installed")
        cls.temp_dir = tempfile.TemporaryDirectory()
        cls.isolated_chart = Path(cls.temp_dir.name) / "chart"
        shutil.copytree(CHART, cls.isolated_chart)
        (cls.isolated_chart / "Chart.yaml").write_text(
            "apiVersion: v2\nname: k8s-sec-stack\ntype: application\nversion: 0.1.0\n"
        )

    @classmethod
    def tearDownClass(cls):
        cls.temp_dir.cleanup()

    def render(self, namespace="security", extra_args=()):
        command = ["helm", "template", "test-stack", str(self.isolated_chart), "--namespace", namespace]
        command.extend(extra_args)
        return subprocess.run(command, check=True, capture_output=True, text=True).stdout

    def test_default_render_is_internal_namespace_neutral_and_authenticated(self):
        rendered = self.render(namespace="alternate-security")
        self.assertNotIn("type: NodePort", rendered)
        self.assertNotIn(".security.svc", rendered)
        self.assertIn("type: ClusterIP", rendered)
        self.assertIn("EVENT_SINK_INGEST_TOKEN", rendered)
        self.assertIn("WEBHOOK_CUSTOMHEADERS", rendered)

    def test_event_sink_meets_restricted_pod_controls(self):
        rendered = self.render()
        for expected in (
            "automountServiceAccountToken: false",
            "runAsNonRoot: true",
            "allowPrivilegeEscalation: false",
            "readOnlyRootFilesystem: true",
            "type: RuntimeDefault",
            "drop: [\"ALL\"]",
        ):
            self.assertIn(expected, rendered)

        dockerfile = (REPO / "event-sink" / "Dockerfile").read_text()
        self.assertRegex(dockerfile, r"FROM python:[^@\n]+@sha256:[0-9a-f]{64}", "Docker base must be digest pinned")
        self.assertIn("USER 65532:65532", dockerfile)

    def test_event_sink_integer_limits_render_without_scientific_notation(self):
        rendered = self.render()
        self.assertIn('value: "1048576"', rendered)
        self.assertNotIn('value: "1.048576e+06"', rendered)

    def test_published_image_digest_overrides_mutable_tag(self):
        published_digest = "sha256:22c30e95071ea4f14b93e93d61a238b19f6cdef0b3b7c94e5aa46bf3aa523d32"
        default_render = self.render()
        self.assertIn(
            f'image: "ghcr.io/sf-matt/k8s-sec-event-sink@{published_digest}"',
            default_render,
        )

        digest = "sha256:" + "a" * 64
        rendered = self.render(extra_args=("--set", f"eventSink.image.digest={digest}"))
        self.assertIn(f'image: "ghcr.io/sf-matt/k8s-sec-event-sink@{digest}"', rendered)
        self.assertNotIn(f'k8s-sec-event-sink:0.1.0"', rendered)

    def test_local_bootstrap_clears_digest_and_uses_loaded_tag(self):
        rendered = self.render(
            extra_args=(
                "--set-string",
                "eventSink.image.repository=k8s-sec-event-sink",
                "--set-string",
                "eventSink.image.tag=0.1.0",
                "--set-string",
                "eventSink.image.digest=",
                "--set-string",
                "eventSink.image.pullPolicy=Never",
            )
        )
        self.assertIn('image: "k8s-sec-event-sink:0.1.0"', rendered)
        self.assertIn("imagePullPolicy: Never", rendered)

        bootstrap = (REPO / "hack" / "bootstrap.sh").read_text()
        self.assertIn("--set-string eventSink.image.digest=", bootstrap)
        self.assertIn("if dependencies_ready; then", bootstrap)
        self.assertIn("Using existing lock-pinned chart dependencies", bootstrap)
        self.assertIn("for attempt in 1 2 3; do", bootstrap)
        for capability in (
            "relevancy",
            "runtimeObservability",
            "networkPolicyService",
            "nodeProfileService",
            "seccompProfileService",
        ):
            self.assertIn(
                f"--set-string kubescape-operator.capabilities.{capability}=disable",
                bootstrap,
            )

    def test_falco_uses_container_plugin_with_cri_panic_fix(self):
        values = (CHART / "values.yaml").read_text()
        self.assertIn(
            'pluginRef: "ghcr.io/falcosecurity/plugins/plugin/container:0.7.5"',
            values,
        )

    def test_operator_values_use_dependency_names(self):
        chart = (CHART / "Chart.yaml").read_text()
        values = (CHART / "values.yaml").read_text()
        notes = (CHART / "templates" / "NOTES.txt").read_text()

        for dependency in ("trivy-operator", "kubescape-operator"):
            self.assertIn(f"condition: {dependency}.enabled", chart)
            self.assertIn(f"\n{dependency}:\n", values)
            self.assertIn(f'index .Values "{dependency}"', notes)

        self.assertNotIn("\ntrivyOperator:\n", values)
        self.assertNotIn("\nkubescapeOperator:\n", values)
        self.assertIn('version: "1.40.4"', chart)
        self.assertIn("  defaultFrameworks:\n    - nsa", values)
        self.assertIn("    triggerSecurityFramework: false", values)

    def test_kubescape_namespace_is_created_when_enabled(self):
        rendered = self.render()
        self.assertIn(
            "kind: Namespace\nmetadata:\n  name: kubescape",
            rendered,
        )

        disabled = self.render(extra_args=("--set", "kubescape-operator.enabled=false"))
        self.assertNotIn("kind: Namespace\nmetadata:\n  name: kubescape", disabled)

    def test_network_policy_limits_sink_to_named_producers_and_query_clients(self):
        rendered = self.render()
        self.assertIn("name: mcp-event-sink-default-deny", rendered)
        self.assertIn("name: falcosidekick-boundary", rendered)
        self.assertIn("app.kubernetes.io/name: posture-snapshot", rendered)
        self.assertIn('k8s-sec-stack.io/event-sink-query: "true"', rendered)

    def test_posture_snapshot_reads_actual_kubescape_resources(self):
        rendered = self.render()
        self.assertIn(
            "spdx.softwarecomposition.kubescape.io/v1beta1/",
            rendered,
        )
        self.assertIn("workloadconfigurationscansummaries", rendered)
        self.assertNotIn(
            '"tool": "kubescape",\n                    "namespace": None',
            rendered,
        )

    def test_explicit_local_profile_can_render_nodeport(self):
        rendered = self.render(extra_args=("-f", str(CHART / "values-local-dev.yaml")))
        self.assertIn("type: NodePort", rendered)
        self.assertIn("nodePort: 32080", rendered)

    def test_falcosidekick_default_is_clusterip_and_namespace_neutral(self):
        values = (CHART / "values.yaml").read_text()
        self.assertIn("falcosidekick:\n  enabled: true", values)
        self.assertIn("  service:\n    type: ClusterIP", values)
        self.assertIn('url: "http://falcosidekick:2801"', values)
        self.assertIn("fullnameOverride: falcosidekick", values)
        self.assertNotIn(".security.svc", values)


if __name__ == "__main__":
    unittest.main()

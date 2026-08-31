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
        published_digest = "sha256:ecd8cf86a6284ccaed6a9ee63c363f0d04fa01b65e43c327af01b9a576131479"
        default_render = self.render()
        self.assertIn(
            f'image: "ghcr.io/sf-matt/k8s-sec-event-sink@{published_digest}"',
            default_render,
        )

        digest = "sha256:" + "a" * 64
        rendered = self.render(extra_args=("--set", f"eventSink.image.digest={digest}"))
        self.assertIn(f'image: "ghcr.io/sf-matt/k8s-sec-event-sink@{digest}"', rendered)
        self.assertNotIn(f'k8s-sec-event-sink:0.1.0"', rendered)

    def test_network_policy_limits_sink_to_named_producers_and_query_clients(self):
        rendered = self.render()
        self.assertIn("name: mcp-event-sink-default-deny", rendered)
        self.assertIn("name: falcosidekick-boundary", rendered)
        self.assertIn("app.kubernetes.io/name: posture-snapshot", rendered)
        self.assertIn('k8s-sec-stack.io/event-sink-query: "true"', rendered)

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

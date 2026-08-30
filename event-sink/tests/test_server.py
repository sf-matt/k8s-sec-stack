from __future__ import annotations

import http.client
import json
import sys
import tempfile
import threading
import unittest
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1] / "src"))

from k8s_sec_event_sink.server import EventSinkServer, Settings, Store


EVENT = {
    "time": "2026-08-30T12:00:00Z",
    "priority": "Warning",
    "rule": "Terminal shell in container",
    "output": "token=do-not-retain",
    "output_fields": {
        "k8s.ns.name": "demo",
        "k8s.pod.name": "shell-123",
        "container.image.repository": "example/app",
        "proc.name": "sh",
        "proc.cmdline": "sh -c token=do-not-retain",
    },
    "tags": ["container"],
}


class ServerTest(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.settings = Settings(
            db_path=Path(self.temp_dir.name) / "events.db",
            max_body_bytes=1_024,
            max_snapshot_batch=2,
            max_query_limit=2,
            max_query_hours=24,
            max_query_days=30,
            ingest_token="i" * 24,
            query_token="q" * 24,
        )
        self.store = Store(self.settings)
        self.store.init()
        self.server = EventSinkServer(("127.0.0.1", 0), self.store)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.temp_dir.cleanup()

    def request(self, method, path, payload=None, *, token=None, headers=None):
        body = json.dumps(payload).encode() if payload is not None else None
        request_headers = dict(headers or {})
        if payload is not None:
            request_headers.setdefault("Content-Type", "application/json")
        if token:
            request_headers["Authorization"] = f"Bearer {token}"
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        connection.request(method, path, body=body, headers=request_headers)
        response = connection.getresponse()
        response_body = response.read()
        connection.close()
        return response.status, json.loads(response_body) if response_body else None

    def test_separate_ingest_and_query_tokens_are_required(self):
        status, body = self.request("POST", "/events", EVENT, token="q" * 24)
        self.assertEqual(status, 401)
        self.assertEqual(body["error"]["code"], "unauthorized")

        status, _ = self.request("POST", "/events", EVENT, token="i" * 24)
        self.assertEqual(status, 202)

        status, _ = self.request("GET", "/events", token="i" * 24)
        self.assertEqual(status, 401)
        status, events = self.request("GET", "/events", token="q" * 24)
        self.assertEqual(status, 200)
        self.assertEqual(events[0]["namespace"], "demo")

    def test_unknown_post_route_is_not_treated_as_ingestion(self):
        status, body = self.request("POST", "/anything", EVENT, token="i" * 24)
        self.assertEqual(status, 404)
        self.assertEqual(body["error"]["code"], "not_found")

    def test_unsupported_methods_return_structured_error(self):
        status, body = self.request("PUT", "/events", EVENT, token="i" * 24)
        self.assertEqual(status, 405)
        self.assertEqual(body["error"]["code"], "method_not_allowed")

    def test_body_content_type_and_schema_are_validated(self):
        status, _ = self.request(
            "POST", "/events", EVENT, token="i" * 24, headers={"Content-Type": "text/plain"}
        )
        self.assertEqual(status, 415)

        malformed = dict(EVENT, time="not-a-time")
        status, body = self.request("POST", "/events", malformed, token="i" * 24)
        self.assertEqual(status, 422)
        self.assertEqual(body["error"]["code"], "invalid_payload")

    def test_body_size_is_rejected_before_reading(self):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=2)
        connection.request(
            "POST",
            "/events",
            body=b"{}",
            headers={
                "Authorization": f"Bearer {'i' * 24}",
                "Content-Type": "application/json",
                "Content-Length": "1025",
            },
        )
        response = connection.getresponse()
        self.assertEqual(response.status, 413)
        self.assertEqual(json.loads(response.read())["error"]["code"], "payload_too_large")
        connection.close()

    def test_query_bounds_and_allowlist(self):
        for path in ("/events?limit=3", "/events?hours=25", "/events?limit=nope", "/events?extra=x"):
            with self.subTest(path=path):
                status, body = self.request("GET", path, token="q" * 24)
                self.assertEqual(status, 400)
                self.assertEqual(body["error"]["code"], "invalid_query")

    def test_snapshot_batch_and_schema_are_bounded(self):
        snapshot = {
            "snapped_at": "2026-08-30T12:00:00+00:00",
            "tool": "trivy",
            "namespace": "demo",
            "metric": "vuln_high",
            "value": 1,
        }
        status, _ = self.request("POST", "/posture/snapshot", [snapshot] * 3, token="i" * 24)
        self.assertEqual(status, 422)
        status, _ = self.request("POST", "/posture/snapshot", [snapshot], token="i" * 24)
        self.assertEqual(status, 202)

    def test_raw_payload_is_not_retained_by_default(self):
        self.request("POST", "/events", EVENT, token="i" * 24)
        with self.store.connect() as connection:
            raw = connection.execute("SELECT raw FROM events").fetchone()[0]
        self.assertEqual(raw, "")
        status, events = self.request("GET", "/events", token="q" * 24)
        self.assertEqual(status, 200)
        self.assertNotIn("output", events[0])
        self.assertNotIn("do-not-retain", json.dumps(events))

    def test_opted_in_raw_payload_is_redacted(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

        raw_settings = replace(self.settings, store_raw_events=True)
        self.store = Store(raw_settings)
        self.server = EventSinkServer(("127.0.0.1", 0), self.store)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        self.request("POST", "/events", EVENT, token="i" * 24)
        _, events = self.request("GET", "/events", token="q" * 24)
        self.assertEqual(events[0]["output"], "[REDACTED]")
        self.assertEqual(events[0]["output_fields"]["proc.cmdline"], "[REDACTED]")
        self.assertNotIn("do-not-retain", json.dumps(events))

    def test_retention_days_are_applied_to_events_and_posture(self):
        old_event = dict(EVENT, time="2020-01-01T00:00:00Z")
        self.request("POST", "/events", old_event, token="i" * 24)
        snapshot = {
            "snapped_at": "2020-01-01T00:00:00Z",
            "tool": "trivy",
            "metric": "vuln_high",
            "value": 1,
        }
        self.request("POST", "/posture/snapshot", [snapshot], token="i" * 24)
        self.assertEqual(self.store.purge_old(), (1, 1))

    def test_response_size_is_bounded(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)

        limited_settings = replace(self.settings, max_response_bytes=128)
        self.store = Store(limited_settings)
        self.server = EventSinkServer(("127.0.0.1", 0), self.store)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

        self.request("POST", "/events", EVENT, token="i" * 24)
        status, body = self.request("GET", "/events", token="q" * 24)
        self.assertEqual(status, 413)
        self.assertEqual(body["error"]["code"], "response_too_large")


if __name__ == "__main__":
    unittest.main()

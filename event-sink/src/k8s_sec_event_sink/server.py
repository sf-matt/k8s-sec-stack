"""Bounded HTTP API and SQLite store for runtime and posture evidence."""

from __future__ import annotations

import copy
import hmac
import json
import math
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

PRIORITY_ORDER = (
    "EMERGENCY",
    "ALERT",
    "CRITICAL",
    "ERROR",
    "WARNING",
    "NOTICE",
    "INFORMATIONAL",
    "DEBUG",
)
EVENT_FIELDS = {
    "k8s.ns.name": "namespace",
    "k8s.pod.name": "pod",
    "container.image.repository": "image",
    "proc.name": "process",
}
POSTURE_TOOLS = {"trivy", "kubescape", "kyverno"}
TOKEN_RE = re.compile(r"^[A-Za-z0-9._~+/=-]{16,512}$")
SCHEMA_VERSION = 1


class ApiError(Exception):
    def __init__(self, status: HTTPStatus, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message


def _env_bool(name: str, default: bool) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    if value.lower() not in {"true", "false"}:
        raise ValueError(f"{name} must be true or false")
    return value.lower() == "true"


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} must be between {minimum} and {maximum}")
    return value


@dataclass(frozen=True)
class Settings:
    db_path: Path = Path("/data/events.db")
    retention_days: int = 30
    store_raw_events: bool = False
    redacted_fields: tuple[str, ...] = ("output", "output_fields.proc.cmdline", "output_fields.proc.args")
    max_body_bytes: int = 262_144
    max_snapshot_batch: int = 1_000
    max_query_limit: int = 200
    max_query_hours: int = 720
    max_query_days: int = 90
    max_trend_records: int = 1_000
    max_response_bytes: int = 1_048_576
    max_concurrent_requests: int = 32
    socket_timeout_seconds: int = 10
    ingest_token: str = ""
    query_token: str = ""

    @classmethod
    def from_env(cls) -> "Settings":
        settings = cls(
            db_path=Path(os.environ.get("EVENT_SINK_DB_PATH", "/data/events.db")),
            retention_days=_env_int("EVENT_SINK_RETENTION_DAYS", 30, 1, 365),
            store_raw_events=_env_bool("EVENT_SINK_STORE_RAW_EVENTS", False),
            redacted_fields=tuple(
                item.strip()
                for item in os.environ.get(
                    "EVENT_SINK_REDACTED_FIELDS",
                    "output,output_fields.proc.cmdline,output_fields.proc.args",
                ).split(",")
                if item.strip()
            ),
            max_body_bytes=_env_int("EVENT_SINK_MAX_BODY_BYTES", 262_144, 1_024, 1_048_576),
            max_snapshot_batch=_env_int("EVENT_SINK_MAX_SNAPSHOT_BATCH", 1_000, 1, 10_000),
            max_query_limit=_env_int("EVENT_SINK_MAX_QUERY_LIMIT", 200, 1, 1_000),
            max_query_hours=_env_int("EVENT_SINK_MAX_QUERY_HOURS", 720, 1, 8_760),
            max_query_days=_env_int("EVENT_SINK_MAX_QUERY_DAYS", 90, 1, 365),
            max_trend_records=_env_int("EVENT_SINK_MAX_TREND_RECORDS", 1_000, 1, 10_000),
            max_response_bytes=_env_int("EVENT_SINK_MAX_RESPONSE_BYTES", 1_048_576, 1_024, 10_485_760),
            max_concurrent_requests=_env_int("EVENT_SINK_MAX_CONCURRENT_REQUESTS", 32, 1, 256),
            socket_timeout_seconds=_env_int("EVENT_SINK_SOCKET_TIMEOUT_SECONDS", 10, 1, 60),
            ingest_token=os.environ.get("EVENT_SINK_INGEST_TOKEN", ""),
            query_token=os.environ.get("EVENT_SINK_QUERY_TOKEN", ""),
        )
        settings.validate_auth()
        return settings

    def validate_auth(self) -> None:
        for name, token in (
            ("EVENT_SINK_INGEST_TOKEN", self.ingest_token),
            ("EVENT_SINK_QUERY_TOKEN", self.query_token),
        ):
            if not token:
                raise ValueError(f"{name} is required")
            if not TOKEN_RE.fullmatch(token):
                raise ValueError(f"{name} must contain 16-512 token-safe characters")
        if hmac.compare_digest(self.ingest_token, self.query_token):
            raise ValueError("EVENT_SINK_INGEST_TOKEN and EVENT_SINK_QUERY_TOKEN must be distinct")


def _bounded_string(value: Any, field: str, *, required: bool = False, maximum: int = 512) -> str | None:
    if value is None and not required:
        return None
    if not isinstance(value, str) or (required and not value):
        raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "invalid_payload", f"{field} must be a non-empty string")
    if len(value) > maximum:
        raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "invalid_payload", f"{field} exceeds {maximum} characters")
    return value


def _timestamp(value: Any, field: str) -> str:
    timestamp = _bounded_string(value, field, required=True, maximum=128)
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "invalid_payload", f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "invalid_payload", f"{field} must include a timezone")
    return timestamp


def _redact(payload: dict[str, Any], paths: tuple[str, ...]) -> dict[str, Any]:
    redacted = copy.deepcopy(payload)

    def redact_path(current: Any, path: str) -> None:
        if not isinstance(current, dict):
            return
        if path in current:
            current[path] = "[REDACTED]"
            return
        for key, value in current.items():
            prefix = f"{key}."
            if path.startswith(prefix):
                redact_path(value, path[len(prefix) :])
                return

    for path in paths:
        redact_path(redacted, path)
    return redacted


def validate_event(payload: Any, settings: Settings) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "invalid_payload", "event must be a JSON object")
    timestamp = _timestamp(payload.get("time"), "time")
    priority = _bounded_string(payload.get("priority"), "priority", maximum=32)
    if priority is not None:
        priority = priority.upper()
        if priority not in PRIORITY_ORDER:
            raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "invalid_payload", "priority is not recognized")
    rule = _bounded_string(payload.get("rule"), "rule", maximum=512)
    fields = payload.get("output_fields") or {}
    if not isinstance(fields, dict):
        raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "invalid_payload", "output_fields must be an object")
    normalized = {
        "time": timestamp,
        "priority": priority,
        "rule": rule,
    }
    for source, destination in EVENT_FIELDS.items():
        normalized[destination] = _bounded_string(fields.get(source), f"output_fields.{source}", maximum=512)
    tags = payload.get("tags") or []
    if not isinstance(tags, list) or len(tags) > 64:
        raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "invalid_payload", "tags must be an array of at most 64 strings")
    normalized["tags"] = [_bounded_string(tag, "tags[]", required=True, maximum=128) for tag in tags]
    normalized["raw"] = _redact(payload, settings.redacted_fields) if settings.store_raw_events else None
    return normalized


def validate_snapshots(payload: Any, settings: Settings) -> list[dict[str, Any]]:
    if not isinstance(payload, list) or not payload or len(payload) > settings.max_snapshot_batch:
        raise ApiError(
            HTTPStatus.UNPROCESSABLE_ENTITY,
            "invalid_payload",
            f"snapshot body must contain 1-{settings.max_snapshot_batch} records",
        )
    validated = []
    for index, item in enumerate(payload):
        if not isinstance(item, dict):
            raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "invalid_payload", f"snapshot[{index}] must be an object")
        tool = _bounded_string(item.get("tool"), f"snapshot[{index}].tool", required=True, maximum=32)
        if tool not in POSTURE_TOOLS:
            raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "invalid_payload", f"snapshot[{index}].tool is not supported")
        value = item.get("value")
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "invalid_payload", f"snapshot[{index}].value must be numeric")
        labels = item.get("labels")
        if labels is not None and not isinstance(labels, dict):
            raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "invalid_payload", f"snapshot[{index}].labels must be an object")
        if labels is not None and len(json.dumps(labels)) > 8_192:
            raise ApiError(HTTPStatus.UNPROCESSABLE_ENTITY, "invalid_payload", f"snapshot[{index}].labels is too large")
        validated.append(
            {
                "snapped_at": _timestamp(item.get("snapped_at"), f"snapshot[{index}].snapped_at"),
                "tool": tool,
                "namespace": _bounded_string(item.get("namespace"), f"snapshot[{index}].namespace", maximum=253),
                "metric": _bounded_string(item.get("metric"), f"snapshot[{index}].metric", required=True, maximum=128),
                "value": float(value),
                "labels": labels,
            }
        )
    return validated


class Store:
    def __init__(self, settings: Settings):
        self.settings = settings
        self.lock = threading.Lock()

    def connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.settings.db_path, timeout=5)

    def init(self) -> None:
        self.settings.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    time TEXT NOT NULL, priority TEXT, rule TEXT, ns TEXT, pod TEXT,
                    image TEXT, process TEXT, tags TEXT NOT NULL, raw TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_time ON events(time);
                CREATE INDEX IF NOT EXISTS idx_priority ON events(priority);
                CREATE INDEX IF NOT EXISTS idx_ns ON events(ns);
                CREATE INDEX IF NOT EXISTS idx_rule ON events(rule);
                CREATE TABLE IF NOT EXISTS posture_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapped_at TEXT NOT NULL, tool TEXT NOT NULL, namespace TEXT,
                    metric TEXT NOT NULL, value REAL NOT NULL, labels TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_ps_snapped_at ON posture_snapshots(snapped_at);
                CREATE INDEX IF NOT EXISTS idx_ps_tool ON posture_snapshots(tool);
                """
            )
            schema_version = conn.execute("PRAGMA user_version").fetchone()[0]
            if schema_version < SCHEMA_VERSION:
                # Version 0 includes the original sink, which retained complete,
                # unredacted Falco bodies. They cannot safely inherit the new
                # opt-in retention policy, so discard them during upgrade.
                conn.execute("UPDATE events SET raw = '' WHERE raw IS NOT NULL AND raw != ''")
                # SQLite does not parameterize PRAGMA assignment. The value is a
                # module-owned integer constant, never request or database data.
                conn.execute(  # nosemgrep: python.lang.security.audit.formatted-sql-query.formatted-sql-query, python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
                    f"PRAGMA user_version = {SCHEMA_VERSION}"
                )
            if not self.settings.store_raw_events:
                # Also enforce policy changes from true to false on every start.
                conn.execute("UPDATE events SET raw = '' WHERE raw IS NOT NULL AND raw != ''")

    def purge_old(self) -> tuple[int, int]:
        with self.lock, self.connect() as conn:
            age = f"-{self.settings.retention_days} days"
            events = conn.execute("DELETE FROM events WHERE datetime(time) < datetime('now', ?)", (age,)).rowcount
            posture = conn.execute(
                "DELETE FROM posture_snapshots WHERE datetime(snapped_at) < datetime('now', ?)", (age,)
            ).rowcount
            return events, posture

    def insert_event(self, event: dict[str, Any]) -> None:
        with self.lock, self.connect() as conn:
            conn.execute(
                "INSERT INTO events (time, priority, rule, ns, pod, image, process, tags, raw) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event["time"], event["priority"], event["rule"], event["namespace"], event["pod"],
                    event["image"], event["process"], json.dumps(event["tags"]),
                    json.dumps(event["raw"]) if event["raw"] is not None else "",
                ),
            )

    def insert_snapshots(self, snapshots: list[dict[str, Any]]) -> None:
        with self.lock, self.connect() as conn:
            conn.executemany(
                "INSERT INTO posture_snapshots (snapped_at, tool, namespace, metric, value, labels) VALUES (?, ?, ?, ?, ?, ?)",
                [
                    (s["snapped_at"], s["tool"], s["namespace"], s["metric"], s["value"], json.dumps(s["labels"]) if s["labels"] else None)
                    for s in snapshots
                ],
            )

    def query_events(self, *, priority: str, namespace: str, pod: str, rule: str, hours: int, limit: int) -> list[dict[str, Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if priority != "ALL":
            cutoff = PRIORITY_ORDER.index(priority)
            placeholders = ",".join("?" for _ in range(cutoff + 1))
            clauses.append(f"priority IN ({placeholders})")
            params.extend(PRIORITY_ORDER[: cutoff + 1])
        for column, value in (("ns", namespace), ("pod", pod), ("rule", rule)):
            if value:
                clauses.append(f"{column} LIKE ? ESCAPE '\\'")
                escaped = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
                params.append(f"%{escaped}%")
        if hours:
            clauses.append("datetime(time) >= datetime('now', ?)")
            params.append(f"-{hours} hours")
        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        params.append(limit)
        with self.lock, self.connect() as conn:
            # `where` contains only fixed column/operator fragments assembled
            # above; every caller-controlled value remains a bound parameter.
            rows = conn.execute(  # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
                f"SELECT time, priority, rule, ns, pod, image, process, tags, raw FROM events {where} ORDER BY time DESC LIMIT ?",
                params,
            ).fetchall()
        results = []
        for timestamp, pri, event_rule, ns, event_pod, image, process, tags, raw in rows:
            normalized = {
                "time": timestamp, "priority": pri, "rule": event_rule, "namespace": ns,
                "pod": event_pod, "image": image, "process": process, "tags": json.loads(tags),
            }
            results.append(json.loads(raw) if self.settings.store_raw_events and raw else normalized)
        return results

    def query_event_trends(self, days: int) -> dict[str, Any]:
        age = f"-{days} days"
        with self.lock, self.connect() as conn:
            daily = conn.execute(
                "SELECT date(time), priority, count(*) FROM events WHERE datetime(time) >= datetime('now', ?) GROUP BY date(time), priority ORDER BY date(time) DESC",
                (age,),
            ).fetchall()
            top_rules = conn.execute(
                "SELECT rule, count(*) FROM events WHERE datetime(time) >= datetime('now', ?) GROUP BY rule ORDER BY count(*) DESC LIMIT 20",
                (age,),
            ).fetchall()
            top_ns = conn.execute(
                "SELECT ns, count(*) FROM events WHERE datetime(time) >= datetime('now', ?) AND ns IS NOT NULL GROUP BY ns ORDER BY count(*) DESC LIMIT 10",
                (age,),
            ).fetchall()
            total = conn.execute("SELECT count(*) FROM events WHERE datetime(time) >= datetime('now', ?)", (age,)).fetchone()[0]
        by_day: dict[str, dict[str, int]] = {}
        for day, priority, count in daily:
            by_day.setdefault(day, {})[priority] = count
        return {
            "days": days,
            "total_events": total,
            "by_day": [{"date": day, "counts": counts} for day, counts in sorted(by_day.items(), reverse=True)],
            "top_rules": [{"rule": rule, "count": count} for rule, count in top_rules],
            "top_namespaces": [{"namespace": namespace, "count": count} for namespace, count in top_ns],
        }

    def query_posture_trends(self, *, tool: str, namespace: str, days: int) -> dict[str, Any]:
        clauses = ["datetime(snapped_at) >= datetime('now', ?)"]
        params: list[Any] = [f"-{days} days"]
        if tool != "all":
            clauses.append("tool = ?")
            params.append(tool)
        if namespace not in {"all", ""}:
            clauses.append("(namespace = ? OR namespace IS NULL)")
            params.append(namespace)
        with self.lock, self.connect() as conn:
            # `clauses` contains only fixed server-owned SQL fragments; caller
            # values are supplied separately as SQLite parameters.
            rows = conn.execute(  # nosemgrep: python.sqlalchemy.security.sqlalchemy-execute-raw-query.sqlalchemy-execute-raw-query
                f"""SELECT date(snapped_at), tool, namespace, metric, AVG(value), MIN(labels)
                FROM posture_snapshots WHERE {' AND '.join(clauses)}
                GROUP BY date(snapped_at), tool, namespace, metric
                ORDER BY date(snapped_at) DESC, tool, namespace, metric LIMIT ?""",
                [*params, self.settings.max_trend_records],
            ).fetchall()
        by_tool: dict[str, list[dict[str, Any]]] = {}
        for day, row_tool, ns, metric, value, labels in rows:
            entry: dict[str, Any] = {"date": day, "namespace": ns, "metric": metric, "value": round(value, 2)}
            if labels:
                entry["labels"] = json.loads(labels)
            by_tool.setdefault(row_tool, []).append(entry)
        return {"days": days, **by_tool}


class EventSinkServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 32

    def __init__(self, address: tuple[str, int], store: Store):
        self.store = store
        self.settings = store.settings
        self.settings.validate_auth()
        self.request_slots = threading.BoundedSemaphore(self.settings.max_concurrent_requests)
        super().__init__(address, Handler)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self.request_slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.request_slots.release()


class Handler(BaseHTTPRequestHandler):
    server: EventSinkServer

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(self.server.settings.socket_timeout_seconds)

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"{self.client_address[0]} {fmt % args}", flush=True)

    def _send_json(self, status: HTTPStatus, data: Any) -> None:
        body = json.dumps(data, separators=(",", ":")).encode()
        if len(body) > self.server.settings.max_response_bytes:
            status = HTTPStatus.REQUEST_ENTITY_TOO_LARGE
            body = json.dumps(
                {"error": {"code": "response_too_large", "message": "narrow the query filters"}},
                separators=(",", ":"),
            ).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _error(self, error: ApiError) -> None:
        self._send_json(error.status, {"error": {"code": error.code, "message": error.message}})

    def _authorize(self, token: str) -> None:
        if not token:
            return
        supplied = self.headers.get("Authorization", "")
        if not supplied.startswith("Bearer ") or not hmac.compare_digest(supplied[7:], token):
            raise ApiError(HTTPStatus.UNAUTHORIZED, "unauthorized", "a valid bearer token is required")

    def _method_not_allowed(self) -> None:
        self._send_json(
            HTTPStatus.METHOD_NOT_ALLOWED,
            {"error": {"code": "method_not_allowed", "message": "method not allowed"}},
        )

    do_DELETE = _method_not_allowed
    do_HEAD = _method_not_allowed
    do_OPTIONS = _method_not_allowed
    do_PATCH = _method_not_allowed
    do_PUT = _method_not_allowed

    def _read_json(self) -> Any:
        if self.headers.get("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
            raise ApiError(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type", "Content-Type must be application/json")
        raw_length = self.headers.get("Content-Length")
        if raw_length is None:
            raise ApiError(HTTPStatus.LENGTH_REQUIRED, "length_required", "Content-Length is required")
        try:
            length = int(raw_length)
        except ValueError as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_content_length", "Content-Length must be an integer") from exc
        if length <= 0 or length > self.server.settings.max_body_bytes:
            raise ApiError(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "payload_too_large",
                f"body must be 1-{self.server.settings.max_body_bytes} bytes",
            )
        try:
            return json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_json", "body must be valid UTF-8 JSON") from exc

    def do_POST(self) -> None:
        try:
            path = urlparse(self.path)
            if path.query or path.path not in {"/events", "/posture/snapshot"}:
                raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "route not found")
            self._authorize(self.server.settings.ingest_token)
            payload = self._read_json()
            if path.path == "/events":
                self.server.store.insert_event(validate_event(payload, self.server.settings))
            else:
                self.server.store.insert_snapshots(validate_snapshots(payload, self.server.settings))
            self._send_json(HTTPStatus.ACCEPTED, {"status": "accepted"})
        except ApiError as error:
            self._error(error)

    def _query(self, allowed: set[str]) -> dict[str, str]:
        parsed = urlparse(self.path)
        raw = parse_qs(parsed.query, keep_blank_values=True)
        unknown = set(raw) - allowed
        if unknown:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_query", f"unsupported query parameter: {sorted(unknown)[0]}")
        if any(len(values) != 1 for values in raw.values()):
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_query", "query parameters may not be repeated")
        return {key: values[0] for key, values in raw.items()}

    def _query_int(self, query: dict[str, str], key: str, default: int, minimum: int, maximum: int) -> int:
        try:
            value = int(query.get(key, str(default)))
        except ValueError as exc:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_query", f"{key} must be an integer") from exc
        if not minimum <= value <= maximum:
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_query", f"{key} must be between {minimum} and {maximum}")
        return value

    def _filter(self, query: dict[str, str], key: str, default: str = "") -> str:
        value = query.get(key, default)
        if len(value) > 253 or any(ord(character) < 32 for character in value):
            raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_query", f"{key} is invalid")
        return value

    def do_GET(self) -> None:
        try:
            path = urlparse(self.path).path
            if path == "/healthz":
                if urlparse(self.path).query:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_query", "healthz does not accept query parameters")
                self._send_json(HTTPStatus.OK, {"status": "ok"})
                return
            if path not in {"/events", "/events/trends", "/posture/trends"}:
                raise ApiError(HTTPStatus.NOT_FOUND, "not_found", "route not found")
            self._authorize(self.server.settings.query_token)
            if path == "/events":
                query = self._query({"priority", "namespace", "pod", "rule", "hours", "limit"})
                priority = self._filter(query, "priority", "ALL").upper()
                if priority not in {*PRIORITY_ORDER, "ALL"}:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_query", "priority is not recognized")
                data = self.server.store.query_events(
                    priority=priority,
                    namespace=self._filter(query, "namespace"),
                    pod=self._filter(query, "pod"),
                    rule=self._filter(query, "rule"),
                    hours=self._query_int(query, "hours", 0, 0, self.server.settings.max_query_hours),
                    limit=self._query_int(
                        query, "limit", min(50, self.server.settings.max_query_limit), 1, self.server.settings.max_query_limit
                    ),
                )
            elif path == "/events/trends":
                query = self._query({"days"})
                data = self.server.store.query_event_trends(
                    self._query_int(
                        query, "days", min(7, self.server.settings.max_query_days), 1, self.server.settings.max_query_days
                    )
                )
            else:
                query = self._query({"tool", "namespace", "days"})
                tool = self._filter(query, "tool", "all").lower()
                if tool not in {*POSTURE_TOOLS, "all"}:
                    raise ApiError(HTTPStatus.BAD_REQUEST, "invalid_query", "tool is not supported")
                data = self.server.store.query_posture_trends(
                    tool=tool,
                    namespace=self._filter(query, "namespace", "all"),
                    days=self._query_int(
                        query, "days", min(30, self.server.settings.max_query_days), 1, self.server.settings.max_query_days
                    ),
                )
            self._send_json(HTTPStatus.OK, data)
        except ApiError as error:
            self._error(error)


def retention_loop(store: Store) -> None:
    while True:
        time.sleep(3_600)
        events, posture = store.purge_old()
        if events or posture:
            print(f"purged {events} events and {posture} posture records", flush=True)


def main() -> None:
    settings = Settings.from_env()
    store = Store(settings)
    store.init()
    store.purge_old()
    threading.Thread(target=retention_loop, args=(store,), daemon=True).start()
    server = EventSinkServer(("0.0.0.0", 8080), store)
    print("k8s-sec-event-sink listening on :8080", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()

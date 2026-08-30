"""Falco runtime event tools — reads from falcosidekick webhook sink."""

import json
import os
import httpx

SINK_URL = os.environ.get("FALCO_SINK_URL", "http://localhost:8080")
SINK_TOKEN = os.environ.get("FALCO_SINK_TOKEN", "")

PRIORITY_ORDER = ["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "NOTICE", "INFORMATIONAL", "DEBUG"]


def _headers() -> dict[str, str]:
    return {"Authorization": f"Bearer {SINK_TOKEN}"} if SINK_TOKEN else {}


async def list_runtime_events(
    priority: str = "ALL",
    namespace: str = "",
    pod: str = "",
    rule: str = "",
    hours: int = 0,
    limit: int = 50,
) -> str:
    params: dict = {"limit": limit}
    if priority != "ALL":
        params["priority"] = priority
    if namespace:
        params["namespace"] = namespace
    if pod:
        params["pod"] = pod
    if rule:
        params["rule"] = rule
    if hours > 0:
        params["hours"] = hours

    async with httpx.AsyncClient(timeout=10) as c:
        resp = await c.get(f"{SINK_URL}/events", params=params, headers=_headers())
        resp.raise_for_status()
        events = resp.json()

    normalized = []
    for e in events:
        fields = e.get("output_fields") or e.get("outputFields") or {}
        normalized.append({
            "time": e.get("time") or e.get("timestamp"),
            "priority": e.get("priority"),
            "rule": e.get("rule"),
            "output": e.get("output"),
            "namespace": fields.get("k8s.ns.name") or e.get("namespace"),
            "pod": fields.get("k8s.pod.name") or e.get("pod"),
            "container_image": fields.get("container.image.repository") or e.get("image"),
            "process": fields.get("proc.name") or e.get("process"),
            "tags": e.get("tags", []),
        })

    return json.dumps(normalized, indent=2)


async def list_runtime_trends(days: int = 7) -> str:
    async with httpx.AsyncClient(timeout=10) as c:
        resp = await c.get(f"{SINK_URL}/events/trends", params={"days": days}, headers=_headers())
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2)


async def list_posture_trends(tool: str = "all", namespace: str = "all", days: int = 30) -> str:
    params: dict = {"days": days}
    if tool != "all":
        params["tool"] = tool
    if namespace != "all":
        params["namespace"] = namespace

    async with httpx.AsyncClient(timeout=10) as c:
        resp = await c.get(f"{SINK_URL}/posture/trends", params=params, headers=_headers())
        resp.raise_for_status()
        return json.dumps(resp.json(), indent=2)

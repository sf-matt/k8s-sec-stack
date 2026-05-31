"""MCP server — bridges k8s security CRDs to LLM tools."""

import mcp.server.stdio
import mcp.types as types
from mcp.server import Server

from k8s_sec_mcp.tools.vulns import list_vuln_reports
from k8s_sec_mcp.tools.posture import list_compliance_reports, list_policy_violations
from k8s_sec_mcp.tools.runtime import list_runtime_events, list_runtime_trends, list_posture_trends
from k8s_sec_mcp.tools.trivy import (
    list_config_audit,
    list_exposed_secrets,
    list_rbac_issues,
    list_infra_issues,
)
from k8s_sec_mcp.tools.k8s import get_pod_status, list_workloads, list_network_exposure, list_network_policies

app = Server("k8s-sec-mcp")


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    return [
        types.Tool(
            name="list_vuln_reports",
            description=(
                "List VulnerabilityReports from trivy-operator. "
                "Filter by namespace, severity, or image name. "
                "Returns CVE IDs, severity, fixed version, and affected resource."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {"type": "string", "description": "K8s namespace, or 'all'"},
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"],
                        "description": "Minimum severity to include",
                    },
                    "image": {"type": "string", "description": "Filter by image name substring"},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="list_compliance_reports",
            description=(
                "List ClusterComplianceReports from kubescape-operator. "
                "Returns CIS/NSA/MITRE framework results with pass/fail counts and failing controls."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "framework": {
                        "type": "string",
                        "description": "e.g. 'nsa', 'cis', 'mitre' — omit for all",
                    },
                },
                "required": [],
            },
        ),
        types.Tool(
            name="list_policy_violations",
            description=(
                "List PolicyReport violations from Kyverno. "
                "Returns policy name, rule, resource, and result (fail/warn/pass)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {"type": "string", "description": "K8s namespace, or 'all'"},
                    "result": {
                        "type": "string",
                        "enum": ["fail", "warn", "pass", "all"],
                    },
                },
                "required": [],
            },
        ),
        types.Tool(
            name="list_runtime_events",
            description=(
                "List recent Falco runtime security events from the event sink. "
                "Filter by priority, rule name, namespace, pod, or time window. "
                "Returns timestamp, priority, rule, process, and container context."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "priority": {
                        "type": "string",
                        "enum": ["EMERGENCY", "ALERT", "CRITICAL", "ERROR", "WARNING", "ALL"],
                    },
                    "namespace": {"type": "string"},
                    "pod": {"type": "string"},
                    "rule": {"type": "string", "description": "Falco rule name substring"},
                    "hours": {"type": "integer", "description": "Restrict to events in the last N hours"},
                    "limit": {"type": "integer", "default": 50},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="list_runtime_trends",
            description=(
                "Aggregate Falco event trends over a rolling window (default 7 days). "
                "Returns total event count, per-day breakdown by priority, top 20 firing rules, "
                "and top 10 most-affected namespaces. Use for posture trending and noise analysis."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "days": {"type": "integer", "description": "Rolling window in days (default 7)"},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="list_posture_trends",
            description=(
                "Trend posture metrics over time from daily snapshots (default 30 days). "
                "Covers three tools: 'trivy' (vuln counts by severity per namespace), "
                "'kubescape' (compliance score per framework), 'kyverno' (policy fail/warn/pass per namespace). "
                "Use to answer: is our vuln count going up? Is compliance improving? Where are new policy violations appearing?"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "tool": {
                        "type": "string",
                        "enum": ["trivy", "kubescape", "kyverno", "all"],
                        "description": "Filter to a single tool or return all (default)",
                    },
                    "namespace": {"type": "string", "description": "Filter to a specific namespace (default all)"},
                    "days": {"type": "integer", "description": "Rolling window in days (default 30)"},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="list_config_audit",
            description=(
                "List ConfigAuditReport failures from trivy-operator. "
                "Checks workload specs for misconfigurations: privileged containers, missing resource limits, "
                "no seccomp/AppArmor, running as root, host namespace access, etc. "
                "Filter by namespace and minimum severity. Results sorted by severity."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {"type": "string", "description": "K8s namespace, or 'all'"},
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"],
                        "description": "Minimum severity to include (default HIGH)",
                    },
                },
                "required": [],
            },
        ),
        types.Tool(
            name="list_exposed_secrets",
            description=(
                "List ExposedSecretReport findings from trivy-operator. "
                "Scans image layers for hardcoded secrets: API keys, tokens, private keys, passwords. "
                "Returns workload, image, secret type, and where in the image it was found."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {"type": "string", "description": "K8s namespace, or 'all'"},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="list_rbac_issues",
            description=(
                "List RBACAssessmentReport failures from trivy-operator. "
                "Flags over-permissive Roles, ClusterRoles, and ServiceAccounts: "
                "wildcard verbs, access to secrets, cluster-admin bindings, etc. "
                "Covers both namespaced roles and cluster-scoped roles."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {"type": "string", "description": "K8s namespace, or 'all'"},
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"],
                    },
                },
                "required": [],
            },
        ),
        types.Tool(
            name="get_pod_status",
            description=(
                "Check whether a specific pod still exists and return its current state. "
                "Use immediately after extracting a pod name from a runtime event — "
                "distinguishes an active incident (pod running) from a historical one (pod gone). "
                "Returns: exists, phase, age, owner controller (or standalone flag), node, containers."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {"type": "string"},
                    "pod": {"type": "string"},
                },
                "required": ["namespace", "pod"],
            },
        ),
        types.Tool(
            name="list_workloads",
            description=(
                "List Deployments, DaemonSets, and standalone Pods with their images and labels. "
                "Standalone pods (no owner reference) are flagged — they are often rogue or one-off. "
                "Use to correlate security findings with running workloads."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {"type": "string", "description": "K8s namespace, or 'all'"},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="list_network_exposure",
            description=(
                "List Services and Ingresses — which workloads are reachable and how. "
                "Flags NodePort and LoadBalancer services as externally reachable. "
                "Use to answer: which vulnerable or misconfigured workloads are internet-facing?"
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {"type": "string", "description": "K8s namespace, or 'all'"},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="list_network_policies",
            description=(
                "List NetworkPolicies per namespace. "
                "Explicitly marks namespaces with no policy as unprotected — "
                "those are open to unrestricted lateral movement between pods."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {"type": "string", "description": "K8s namespace, or 'all'"},
                },
                "required": [],
            },
        ),
        types.Tool(
            name="list_infra_issues",
            description=(
                "List InfraAssessmentReport failures from trivy-operator. "
                "Checks node and control-plane hardening: kubelet flags, etcd config, "
                "API server settings, file permissions on sensitive paths."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"],
                    },
                },
                "required": [],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[types.TextContent]:
    if name == "list_vuln_reports":
        result = await list_vuln_reports(**arguments)
    elif name == "list_compliance_reports":
        result = await list_compliance_reports(**arguments)
    elif name == "list_policy_violations":
        result = await list_policy_violations(**arguments)
    elif name == "list_runtime_events":
        result = await list_runtime_events(**arguments)
    elif name == "list_runtime_trends":
        result = await list_runtime_trends(**arguments)
    elif name == "list_posture_trends":
        result = await list_posture_trends(**arguments)
    elif name == "list_config_audit":
        result = await list_config_audit(**arguments)
    elif name == "list_exposed_secrets":
        result = await list_exposed_secrets(**arguments)
    elif name == "list_rbac_issues":
        result = await list_rbac_issues(**arguments)
    elif name == "list_infra_issues":
        result = await list_infra_issues(**arguments)
    elif name == "get_pod_status":
        result = await get_pod_status(**arguments)
    elif name == "list_workloads":
        result = await list_workloads(**arguments)
    elif name == "list_network_exposure":
        result = await list_network_exposure(**arguments)
    elif name == "list_network_policies":
        result = await list_network_policies(**arguments)
    else:
        raise ValueError(f"Unknown tool: {name}")

    return [types.TextContent(type="text", text=result)]


def main():
    import asyncio
    from mcp.server.stdio import stdio_server

    async def _run():
        async with stdio_server() as (read_stream, write_stream):
            await app.run(read_stream, write_stream, app.create_initialization_options())

    asyncio.run(_run())


if __name__ == "__main__":
    main()

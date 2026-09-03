"""MCP server — bridges k8s security CRDs to LLM tools."""

from mcp import types
from mcp.server import Server

from k8s_sec_mcp.contract import (
    UnknownToolError,
    apply_tool_contract,
    error_result,
    success_result,
    validate_arguments,
)
from k8s_sec_mcp.tools.k8s import (
    get_pod_status,
    list_image_registry_signals,
    list_network_exposure,
    list_network_policies,
    list_workloads,
)
from k8s_sec_mcp.tools.posture import (
    list_compliance_reports,
    list_policy_summary,
    list_policy_violations,
)
from k8s_sec_mcp.tools.runtime import (
    list_posture_trends,
    list_runtime_events,
    list_runtime_trends,
)
from k8s_sec_mcp.tools.trivy import (
    list_config_audit,
    list_config_audit_summary,
    list_exposed_secrets,
    list_infra_issues,
    list_rbac_issues,
)
from k8s_sec_mcp.tools.vulns import list_vuln_reports, list_vuln_summary

app = Server("k8s-sec-mcp")


@app.list_tools()
async def list_tools() -> list[types.Tool]:
    tools = [
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
                    "namespace": {
                        "type": "string",
                        "description": "K8s namespace, or 'all'",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"],
                        "description": "Minimum severity to include",
                    },
                    "image": {
                        "type": "string",
                        "description": "Filter by image name substring",
                    },
                },
                "required": [],
            },
        ),
        types.Tool(
            name="list_vuln_summary",
            description=(
                "Deduplicated vulnerability summary per image. Splits unfixable CVEs (no fixedVersion) "
                "from fixable ones. Use for policy decisions: unfixable → block-cve-images policy, "
                "fixable → /fix-image. Much smaller than list_vuln_reports — one row per image."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {
                        "type": "string",
                        "description": "K8s namespace, or 'all'",
                    },
                    "severity": {
                        "type": "string",
                        "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "ALL"],
                        "description": "Minimum severity to include (default CRITICAL)",
                    },
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
            name="list_policy_summary",
            description=(
                "Summarise Kyverno PolicyReports by policy. Returns one row per policy with "
                "fail/pass/warn counts and the policy mode (audit/enforce). Use this instead of "
                "list_policy_violations when you only need a health snapshot — it is far smaller."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
        ),
        types.Tool(
            name="list_policy_violations",
            description=(
                "List individual PolicyReport violations from Kyverno. "
                "Returns one record per resource per policy — use for targeted investigation of a "
                "specific policy or namespace. For a cluster-wide health snapshot use list_policy_summary."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {
                        "type": "string",
                        "description": "K8s namespace, or 'all'",
                    },
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
                        "enum": [
                            "EMERGENCY",
                            "ALERT",
                            "CRITICAL",
                            "ERROR",
                            "WARNING",
                            "ALL",
                        ],
                    },
                    "namespace": {"type": "string"},
                    "pod": {"type": "string"},
                    "rule": {
                        "type": "string",
                        "description": "Falco rule name substring",
                    },
                    "hours": {
                        "type": "integer",
                        "description": "Restrict to events in the last N hours",
                    },
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
                    "days": {
                        "type": "integer",
                        "description": "Rolling window in days (default 7, maximum 90)",
                    },
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
                    "namespace": {
                        "type": "string",
                        "description": "Filter to a specific namespace (default all)",
                    },
                    "days": {
                        "type": "integer",
                        "description": "Rolling window in days (default 30, maximum 90)",
                    },
                },
                "required": [],
            },
        ),
        types.Tool(
            name="list_config_audit_summary",
            description=(
                "Config audit findings grouped by KSV check ID with affected workload counts and samples. "
                "Use this instead of list_config_audit when you need a policy gap overview — returns one row "
                "per KSV ID rather than one row per workload. Much smaller output."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "namespace": {
                        "type": "string",
                        "description": "K8s namespace, or 'all'",
                    },
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
                    "namespace": {
                        "type": "string",
                        "description": "K8s namespace, or 'all'",
                    },
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
                    "namespace": {
                        "type": "string",
                        "description": "K8s namespace, or 'all'",
                    },
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
                    "namespace": {
                        "type": "string",
                        "description": "K8s namespace, or 'all'",
                    },
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
                    "namespace": {
                        "type": "string",
                        "description": "K8s namespace, or 'all'",
                    },
                },
                "required": [],
            },
        ),
        types.Tool(
            name="list_image_registry_signals",
            description=(
                "Unique images across all workloads with registry origin and tag info. "
                "Flags images using :latest or no tag. Use for image hygiene policy decisions "
                "(disallow-image-tags, restrict-image-registries) instead of list_workloads — "
                "much smaller output, purpose-built for policy gap analysis."
            ),
            inputSchema={"type": "object", "properties": {}, "required": []},
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
                    "namespace": {
                        "type": "string",
                        "description": "K8s namespace, or 'all'",
                    },
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
                    "namespace": {
                        "type": "string",
                        "description": "K8s namespace, or 'all'",
                    },
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
    return [apply_tool_contract(tool) for tool in tools]


@app.call_tool(validate_input=False)
async def call_tool(name: str, arguments: dict) -> types.CallToolResult:
    handlers = {
        "list_vuln_reports": list_vuln_reports,
        "list_vuln_summary": list_vuln_summary,
        "list_compliance_reports": list_compliance_reports,
        "list_policy_summary": list_policy_summary,
        "list_policy_violations": list_policy_violations,
        "list_runtime_events": list_runtime_events,
        "list_runtime_trends": list_runtime_trends,
        "list_posture_trends": list_posture_trends,
        "list_config_audit_summary": list_config_audit_summary,
        "list_config_audit": list_config_audit,
        "list_exposed_secrets": list_exposed_secrets,
        "list_rbac_issues": list_rbac_issues,
        "list_infra_issues": list_infra_issues,
        "get_pod_status": get_pod_status,
        "list_workloads": list_workloads,
        "list_image_registry_signals": list_image_registry_signals,
        "list_network_exposure": list_network_exposure,
        "list_network_policies": list_network_policies,
    }
    try:
        handler = handlers.get(name)
        if handler is None:
            raise UnknownToolError(name)
        declared = next(tool for tool in await list_tools() if tool.name == name)
        validate_arguments(declared, arguments)
        result = await handler(**arguments)
        return success_result(name, result)
    # The MCP boundary converts adapter failures to non-secret typed errors.
    # Cancellation and process-exit signals do not inherit from Exception.
    except Exception as error:  # noqa: BLE001
        return error_result(name, error)


def main():
    import asyncio

    from mcp.server.stdio import stdio_server

    async def _run():
        async with stdio_server() as (read_stream, write_stream):
            await app.run(
                read_stream, write_stream, app.create_initialization_options()
            )

    asyncio.run(_run())


if __name__ == "__main__":
    main()

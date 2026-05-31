# k8s-sec-stack

An opinionated, fully open-source Kubernetes security reference stack covering posture, vulnerability management, and runtime threat detection — wired together with an MCP server and Claude-powered skills.

## Stack

| Layer | Tool | Data Surface |
|---|---|---|
| Runtime threats | [Falco](https://falco.org) + [falcosidekick](https://github.com/falcosecurity/falcosidekick) | Webhook → event sink |
| Vulnerability management | [trivy-operator](https://github.com/aquasecurity/trivy-operator) | `VulnerabilityReport` / `ConfigAuditReport` CRDs |
| Posture / compliance | [kubescape-operator](https://github.com/kubescape/kubescape-operator) | `ClusterComplianceReport` CRD |
| Policy enforcement | [Kyverno](https://kyverno.io) | `PolicyReport` CRD |
| Agent interface | `mcp-server/` | MCP tools over the above CRDs |

## Layout

```
charts/          Helm umbrella chart — one install to deploy the full stack
mcp-server/      MCP server exposing CRD data as Claude-readable tools
skills/          Claude skill prompts (posture-check, triage-threat, fix-image)
hack/            Local dev bootstrap (kind cluster, helm install)
demo/            Deliberately vulnerable workloads for testing
blog/            Draft posts for the companion blog series
```

## Prerequisites

- A running Kubernetes cluster with `kubectl` pointing at it
- `helm` >= 3.12
- Python >= 3.11 + [`uv`](https://github.com/astral-sh/uv)
- [Claude Code](https://claude.ai/code)

## Quickstart

```bash
# 1. Deploy the full stack into your cluster
./hack/bootstrap.sh

# 2. Deploy vulnerable demo workloads (optional — exercises the full triage workflow)
kubectl apply -f demo/

# 3. Generate local MCP + Claude Code config (run once per machine)
./hack/configure-local.sh

# 4. Start the MCP server
cd mcp-server && uv run k8s-sec-mcp
```

Then restart Claude Code. The skills `/triage-threat`, `/posture-check`, and `/fix-image` are available immediately.

## Blog series

Companion posts publish to [cloudsecburrito.com](https://cloudsecburrito.com).

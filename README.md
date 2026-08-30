# k8s-sec-stack

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

An opinionated, open-source Kubernetes security reference stack covering posture, vulnerability management, and runtime threat detection—wired together with a provider-neutral MCP server and optional agent workflows.

> **Project status: reference implementation and lab.** This is not a production-ready security product, SIEM replacement, or independently audited control plane. Review [the security policy](SECURITY.md) and [known findings](docs/security-review.md) before deploying it outside an isolated test environment.

## Stack

| Layer | Tool | Data Surface |
|---|---|---|
| Runtime threats | [Falco](https://falco.org) + [falcosidekick](https://github.com/falcosecurity/falcosidekick) | Webhook → event sink |
| Vulnerability management | [trivy-operator](https://github.com/aquasecurity/trivy-operator) | `VulnerabilityReport` / `ConfigAuditReport` CRDs |
| Posture / compliance | [kubescape-operator](https://github.com/kubescape/kubescape-operator) | `ClusterComplianceReport` CRD |
| Policy enforcement | [Kyverno](https://kyverno.io) | `PolicyReport` CRD |
| Agent interface | `mcp-server/` | Read-only MCP tools over the above evidence sources |

## Layout

```
charts/          Helm umbrella chart — one install to deploy the full stack
mcp-server/      Provider-neutral MCP server exposing normalized security evidence
skills/          Current client-oriented workflow prompts for triage, posture, remediation, and policy
hack/            Bootstrap scripts (helm install, local MCP config generation)
demo/            Deliberately vulnerable workloads for testing
blog/            Draft posts for the companion blog series
policies/        Generated policy + exception YAML — gitignored, lives locally only
```

## Prerequisites

- A running Kubernetes cluster with `kubectl` pointing at it
- `helm` >= 3.12
- Python >= 3.11 + [`uv`](https://github.com/astral-sh/uv)
- Claude Code for the current automated client setup; other MCP-compatible hosts can launch the stdio server manually

## Quickstart

```bash
# 1. Deploy the full stack into your cluster
./hack/bootstrap.sh

# 2. Deploy vulnerable demo workloads (optional — exercises the full triage workflow)
kubectl apply -f demo/

# 3. Generate authenticated local MCP settings (run once per install)
./hack/configure-local.sh

# 4. In a separate terminal, open the local-only sink access path
kubectl -n security port-forward service/mcp-event-sink 8080:8080

# 5. Restart your MCP client from the project directory
```

The default chart exposes neither the event sink nor falcosidekick outside the
cluster. `charts/k8s-sec-stack/values-local-dev.yaml` retains explicit NodePort
settings for isolated disposable labs, but the port-forward path above is preferred.
The generated local MCP configuration contains a query-only bearer token and must
not be committed or shared.

The MCP server starts automatically when Claude Code loads. Skills are available immediately.

> **Note:** scan data takes ~5 minutes to populate after a fresh install. If `/kyverno-suggest` or `/posture-check` return nothing, wait a few minutes and try again — trivy-operator and kubescape run scan jobs in the background before results appear in CRDs.

| Skill | What it does |
|---|---|
| `/triage-threat` | Full kill chain triage of a Falco alert |
| `/posture-check` | Compliance scores + Kyverno violation audit |
| `/fix-image` | Image remediation from VulnerabilityReport data |
| `/kyverno-suggest` | Survey cluster findings, map to Kyverno policies |
| `/kyverno-create-policy` | Generate annotated ClusterPolicy YAML |
| `/kyverno-create-exception` | Generate scoped PolicyException with justification |

## Blog series

Companion posts publish to [cloudsecburrito.com](https://cloudsecburrito.com).

## Development disclosure

This project has been substantially developed with AI coding agents, including Claude Code and OpenAI Codex. AI assistance has included code generation, refactoring, documentation, review, and test scaffolding.

Project maintainer Matt Brown directs the architecture, manually tests and validates the documented lab workflows, reviews changes, and remains responsible for what is merged and released. AI assistance is not an independent security audit. See [CONTRIBUTING.md](CONTRIBUTING.md) for the contribution and validation policy.

## License

Licensed under the [Apache License 2.0](LICENSE). Copyright 2026 k8s-sec-stack contributors. Third-party dependencies remain subject to their own licenses.

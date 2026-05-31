# k8s-sec-stack — Agent Instructions

## What this repo is

An OSS Kubernetes security reference stack. Four tools (Falco, trivy-operator, kubescape-operator, Kyverno) deployed via a single Helm umbrella chart, surfaced to LLM agents through an MCP server.

## MCP tools available

**Trivy**
| Tool | Source | Filters |
|---|---|---|
| `list_vuln_reports` | VulnerabilityReport CRDs | namespace, severity, image |
| `list_config_audit` | ConfigAuditReport + ClusterConfigAuditReport CRDs | namespace, severity |
| `list_exposed_secrets` | ExposedSecretReport CRDs | namespace |
| `list_rbac_issues` | RBACAssessmentReport + ClusterRBACAssessmentReport CRDs | namespace, severity |
| `list_infra_issues` | InfraAssessmentReport + ClusterInfraAssessmentReport CRDs | severity |

**Posture / Policy**
| Tool | Source | Filters |
|---|---|---|
| `list_compliance_reports` | kubescape ClusterComplianceReport CRDs | framework |
| `list_policy_violations` | Kyverno PolicyReport CRDs | namespace, result |

**Runtime**
| Tool | Source | Filters |
|---|---|---|
| `list_runtime_events` | falcosidekick → mcp-event-sink SQLite | priority, namespace, pod, rule, hours |
| `list_runtime_trends` | mcp-event-sink /events/trends | days (default 7) |
| `list_posture_trends` | mcp-event-sink /posture/trends (daily snapshot) | tool, namespace, days (default 30) |

**Kubernetes context**
| Tool | Source | Filters |
|---|---|---|
| `list_workloads` | Deployments, DaemonSets, standalone Pods | namespace |
| `list_network_exposure` | Services + Ingresses | namespace |
| `list_network_policies` | NetworkPolicy CRDs — flags unprotected namespaces | namespace |

## Common join key

`namespace` + `pod label` links runtime events ↔ VulnerabilityReports. Always use these as the correlation axis when triaging a Falco alert.

## Skills

- `/triage-threat` — full kill chain triage of a Falco alert: runtime event → workload context → CVEs → misconfig → network exposure → lateral movement → RBAC blast radius → Threat Score + MONITOR/ISOLATE/KILL
- `/posture-check` — compliance framework scores (kubescape) + Kyverno policy violation audit
- `/fix-image` — image remediation from VulnerabilityReport data
- `/kyverno-suggest` — survey kubescape + trivy findings (or take user intent directly), map to Kyverno PSS library policies, and output a numbered selection list for /kyverno-create-policy
- `/kyverno-create-policy` — generate annotated ClusterPolicy YAML from a policy name, intent description, or selection from /kyverno-suggest; handles mutation complements and file paths
- `/kyverno-create-exception` — generate a namespace-scoped PolicyException for a workload with a legitimate bypass need; requires justification, scopes as tightly as possible

## Layout

```
charts/          Helm umbrella — one install
mcp-server/      Python MCP server (k8s_sec_mcp package)
skills/          Skill prompt files
hack/            bootstrap.sh — kind cluster + helm install
demo/            Vulnerable workloads for testing
blog/            Draft blog posts
```

## Dev workflow

```bash
./hack/bootstrap.sh          # spin up kind cluster + deploy stack
kubectl apply -f demo/       # deploy vulnerable workloads
cd mcp-server && uv run k8s-sec-mcp   # start MCP server
```

## Blog series context

Each significant feature addition should have a companion blog draft in `blog/`. Posts target cloudsecburrito.com. Scrub all identifiers before publishing.

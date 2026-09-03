# Architecture

Last verified against repository: 2026-09-02 (`codex/phase2-mcp-contract-corrections`, maintainer-reviewed and CI-verified)

## System context

`k8s-sec-stack` collects evidence from four Kubernetes security projects and exposes a normalized, read-only MCP interface for agent-assisted analysis.

```mermaid
flowchart LR
    subgraph Cluster["Kubernetes cluster"]
        Falco["Falco"] --> Sidekick["falcosidekick"]
        Sidekick --> Sink["Event sink\nHTTP + SQLite"]
        Trivy["trivy-operator"] --> CRDs["Security CRDs"]
        Kubescape["kubescape-operator"] --> CRDs
        Kyverno["Kyverno"] --> CRDs
        Snapshot["Posture snapshot CronJob"] --> CRDs
        Snapshot --> Sink
        K8sAPI["Kubernetes API"] --> CRDs
    end

    Client["MCP client / agent"] -->|"stdio"| MCP["k8s-sec-mcp"]
    MCP -->|"kubeconfig or in-cluster identity"| K8sAPI
    MCP -->|"HTTP"| Sink
```

## Components

### Helm umbrella chart

`charts/k8s-sec-stack/` pins upstream chart versions and configures:

- Falco with modern eBPF and JSON HTTP output;
- falcosidekick forwarding Falco payloads to the event sink;
- trivy-operator CRD scanners for vulnerabilities, configuration, RBAC, infrastructure, secrets, and SBOMs;
- kubescape continuous scanning;
- Kyverno admission, background, cleanup, and report controllers;
- the project-owned event sink and posture-snapshot CronJob.

The default chart uses internal `ClusterIP` services. Optional NodePort exposure is isolated in `values-local-dev.yaml` and is intended only for disposable local labs.

### Event sink

The event sink is a project-owned Python application under `event-sink/` with a digest-pinned Python base image. It provides:

- `POST /events` for validated Falco payloads;
- `GET /events` for filtered normalized events (or redacted raw events when explicitly enabled);
- `GET /events/trends` for aggregate runtime trends;
- `POST /posture/snapshot` for daily metric batches;
- `GET /posture/trends` for historical posture metrics;
- `GET /healthz` for liveness and readiness.

All other routes and methods are rejected. Ingest and query routes use separate bearer tokens by default. Body size, snapshot batch size, filter length, time windows, result counts, response bytes, concurrent requests, and socket time are bounded. Event and posture schemas are validated before SQLite writes.

SQLite data is stored on a 1 GiB ReadWriteOnce PVC. Retention is chart-configurable from 1–365 days. Raw Falco bodies are discarded by default; operators may opt in and configure field redaction. The application remains a single process with an in-process database lock, so the RWO volume and SQLite design still constrain availability and scale.

Startup requires distinct ingest and query credentials. Upgrades from schema
version 0 irreversibly clear legacy raw Falco bodies before serving queries;
normalized event fields and posture history remain. Credential rotation requires
a coordinated restart because Kubernetes Secret-backed environment variables do
not update in running processes. See `docs/event-sink-operations.md`.

### Posture snapshot CronJob

The CronJob reads selected CRDs with a cluster-scoped, read-only service account, computes counts/scores, and posts them to the event sink daily. It is already configured with a non-root container security context. Its upstream API parsing must be covered by fixtures because CRD shapes can change across operator versions.

### MCP server

`mcp-server/` is a Python stdio MCP server. Tool handlers use either:

- the Kubernetes Python client, loading in-cluster configuration first and local kubeconfig second; or
- authenticated HTTP requests to the event sink configured by `FALCO_SINK_URL` and `FALCO_SINK_TOKEN`.

Phase 2A keeps the complete legacy JSON value in MCP text content and returns the
same value in a versioned structured envelope with bounded, typed errors, static
source provenance, response-generation time, and explicit freshness state.
Success responses are never silently truncated: values that cannot fit the
configured record, string, or complete dual-representation byte budget return a
visible `response_too_large` tool error. `list_policy_summary` and
`list_image_registry_signals` cannot currently narrow or paginate an oversized
result; operators may raise the bounded MCP limits and restart the server while
later Phase 2 work adds retrieval controls. Unadvertised tool names are not
echoed.

The envelope and top-level array/object shapes are schema-enforced. Nested legacy
fields are intentionally open until later Phase 2 domain models and CRD fixtures
exist. The tools remain logically read-only, but their effective Kubernetes
privilege is whatever the selected identity permits. See
`docs/mcp-contract-v1.md`.

### Agent workflow skills

Files under `skills/` coordinate MCP tool calls. The principal correlation workflow is:

1. identify a Falco event;
2. verify whether the pod still exists;
3. resolve workload and image context;
4. join vulnerability, configuration, policy, network, and RBAC evidence;
5. currently calculate a bounded threat score and recommend a response.

That final step is a documented design debt. The target workflow returns observed facts, deterministic correlations, missing context, confidence, investigation steps, and possible containment options requiring human approval. It must not infer that an image CVE caused an observed process event.

The current correlation axis is a loose combination of namespace, pod/workload context, and image strings. Exact pod names are ephemeral, tags can move, and a direct owner can be only an intermediate ReplicaSet. The target correlation record includes pod UID, container ID, image digest, namespace, full owner chain, evidence timestamps/generation, source/scanner versions, and freshness.

## Trust boundaries

| Boundary | Data crossing it | Current control | Required direction |
|---|---|---|---|
| Falco/falcosidekick → event sink | runtime telemetry | ClusterIP, producer NetworkPolicy, ingest bearer token, schema/size limits | Calico allow/deny boundary verified 2026-08-31; use TLS or mTLS if traffic crosses an untrusted network |
| Snapshot CronJob → event sink | aggregate security posture | ClusterIP, producer NetworkPolicy, ingest bearer token, route/schema/batch limits | Calico allow/deny boundary verified 2026-08-31 |
| MCP server → Kubernetes API | cluster inventory and security findings | caller kubeconfig or pod identity | documented least-privilege read-only role |
| MCP server → event sink | normalized/aggregate runtime evidence | query bearer token plus port-forward or explicitly labeled in-cluster pod | add TLS or a reviewed proxy for remote access; do not expose the plain HTTP service directly |
| MCP server → agent/model | potentially sensitive cluster evidence | stdio session | minimization, redaction, limits, and operator awareness |
| Repository → published articles | commands, screenshots, findings | manual scrubbing | claim matrix and explicit sanitization gate |

## Provider-neutral target

Provider neutrality applies in three dimensions:

- **MCP client:** core installation should describe a generic stdio server declaration; Claude, Codex, and other clients become separate examples.
- **Kubernetes environment:** service discovery must derive from the Helm release namespace, and local-cluster conveniences must not be required by the core chart.
- **LLM workflow:** tool schemas and JSON results are the contract; reusable skills should avoid assumptions about one vendor's proprietary commands.

The target MCP design should separate:

1. transport and server registration;
2. Kubernetes/security data adapters;
3. stable domain models and schemas;
4. workflow prompts/evaluations.

Provider-neutral workflows should live separately from client packaging. A likely target layout is `workflows/` for investigation procedures plus `clients/<host>/` for Codex, Claude Code, VS Code, or other host-specific registration and commands. Reusable MCP prompts can be evaluated later without making them a prerequisite for core tool interoperability.

This makes parser and transport changes testable without changing every skill.

## Key extension points

- Add new evidence sources behind adapters that return stable internal models.
- Add a correlation layer that uses workload UID, owner reference, labels, and image digest.
- Add pagination/response budgets without changing semantic tool names.
- Return declared structured content and schemas while keeping a compatibility text representation during migration.
- Support an in-cluster MCP deployment or secure API gateway while retaining stdio for local use.
- Export normalized evidence to external systems without coupling core collection to one SIEM or agent.

## Known architecture constraints

- the packaged event-sink image has not yet been published, so the chart retains a tag fallback until a release digest exists;
- bearer tokens protect route classes but plain in-cluster HTTP does not provide transport confidentiality;
- NetworkPolicy behavior depends on a policy-enforcing CNI; Calico v3.25.0 was verified in one Kubernetes v1.35.6 lab topology, not across all supported CNIs;
- one replica and one RWO SQLite volume limit availability and scale;
- raw CRD dictionaries flow directly into tool-specific parsers with no versioned domain model;
- MCP results now have a versioned envelope and fail-visible response limits, but no pagination or field-level tool data schemas; `list_policy_summary` and `list_image_registry_signals` also have no narrowing filters, so their only current oversized-result workaround is an operator-approved bounded limit increase and MCP restart;
- untrusted Kubernetes fields and Falco output still cross into model context; the envelope documents limits and data-versus-instruction handling, but end-to-end injection evaluations remain pending;
- client-specific skills are currently presented adjacent to the MCP layer, obscuring the host/client/model boundary.

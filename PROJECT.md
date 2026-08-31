# k8s-sec-stack project brief

Last updated: 2026-08-30

## Mission

Build an open-source Kubernetes security reference stack that correlates posture, vulnerability, policy, network, RBAC, and runtime evidence and exposes that evidence safely to LLM agents through the Model Context Protocol (MCP).

The project is licensed under Apache-2.0. It is explicitly labeled as a reference implementation and lab rather than a production-ready or independently audited security product.

The project should be useful as both:

- a reproducible learning and demonstration environment; and
- a credible reference architecture that makes the boundary between local-demo defaults and production requirements explicit.

## Product scope

The current stack installs Falco, falcosidekick, trivy-operator, kubescape-operator, and Kyverno with one Helm umbrella chart. A Python MCP server reads Kubernetes CRDs and an SQLite-backed event sink to provide investigation and posture tools. Repository skills orchestrate those tools into threat triage, posture review, image remediation, and Kyverno policy workflows.

In scope:

- read-only security evidence collection and correlation;
- provider-neutral MCP tools and reusable agent workflow instructions;
- secure, configurable Helm deployment;
- deterministic local and CI test paths;
- transparent limitations, threat model, and operational guidance;
- companion articles whose claims are reproducible from repository tags.

Out of scope unless deliberately added to the roadmap:

- replacing a SIEM, vulnerability platform, or incident-response system;
- autonomous destructive response in a cluster;
- promising production readiness without documented hardening and scale testing;
- hiding required external systems such as registries, signing services, or identity providers.

## Design principles

1. **Evidence before action.** Tools report observed cluster state; skills must not invent findings.
2. **Read-only by default.** The MCP surface must not mutate the cluster without a separately designed and authorized capability.
3. **Least privilege.** Every in-cluster component and local client gets only the access its function requires.
4. **Provider neutrality.** MCP schemas and core workflows must work with any compliant client and any conformant Kubernetes cluster.
5. **Secure defaults, explicit demo overrides.** Public ports, unauthenticated endpoints, and reduced replicas belong in opt-in development profiles.
6. **Reproducibility.** Dependencies, fixtures, test commands, and article demonstrations should be pinned and repeatable.
7. **Honest documentation.** Clearly label implemented behavior, planned behavior, assumptions, and known limitations.
8. **Deterministic correlation.** Code establishes identity and freshness matches; the model explains assembled evidence and uncertainty.
9. **Human authority.** Containment is presented as an option requiring approval, not an automatically selected or executed outcome.
10. **Transparent development.** Credit material AI assistance and record the human review and manual validation behind a release.

## Current baseline

Implemented in `main` at commit `cb89914` when this brief was created:

- Helm umbrella chart with five upstream chart dependencies.
- SQLite event sink with Falco event retention and trend endpoints.
- Daily posture snapshots for Trivy, Kubescape, and Kyverno.
- MCP tools for vulnerabilities, configuration audits, secrets, RBAC, infrastructure, compliance, policies, workload context, network context, runtime events, and trends.
- Six workflow skills for triage, posture, remediation, and Kyverno policy work.
- Demo workload fixtures and a Kyverno CLI test manifest.

Known baseline constraints:

- deployment values contain hard-coded `security` namespace service addresses;
- the event sink and falcosidekick are exposed with NodePort defaults;
- the event sink has no authentication and stores raw Falco payloads;
- MCP Kubernetes access inherits the invoking kubeconfig rather than a documented least-privilege identity;
- no automated Python parser, MCP contract, Helm, or end-to-end CI suite is committed;
- Kyverno tests reference generated policy files that are intentionally gitignored;
- MCP tool results are JSON encoded into text content without declared structured-output schemas;
- the triage skill maps a heuristic score to MONITOR/ISOLATE/KILL despite insufficient causal evidence;
- stable correlation identifiers and freshness metadata are not preserved end-to-end;
- local setup and README language are Claude-specific even though MCP is intended to be client-neutral;
- article sources live in a separate blog repository and are not included in this clone.

Phase 1 hardening implemented on `codex/phase1-event-sink-hardening` and pending maintainer review changes that baseline as follows: the sink and falcosidekick default to `ClusterIP`; release-namespace coupling is removed from their routes; ingest and query tokens are separated; sink inputs, queries, concurrency, and responses are bounded; normalized-only retention is the default; and the sink pod and network boundary are restricted. The project image is publicly available from GHCR and the chart selects its scanned multi-platform manifest by digest. Live CNI connectivity and Pod Security admission verification remain release gates.

The event-sink authentication boundary fails closed when credentials are missing or
identical. Schema version 0 upgrades clear legacy raw Falco bodies before queries
are served. Image publication uses public GHCR with a blocking Trivy scan, SBOM,
provenance, and a digest-pinned Helm reference.

See `docs/security-review.md` for risk detail and `docs/roadmap.md` for sequencing.

## Workstreams

Use one Codex task per workstream so that discussions stay focused while all tasks share these files:

| Task | Purpose | Durable output |
|---|---|---|
| Project setup and roadmap | Maintain shared decisions and sequencing | `AGENTS.md`, `PROJECT.md`, `docs/` |
| Repository hardening | Fix trust-boundary, deployment, and supply-chain risks | Helm/MCP changes and `docs/security-review.md` |
| Provider-neutral MCP support | Remove client-specific setup and define stable contracts | MCP adapters, setup docs, contract tests |
| Testing and evaluation | Establish repeatable correctness and quality gates | fixtures, automated tests, CI, eval reports |
| Part 1 article revision | Align architecture article with trust/correlation model | sanitized draft and claim matrix |
| Part 2 article revision | Align deployment article with reproducible proof | sanitized draft and evaluation evidence |
| Future Part 3 | Cover hardening and operationalization after implementation | scoped draft only after release evidence exists |

## Definition of done for the next milestone

The foundation milestone is complete when:

- Apache-2.0 licensing metadata remains consistent across the repository;
- the README continues to label the current maturity and intended use prominently;
- the event sink is internal by default, authenticated where it crosses a trust boundary, input-bounded, and hardened as a pod;
- chart service discovery works in any Helm release namespace;
- MCP setup is documented for a generic stdio client, with client-specific examples isolated;
- a least-privilege access model is documented and testable;
- Python unit tests cover CRD parsing and event-sink validation;
- correlation code preserves stable identity, provenance, and freshness and returns unmatched evidence explicitly;
- triage output reports facts, uncertainty, investigation steps, and human-approved containment options instead of a KILL score;
- Helm rendering/lint and MCP contract tests run in CI;
- an end-to-end demo produces expected correlation results from a fresh supported cluster;
- article claims link to commands, fixtures, outputs, and a repository tag.

## Decision log

| Date | Decision | Rationale |
|---|---|---|
| 2026-08-30 | Use this repository as the durable project source of truth. | Separate Codex tasks share files, not complete conversation history. |
| 2026-08-30 | Separate repository hardening, provider-neutral MCP, testing/evaluation, and article work into focused tasks. | These tracks can progress independently while using one roadmap. |
| 2026-08-30 | Keep documentation changes local until reviewed. | No commit or push was authorized during project bootstrap. |
| 2026-08-30 | Treat licensing as a release blocker rather than choosing a license automatically. | License selection is a maintainer/legal decision; repository code currently has no license. |
| 2026-08-30 | Replace heuristic threat scoring with evidence and confidence. | Current data cannot establish CVE causality or justify automatic KILL recommendations. |
| 2026-08-30 | License the project under Apache-2.0. | Permissive reuse plus an explicit patent grant fits a Kubernetes infrastructure reference project. |
| 2026-08-30 | Disclose substantial Claude Code and OpenAI Codex assistance while crediting maintainer validation. | Provenance should be transparent without treating an AI system as a copyright holder or independent auditor. |
| 2026-08-30 | Separate event-sink ingest and query credentials and discard raw Falco bodies by default. | Producers do not need read access, query clients do not need write access, and normalized evidence reduces sensitive-data retention. |

Add consequential decisions here or in a dedicated ADR under `docs/` when implementation begins.

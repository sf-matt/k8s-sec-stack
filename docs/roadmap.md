# Roadmap

Last updated: 2026-08-30

This roadmap orders work by risk and dependency. Status values are `planned`, `in progress`, `blocked`, or `complete`; all items begin as planned.

## Phase 0 — Durable project baseline

Goal: make decisions discoverable across Codex tasks and establish an honest baseline.

| Deliverable | Status | Exit evidence |
|---|---|---|
| Project brief, architecture, security review, roadmap, and article plan | complete | Files exist in repository working tree and match current code |
| Maintainer selects and adds a project license | complete | Apache-2.0 `LICENSE`, `NOTICE`, package/chart metadata, and contribution terms added locally |
| Label current repository as a lab/reference implementation | complete | README and `SECURITY.md` contain maturity, audit, and production-use warnings |
| Disclose AI-assisted development and human validation | complete | README, `CONTRIBUTING.md`, and `SECURITY.md` credit tools and maintainer testing/review responsibility |
| Review and commit durable documentation | planned | Reviewed commit on a feature branch or `main`, per maintainer choice |
| Create focused Codex tasks for each workstream | planned | Tasks named in `PROJECT.md` are visible in this project |

## Phase 1 — Contain the local-demo attack surface

Goal: close the highest-risk trust-boundary gaps before expanding features.

| Deliverable | Security link | Status | Exit evidence |
|---|---|---|---|
| Default event sink and falcosidekick services to ClusterIP | SEC-001, SEC-009 | complete | Default full render has no NodePort; `values-local-dev.yaml` retains explicit optional access |
| Remove hard-coded release namespace addresses | SEC-006 | complete | Isolated tests and full renders pass for `security` and `alternate-security` |
| Harden event-sink pod and pin/package its image | SEC-002 | complete | Public GHCR build/scan/SBOM/provenance passed, chart pins its manifest, and live Pod Security Restricted admission passed |
| Add NetworkPolicies for the security namespace flows | SEC-001 | complete | Render tests plus live Calico allowed, unlabeled-denied, and cross-namespace-denied probes passed |
| Bound/validate sink routes, payloads, and queries | SEC-003 | complete | HTTP boundary suite covers auth, allowlists, schemas, size/range limits, and response bounds |
| Make raw payload retention and retention days configurable | SEC-004 | complete | normalized-only default, opt-in redaction, and purge tests pass |

Recommended implementation order: service defaults and namespace templating, then pod image/security context, then API validation/auth and NetworkPolicy. Keep each change small enough to review independently.

Implementation and lab evidence (pending maintainer review): `python3 -m unittest discover -s event-sink/tests -v`, `python3 -m unittest discover -s tests/helm -v`, `helm lint charts/k8s-sec-stack`, full `helm template` renders in two namespaces, public workflow run `33358389880`, live Calico policy probes, live auth checks, and Pod Security Restricted admission. Phase 1 is complete in the tested lab topology.

## Phase 2 — Provider-neutral MCP foundation

Goal: support any compliant MCP client without coupling the core to Claude Code or one cluster topology.

| Deliverable | Status | Exit evidence |
|---|---|---|
| Define stable tool schemas, error envelope, limits, and compatibility policy | planned | versioned contract document and tests |
| Separate domain models from Kubernetes CRD adapters and return structured content | planned | fixture tests cover supported CRD versions and schemas |
| Preserve pod UID, container ID, image digest, full owner chain, provenance, and freshness | planned | deterministic correlation tests return matched/unmatched evidence correctly |
| Publish generic stdio configuration and isolate client examples | planned | clean setup succeeds with generic MCP inspector plus documented clients |
| Add a secure runtime-event access strategy without required NodePort | planned | tested port-forward/proxy or in-cluster option |
| Document/install MCP least-privilege RBAC and namespace scope | planned | all tools tested with restricted identity |
| Replace provider-specific wording in README and skills where semantics are generic | planned | terminology review passes; client-specific notes remain accurate |
| Split provider-neutral workflows from client-specific packaging | planned | core workflow plus at least two host examples share the same contract |
| Replace threat score/KILL mapping with evidence, confidence, and approved options | planned | ambiguity and human-approval evaluations pass |

Compatibility rule: add fields without breaking current consumers; announce tool removal or semantic changes and cover them with contract fixtures.

## Phase 3 — Testing and evaluation

Goal: measure correctness, safety, and usefulness rather than relying on demonstrations alone.

### Automated tests

- Python unit tests for each CRD parser, severity filter, image correlation, and error path.
- Event-sink unit/integration tests for route allowlists, authentication, schema validation, retention, redaction, and query bounds.
- MCP list/call contract tests, including unknown tools and unavailable data sources.
- Helm lint and golden render tests for default, local-dev, disabled-component, and alternate-namespace configurations.
- Kyverno CLI tests whose required policy fixtures exist in a clean clone.
- kind smoke test: install, deploy demo, wait for reports, call representative MCP tools, and uninstall cleanly.

### Agent evaluations

Build sanitized, deterministic cases for:

- active versus historical Falco events;
- same namespace with multiple similar workloads;
- vulnerable image with and without a fixed version;
- externally exposed versus network-isolated workload;
- high versus low RBAC blast radius;
- missing, forbidden, stale, malformed, and conflicting data sources;
- prompt-injection-like strings inside event fields or resource labels.

Score factual grounding, correlation accuracy, confidence calibration, citation to tool evidence, abstention on missing evidence, resistance to untrusted instructions, token/response size, and repeatability. Safety is a gate: an evaluation must fail if the workflow invents evidence, treats data as an instruction, asserts CVE causality without proof, or presents containment as already selected/executed.

### CI gates

| Gate | Pull requests | Scheduled/release |
|---|---|---|
| formatting/static checks/unit tests | required | required |
| Helm and Kyverno tests | required | required |
| dependency/image/secret scanning | required | required |
| kind end-to-end | targeted or required after stabilization | required |
| agent evaluation suite | smoke subset | full suite |

## Phase 4 — Operational readiness

Goal: make limitations and production choices explicit after the secure foundation is measured.

- add health/readiness and source-freshness indicators;
- define backup, migration, and recovery for event history;
- add observability for ingestion failures, dropped payloads, database size, and query latency;
- test upgrade/uninstall behavior and CRD ownership boundaries;
- publish resource-sizing guidance from measured workloads;
- decide whether SQLite remains the reference backend or becomes one adapter;
- produce a threat model and supported deployment matrix;
- tag a release candidate only after the security review closure evidence is linked.

## Article delivery track

Articles follow implementation evidence, not the reverse:

1. revise Part 1 around architecture, trust boundaries, identity/freshness, provider-neutral MCP, and prototype status;
2. revise Part 2 around a reproducible lab, safe access, actual MCP calls, and one deterministic end-to-end investigation;
3. write Part 3 after hardening/operational work is implemented and measured.

See `docs/article-revision-plan.md` for claim gates and missing inputs.

## Deferred ideas

These are valuable but should not displace Phases 1–3:

- write-capable remediation tools;
- automated KILL/ISOLATE execution;
- multi-cluster aggregation;
- external SIEM/ticketing integrations;
- pluggable long-term event stores;
- policy-generation enforcement automation.

Each requires a separate threat model and explicit authorization design.

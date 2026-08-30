# Security review

Review date: 2026-08-30

Scope: static review of committed Helm, Python, shell, demo, skill, and test files at `main` commit `cb89914`

Status: initial review, not a penetration test or production-readiness certification

## Executive summary

The project has a sound read-only analysis concept and uses least-privilege RBAC for the posture snapshot job, but the deployment currently assumes a trusted local environment. The most important technical issue is the unauthenticated NodePort event sink: it accepts telemetry and returns raw Falco records without an authorization boundary. Apache-2.0 licensing and prominent lab/reference labeling were added during this review. Production use should wait until exposure, input validation, pod hardening, MCP identity, correlation, and automated test gaps are addressed.

No known vulnerability claims about the pinned third-party versions are made here; dependency advisories and image contents require a separate, time-bound scan.

## Resolved project blocker — project license and maturity label

- Status: resolved locally on 2026-08-30; pending commit/review.
- Resolution: added the canonical Apache License 2.0 text, a `NOTICE`, package/chart license metadata, contribution terms, a security policy, and prominent reference-implementation labeling.
- Development provenance: README, contribution, and security documentation disclose substantial Claude Code and OpenAI Codex assistance while assigning architecture direction, manual workflow testing, validation, merge, and release responsibility to the maintainer.
- Follow-up: audit third-party dependency notices before distributing bundled binaries or images; keep article license claims tied to a repository commit containing these files.

## Findings

### SEC-001 — Unauthenticated event ingestion and retrieval over NodePort

- Severity: High
- Evidence: `event-sink-service.yaml` sets `type: NodePort`; the HTTP handler authenticates neither POST nor GET routes; `.mcp.json.example` connects through a node IP.
- Impact: a party with node-port reachability can read raw runtime events, poison incident history/posture data, and consume disk or service capacity. Falco output can contain sensitive process and workload context.
- Remediation:
  1. make the service `ClusterIP` by default;
  2. provide an explicit local-development exposure profile;
  3. require authenticated ingestion/query whenever traffic crosses the pod/namespace trust boundary;
  4. apply default-deny and narrowly scoped NetworkPolicies;
  5. separate ingestion and query authorization if the API remains networked.
- Verification: unauthenticated requests fail; only falcosidekick, the snapshot job, and the chosen MCP access path can reach their required routes.

### SEC-002 — Event sink container is not hardened and uses a mutable runtime image

- Severity: High
- Evidence: the event-sink Deployment has no pod/container `securityContext`; it uses `python:3.12-slim` without a digest and executes code mounted from a ConfigMap.
- Impact: the sink may run as root, has a writable filesystem beyond the data need, and can change when the image tag moves. Compromise affects retained telemetry and the namespace network.
- Remediation: build a minimal project-owned image, pin it by digest for releases, run as non-root, drop all capabilities, disable privilege escalation, use a read-only root filesystem, set seccomp, disable service-account token mounting, and grant write access only to the data volume.
- Verification: Pod Security Restricted checks pass and image provenance is reproducible.

### SEC-003 — Unbounded request/query inputs permit denial of service

- Severity: Medium
- Evidence: `Content-Length` is trusted without a maximum; `limit`, `hours`, and `days` are parsed directly with no range checks; all non-`/posture/snapshot` POST paths are treated as event ingestion; the server uses single-threaded `HTTPServer`.
- Impact: oversized bodies, extreme query ranges/limits, slow clients, or malformed numeric values can exhaust memory, block request handling, or produce handler failures.
- Remediation: allowlist methods/routes, cap body and result sizes, validate schemas and numeric ranges, set socket/request timeouts, return structured errors, and add load/abuse tests. Consider a maintained web framework/server once the sink is packaged.
- Verification: boundary tests demonstrate 4xx responses and bounded resource use.

### SEC-004 — Raw security telemetry retention lacks minimization controls

- Severity: Medium
- Evidence: complete Falco events are serialized into the `raw` SQLite column; retention is hard-coded to 30 days; the API returns those records.
- Impact: command arguments, paths, workload identifiers, or other operational data may be retained and sent to an LLM when a smaller normalized record would suffice.
- Remediation: define a data classification, allow configurable retention, store normalized fields by default, explicitly opt into raw payload retention, redact configured fields, and document PVC backup/encryption expectations.
- Verification: fixtures containing representative secrets are redacted or excluded and retention settings are chart-configurable.

### SEC-005 — MCP server inherits broad caller Kubernetes privileges

- Severity: Medium
- Evidence: tool modules call `load_kube_config()` outside the cluster and perform cluster-wide reads; no MCP-specific RBAC manifest or access matrix is committed.
- Impact: the nominally read-only tool surface can expose everything readable by a developer's current context, including namespaces outside the intended scope. A compromised MCP process also possesses that access context.
- Remediation: publish an exact API/resource/verb matrix, add an optional least-privilege service account and kubeconfig workflow, support namespace allowlists, confirm tools never invoke mutation APIs, and document current-context checks.
- Verification: contract tests run under the restricted identity and forbidden resources return clear errors.

### SEC-006 — Namespace coupling can redirect or break telemetry

- Severity: Medium
- Evidence: Falco and falcosidekick URLs in `values.yaml` include the literal namespace `security`, while Helm supports an arbitrary release namespace.
- Impact: installing into another namespace breaks the intended pipeline and can send traffic to an unexpected same-named service if one exists in `security`.
- Remediation: template project-owned service addresses and expose supported overrides; add Helm render tests for multiple namespaces.
- Verification: an install under a non-default namespace produces no references to `.security.svc` unless explicitly configured.

### SEC-007 — Dependency and build reproduction are incomplete

- Severity: Medium
- Evidence: Python dependencies use open lower bounds, `uv.lock` is gitignored, container images are tag-only, and Helm dependency archives/lock are not committed.
- Impact: two installations can resolve different code, complicating vulnerability response, testing, and article reproducibility.
- Remediation: choose and document a dependency update policy, commit appropriate lock metadata, pin release images by digest, automate SBOM/advisory scanning, and use a controlled dependency-update process.
- Verification: clean builds resolve identical artifacts and CI records scan results.

### SEC-008 — Automated security regression coverage is insufficient

- Severity: Medium
- Evidence: no CI workflow or Python test suite is committed. The Kyverno test manifest references policy YAML under `policies/`, while that directory's generated content is gitignored.
- Impact: parser drift, route-validation regressions, unsafe chart defaults, and broken policy tests can merge undetected.
- Remediation: add fixture-based parser tests, MCP schema/dispatch tests, event-sink validation tests, Helm lint/render tests, executable Kyverno fixtures, and a minimal kind end-to-end job.
- Verification: all suites run from a clean clone in CI.

### SEC-009 — falcosidekick NodePort expands the network surface

- Severity: Medium
- Evidence: `falcosidekick.service.type` is `NodePort` with a fixed port in the default values.
- Impact: a service intended for internal routing is exposed on every node, increasing discovery and attack surface and creating port conflicts.
- Remediation: default to `ClusterIP`; move NodePort settings into local-development values only; confirm whether any external consumer is genuinely required.
- Verification: default Helm render contains no NodePort services.

### SEC-010 — Broad exception handling obscures partial posture failures

- Severity: Low
- Evidence: snapshot collectors catch broad exceptions and continue; policy mode discovery also falls back to unknown on any exception.
- Impact: consumers may interpret incomplete results as healthy/empty data rather than collection failure.
- Remediation: return explicit source status and error metadata, distinguish forbidden/not-found/version errors, expose health metrics, and fail the snapshot when required sources are unavailable according to policy.
- Verification: missing CRDs and RBAC denial fixtures produce visible degraded status.

### SEC-011 — Untrusted cluster content is passed into model context without an injection contract

- Severity: Medium
- Evidence: Kubernetes labels, report messages, Falco output, and raw event fields are serialized into MCP text responses; workflows do not explicitly instruct every consumer to treat embedded content as data rather than instructions.
- Impact: an attacker able to control workload metadata, process arguments, image labels, report messages, or event ingestion could attempt indirect prompt injection, distort analysis, or encourage unsafe actions.
- Remediation: return typed/structured fields, minimize raw text, mark provenance, sanitize control characters/oversized values, add workflow rules that tool data is never executable instruction, and create adversarial fixtures. Keep all mutation/containment behind explicit human approval.
- Verification: evaluation cases containing instruction-like resource names and event output do not alter workflow control or cause unsupported actions.

### SEC-012 — Heuristic threat score overstates evidence and recommends KILL

- Severity: Medium
- Evidence: `skills/triage-threat.md` computes `(Runtime × 2 + Vuln Amp + Exposure)` and caps the result at 10, then maps 8–10 to KILL. The uncapped maximum is 20, so materially different cases collapse into the same top band.
- Impact: the score implies precision and causal linkage the available data does not support. A CVE in an image does not prove that the observed process exercised the affected component; a KILL recommendation may create operational harm even though the skill does not execute it.
- Remediation: replace the score/action mapping with observed facts, correlated evidence, explicit unmatched/missing context, confidence level, recommended investigation, and containment options requiring human approval. Remove autonomy as an assumed product destination.
- Verification: evaluation fixtures with ambiguous CVEs or incomplete identity never produce a definitive causal claim or automatic containment directive.

### SEC-013 — Correlation identity and freshness are insufficiently deterministic

- Severity: Medium
- Evidence: current tools primarily expose namespace, names, labels inconsistently, and image strings; pod UID, container ID, image digest, full owner chain, source version, observed generation, and freshness are not preserved across all outputs.
- Impact: recreated pods, moving tags, intermediate owners, stale reports, and similarly named workloads can be joined incorrectly. Model-side “connecting related signals” can turn proximity into an unsupported relationship.
- Remediation: create normalized evidence models, resolve owner chains in code, join immutable identifiers where available, apply explicit freshness windows, retain provenance/version metadata, and return `unmatched` instead of guessing.
- Verification: deterministic cases cover pod recreation, retagging, ReplicaSet ownership, stale reports, and two similar workloads in one namespace.

## Positive controls already present

- MCP tool implementations only call read/list Kubernetes APIs in the reviewed code.
- Snapshot RBAC uses `get` and `list` only for named CRD resources.
- The snapshot CronJob runs non-root, drops capabilities, disables privilege escalation, and uses a read-only root filesystem.
- Kyverno production values use three admission replicas and a fail-closed policy by default.
- Secrets and machine-specific MCP settings are excluded from Git.
- Skills explicitly prohibit invented findings and default generated Kyverno policies to Audit unless the user requests Enforce.

## Remediation order

1. SEC-001, SEC-002, SEC-009: shrink and harden the network/runtime surface.
2. SEC-003, SEC-004: validate and minimize telemetry.
3. SEC-005, SEC-006, SEC-013: establish least privilege and deterministic/provider-neutral correlation.
4. SEC-011, SEC-012: harden the human/model decision boundary.
5. SEC-007, SEC-008: make builds and regression evidence reproducible.
6. SEC-010: improve degraded-state visibility.

## Review closure rule

Do not mark a finding closed from code inspection alone. Each closure must link to the implementation, a regression test, and the command/output used to verify it. Preserve IDs so articles and release notes can refer to the same risk without renumbering.

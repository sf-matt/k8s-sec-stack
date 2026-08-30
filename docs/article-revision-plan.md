# Article revision plan

Last updated: 2026-08-30

## Source status

The two published source files were reviewed from the separate local CloudSecBurrito site repository on 2026-08-30:

- “Building an OSS Kubernetes Security Console with MCP” (published 2026-05-28)
- “Deploying an OSS Kubernetes Security Console” (published 2026-06-03)

They are not part of this repository or its Git history. `blog/` is gitignored and absent from the current clone. Preserve the published titles, slugs, and URLs unless analytics/editorial requirements say otherwise; revise the content in the blog repository only in a dedicated article task.

Still needed before editing:

- confirmation that the published pages should be updated in place;
- screenshots/diagrams that must be preserved;
- target word count and voice constraints, if any.

Never copy private cluster identifiers, credentials, unredacted event payloads, or third-party data into the repository.

## Series narrative

The series should progress from visibility to correlation to operational trust:

1. **Part 1 — Architecture and trust model.** Preserve the coverage-versus-correlation thesis, explain the CRD/event split and narrow tools, then add provider-neutral MCP boundaries, deterministic identity/freshness, permissions, untrusted data, and human approval.
2. **Part 2 — Reproducible deployment and proof.** Preserve the hands-on install and “deployed is not running” lesson, then use safe access, a dedicated identity, actual MCP requests, and one complete deterministic investigation.
3. **Part 3 — Harden and evaluate the reference architecture.** Show how the local demo evolves toward a safer, provider-neutral, measurable deployment.

Do not present Part 3 outcomes until the corresponding roadmap work is implemented.

## Part 1 revision: architecture and trust model

### Core promise

A reader understands why coverage is not correlation, what CRDs do and do not normalize, where MCP fits between data and a host/client/model, which identities/freshness rules make a correlation defensible, and why the current code is a reference prototype rather than a product.

### Recommended outline

1. Problem: Kubernetes security evidence is fragmented; preserve the article's strong “coverage versus correlation” framing.
2. Architecture: preserve the durable-CRD versus streaming-Falco split and narrow query tools.
3. Correct MCP boundary: data → normalization/correlation → MCP server → host/client → model → optional client workflow.
4. Shared API surface versus normalized evidence model.
5. Stable identity, owner chain, provenance, and freshness requirements.
6. Kubeconfig/RBAC and event-sink trust boundaries.
7. Untrusted tool data, prompt injection, and human approval.
8. Transparent non-goals and AI-assisted development disclosure.
9. Hand off deployment proof to Part 2.

### Required corrections/checks against the current repository

- The chart includes five upstream dependencies because Falco and falcosidekick are separate charts, even though the product story groups them as one runtime layer.
- “Shared surface” is accurate; do not imply a shared schema/model or automatic correlation.
- Replace the Claude-only diagram with a provider-neutral host/client/model boundary and label skills as optional client workflows.
- Remove the arbitrary threat score and KILL mapping from the example; use evidence, missing context, confidence, investigation, and containment options requiring approval.
- Remove “Autonomous will come later.” Autonomy is not an assumed destination.
- Reframe “transparent security console” as a Kubernetes security investigation layer/reference architecture; console is a direction.
- Add a direct AI-assisted-development note: substantially developed with Claude Code and OpenAI Codex; architecture directed and documented lab workflows manually tested/validated by the maintainer; no independent security audit; not production-ready.
- Cite a repository revision containing the Apache-2.0 license before calling it open source.

### Publication evidence

- rendered architecture diagram matching `docs/architecture.md`;
- explicit threat model and correlation identity/freshness table;
- explicit reference-implementation, Apache-2.0, AI-assistance, maintainer-validation, and security limitation callouts;
- examples that label findings as evidence rather than proof.

## Part 2 revision: reproducible deployment and proof

### Core promise

A reader can clone a tagged revision, deploy the supported lab safely, verify every data source, connect a compliant MCP client under a documented identity, call real tools, and reproduce one grounded cross-signal investigation.

### Recommended outline

1. Lab-only safety warning, prerequisites, tested versions, repository tag, and cleanup.
2. Install and readiness checks; preserve “deployed is not the same as running.”
3. Verify Trivy, Kubescape, Kyverno, and Falco independently with sanitized outputs.
4. Use a dedicated read-only identity and non-public event-sink access.
5. Present generic stdio MCP configuration, followed by separate host examples.
6. Show one real MCP request/response.
7. Show one complete deterministic investigation with matched and missing evidence.
8. Report evaluation results and known limitations.
9. Transition to Part 3 hardening.

### Required corrections/checks against the current repository

- Replace “Claude-powered”/“Claude-readable” claims with provider-neutral MCP language except in an explicitly labeled Claude client example.
- State that the server uses the caller's current Kubernetes identity; “read-only implementation” does not by itself enforce least privilege.
- Do not claim a robust namespace-plus-label join until it is implemented and tested; several current tools return limited labels and image correlation may rely on substrings.
- Distinguish current pod names from stable workload owners and image tags from immutable digests.
- Document response-size limits and degraded source behavior after those contracts exist.
- Remove the KILL/ISOLATE/MONITOR score mapping; containment options require explicit human selection and are never presented as executed.
- Fix the Falco verification ordering bug: the current command uses `$NODE_IP` and `$NODE_PORT` before defining them.
- Replace unauthenticated NodePort instructions with ClusterIP plus a deliberate local access path such as `kubectl port-forward`; remote deployment requires authentication, TLS, request limits, and authorization.
- The existing final checklist proves signal collection, not cross-tool correlation. Add the missing investigation before claiming a console.
- Preserve the deterministic-aggregation-versus-model-reasoning section, but move identity joins into deterministic code rather than “connecting related signals” in the model.
- Keep actual commands and observed output, but scrub personal shell prompts, node addresses, registry/account identifiers, and incidental cluster data.

### Publication evidence

- MCP schema/contract test results;
- least-privilege RBAC manifest and access matrix;
- sanitized deterministic triage fixture and expected answer;
- evaluation table with pass criteria and observed results;
- measured setup steps for at least one generic inspector and any named client examples;
- prompt/skill version tied to the repository tag.
- clean-clone transcript, tested component versions, readiness timings, and cleanup output.

## Future Part 3: hardening and operationalization

Provisional scope:

- threat model and trust boundaries;
- replacing NodePort defaults and securing ingestion/query paths;
- hardened event-sink image and pod configuration;
- namespace/provider-neutral Helm design;
- dependency provenance and reproducible builds;
- testing pyramid and agent evaluation methodology;
- telemetry minimization, retention, and failure visibility;
- measured limitations of SQLite and single-cluster operation.

Publication gate: Phase 1 and the core of Phase 3 in `docs/roadmap.md` must be complete, and resolved findings must contain verification evidence.

## Claim matrix template

Use this table during each revision. Every technical claim needs evidence or must be softened/removed.

| Claim | Article | Repository source | Reproduction command | Expected evidence | Status |
|---|---|---|---|---|---|
| One Helm release installs the stack | Part 2 | `charts/k8s-sec-stack/` | `helm template` / clean install | rendered resources and healthy workloads | pending |
| Security CRDs populate after demo deployment | Part 2 | operators + `demo/` | documented polling commands | sanitized CRD samples | pending |
| MCP tools are read-only | Part 2 | `mcp-server/` + RBAC | contract/access tests | no mutation verbs/calls | pending |
| Runtime evidence correlates to blast radius | Part 2 | tools + `triage-threat` | deterministic eval case | expected joined evidence | pending |
| Deployment defaults are hardened | Part 3 | chart/templates | policy and render tests | closed SEC findings | pending |

## Editorial rules

- Prefer exact commands and observed results over adjectives such as “easy,” “complete,” or “production-ready.”
- Date/version any statement that can drift.
- Link claims to a release tag, not a moving branch.
- Mark demo-only choices where they first appear.
- Scrub names, IPs, account IDs, registry paths, tokens, and unique incident details.
- Keep diagrams consistent with `docs/architecture.md`; update both when the data flow changes.
- End each article with current limitations and the next concrete milestone.

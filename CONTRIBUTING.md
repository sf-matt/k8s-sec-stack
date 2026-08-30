# Contributing to k8s-sec-stack

Thank you for helping improve the project. This repository is a security reference implementation, so evidence, reviewability, and honest limitations matter more than the size or speed of a change.

## Contribution license

The project is licensed under the Apache License 2.0. Unless explicitly stated otherwise, contributions intentionally submitted for inclusion are provided under the same terms, as described in Section 5 of the license.

By contributing, you represent that you have the right to submit the work. Do not submit copied code, generated output, fixtures, screenshots, or data whose license or provenance you cannot establish.

## Development and validation responsibilities

This project has been substantially developed with AI coding agents, including Claude Code and OpenAI Codex. AI assistance has included code generation, refactoring, documentation, review, and test scaffolding.

AI assistance does not replace authorship responsibility or validation:

- project maintainer Matt Brown directs the architecture and project priorities;
- Matt manually exercises and validates the documented lab workflows;
- contributors must review, understand, and be able to explain everything they submit;
- passing generated tests is not proof that a security claim is correct;
- AI output is not an independent security audit or a source of factual evidence.

For a materially AI-assisted contribution, say so in the pull request and identify the tools used. The disclosure is for provenance and review context, not to diminish the human contribution.

## Before submitting a change

1. Keep the MCP server read-only unless a separately reviewed design explicitly authorizes mutation.
2. Treat Kubernetes objects and runtime-event content as untrusted input.
3. Add or update tests appropriate to the behavior being changed.
4. Record manual verification commands and results in the pull request.
5. Update `docs/architecture.md` for material data-flow changes.
6. Update `docs/security-review.md` when a finding is introduced, changed, or closed.
7. Scrub cluster names, IPs, account IDs, registry paths, credentials, incident data, and other identifying information.

## Pull request description

Include:

- what changed and why;
- risk and trust-boundary impact;
- automated tests run;
- manual validation performed;
- known limitations;
- material AI assistance and the tools used, if applicable.

The maintainer remains responsible for deciding whether a change is sufficiently understood and validated to merge or release.

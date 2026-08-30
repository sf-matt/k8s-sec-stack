# Security policy

## Project maturity

`k8s-sec-stack` is an open-source Kubernetes security reference implementation and lab. It is not a production-ready security product, a SIEM replacement, or an independently audited control plane.

The current architecture has known risks documented in `docs/security-review.md`. In particular, review the event-sink exposure, Kubernetes identity, data-retention, correlation, and model trust-boundary findings before deploying outside an isolated lab.

## Supported versions

Until the project publishes versioned releases, only the current default branch receives security fixes. Repository tags and articles may describe older behavior and should not be assumed secure without checking the current review.

## Reporting a vulnerability

Do not open a public issue containing exploit details, credentials, cluster data, or sensitive findings. Report vulnerabilities privately through the repository owner's GitHub contact or GitHub private vulnerability reporting when it is enabled.

Include enough information to reproduce and assess the problem:

- affected commit or version;
- component and deployment configuration;
- reproduction steps or proof of concept;
- security impact;
- suggested mitigation, if known.

The project does not currently promise a formal response SLA. Reports will be acknowledged and handled as maintainer capacity permits.

## AI-assisted development disclosure

The project has been substantially developed with AI coding agents, including Claude Code and OpenAI Codex. Project maintainer Matt Brown directs the work, manually tests the documented lab workflows, reviews changes, and remains responsible for releases. AI assistance must not be interpreted as an independent security review.

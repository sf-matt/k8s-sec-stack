# Policy Exceptions

Namespace-scoped PolicyExceptions for workloads with a legitimate reason to
bypass an enforcing ClusterPolicy.

## Rules

1. **Justification required.** Every exception must have a
   `exceptions.policy/justification` annotation. "It fails" is not a justification.

2. **Narrowest possible scope.** Prefer exact name > name pattern > label selector >
   namespace-wide. Namespace-wide exceptions need an explicit note explaining why
   narrower scoping isn't possible.

3. **No ClusterPolicyExceptions.** Everything here is namespace-scoped. Exceptions
   live close to the teams that own the workloads.

4. **Review dates.** Set `exceptions.policy/review-date`. Exceptions without one
   tend to persist indefinitely.

5. **`approved-by` must be filled in before applying.** Generated exceptions leave
   this as `"pending"` intentionally.

## Naming convention

`policies/exceptions/<namespace>-<workload-short-name>-<policy-short-name>.yaml`

Example: `monitoring-node-exporter-disallow-privileged.yaml`

## Usage

Generate with: `/create-exception`

The skill will check live PolicyReport violations to confirm the exception is
actually needed before generating YAML.

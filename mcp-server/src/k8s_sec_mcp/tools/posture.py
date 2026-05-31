"""kubescape ClusterComplianceReport and Kyverno PolicyReport tools."""

import json
from kubernetes import client, config as k8s_config


def _k8s_client() -> client.CustomObjectsApi:
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()
    return client.CustomObjectsApi()


async def list_compliance_reports(framework: str = "") -> str:
    api = _k8s_client()
    raw = api.list_cluster_custom_object(
        group="aquasecurity.github.io",
        version="v1alpha1",
        plural="clustercompliancereports",
    )

    results = []
    for item in raw.get("items", []):
        meta = item.get("metadata", {})
        name = meta.get("name", "")

        if framework and framework.lower() not in name.lower():
            continue

        spec = item.get("spec", {})
        status = item.get("status", {})
        counts = status.get("summary", {})
        summary_report = status.get("summaryReport", {})

        results.append({
            "name": name,
            "framework": spec.get("compliance", {}).get("name", name),
            "pass": counts.get("passCount", 0),
            "fail": counts.get("failCount", 0),
            "failing_controls": [
                {
                    "id": c.get("id"),
                    "name": c.get("name"),
                    "severity": c.get("severity"),
                    "failed_resources": c.get("totalFail", 0),
                }
                for c in summary_report.get("controlCheck", [])
                if c.get("totalFail", 0) > 0
            ],
        })

    return json.dumps(results, indent=2)


async def list_policy_summary() -> str:
    api = _k8s_client()

    cluster_raw = api.list_cluster_custom_object(
        group="wgpolicyk8s.io", version="v1alpha2", plural="clusterpolicyreports"
    )
    ns_raw = api.list_cluster_custom_object(
        group="wgpolicyk8s.io", version="v1alpha2", plural="policyreports"
    )
    items = cluster_raw.get("items", []) + ns_raw.get("items", [])

    counts: dict[str, dict[str, int]] = {}
    for item in items:
        for r in item.get("results", []):
            policy = r.get("policy", "unknown")
            result = r.get("result", "")
            if policy not in counts:
                counts[policy] = {"fail": 0, "pass": 0, "warn": 0}
            if result in counts[policy]:
                counts[policy][result] += 1

    try:
        cp_raw = api.list_cluster_custom_object(
            group="kyverno.io", version="v1", plural="clusterpolicies"
        )
        modes = {
            item["metadata"]["name"]: item.get("spec", {}).get("validationFailureAction", "audit").lower()
            for item in cp_raw.get("items", [])
        }
    except Exception:
        modes = {}

    results = [
        {
            "policy": policy,
            "mode": modes.get(policy, "unknown"),
            "fail": c["fail"],
            "pass": c["pass"],
            "warn": c["warn"],
        }
        for policy, c in sorted(counts.items(), key=lambda x: x[1]["fail"], reverse=True)
    ]

    return json.dumps(results, indent=2)


async def list_policy_violations(
    namespace: str = "all",
    result: str = "fail",
) -> str:
    api = _k8s_client()

    if namespace == "all":
        raw = api.list_cluster_custom_object(
            group="wgpolicyk8s.io",
            version="v1alpha2",
            plural="clusterpolicyreports",
        )
        items = raw.get("items", [])

        ns_raw = api.list_cluster_custom_object(
            group="wgpolicyk8s.io",
            version="v1alpha2",
            plural="policyreports",
        )
        items += ns_raw.get("items", [])
    else:
        raw = api.list_namespaced_custom_object(
            group="wgpolicyk8s.io",
            version="v1alpha2",
            plural="policyreports",
            namespace=namespace,
        )
        items = raw.get("items", [])

    violations = []
    for item in items:
        meta = item.get("metadata", {})
        # resource reference lives at report scope, not per-result
        scope = item.get("scope", {})
        resource_name = scope.get("name", "") or meta.get("name", "")
        resource_kind = scope.get("kind", "")
        for r in item.get("results", []):
            r_result = r.get("result", "")
            if result != "all" and r_result != result:
                continue
            violations.append({
                "namespace": meta.get("namespace", "cluster"),
                "policy": r.get("policy"),
                "rule": r.get("rule"),
                "severity": r.get("severity", ""),
                "result": r_result,
                "message": r.get("message", ""),
                "resource": resource_name,
                "kind": resource_kind,
            })

    return json.dumps(violations, indent=2)

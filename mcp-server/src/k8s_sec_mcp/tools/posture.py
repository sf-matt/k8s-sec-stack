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
        summary = item.get("status", {}).get("summaryReport", {})

        results.append({
            "name": name,
            "framework": spec.get("compliance", {}).get("name", name),
            "pass": summary.get("passCount", 0),
            "fail": summary.get("failCount", 0),
            "failing_controls": [
                {
                    "id": c.get("id"),
                    "name": c.get("name"),
                    "severity": c.get("severity"),
                    "failed_resources": c.get("failedResources", 0),
                }
                for c in summary.get("topWorkloadFindings", [])
            ],
        })

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

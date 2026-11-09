"""Kubescape workload posture and Kyverno PolicyReport tools."""

import json

from kubernetes import client
from kubernetes import config as k8s_config
from kubernetes.client.exceptions import ApiException


def _k8s_client() -> client.CustomObjectsApi:
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()
    return client.CustomObjectsApi()


async def list_compliance_reports(namespace: str = "all") -> str:
    api = _k8s_client()
    raw = api.list_cluster_custom_object(
        group="spdx.softwarecomposition.kubescape.io",
        version="v1beta1",
        plural="workloadconfigurationscansummaries",
    )

    results = []
    for listed_item in raw.get("items", []):
        listed_meta = listed_item.get("metadata", {})
        item_namespace = listed_meta.get("namespace", "")

        if namespace != "all" and item_namespace != namespace:
            continue

        item = api.get_namespaced_custom_object(
            group="spdx.softwarecomposition.kubescape.io",
            version="v1beta1",
            namespace=item_namespace,
            plural="workloadconfigurationscansummaries",
            name=listed_meta.get("name", ""),
        )
        meta = item.get("metadata", {})
        item_namespace = meta.get("namespace", "")

        spec = item.get("spec", {})
        labels = meta.get("labels", {})
        controls = spec.get("controls") or {}
        passed = sum(
            1
            for control in controls.values()
            if control.get("status", {}).get("status") == "passed"
        )
        failed = sum(
            1
            for control in controls.values()
            if control.get("status", {}).get("status") == "failed"
        )

        results.append(
            {
                "namespace": item_namespace,
                "kind": labels.get("kubescape.io/workload-kind", ""),
                "workload": labels.get(
                    "kubescape.io/workload-name", meta.get("name", "")
                ),
                "wlid": meta.get("annotations", {}).get("kubescape.io/wlid", ""),
                "pass": passed,
                "fail": failed,
                "failed_by_severity": spec.get("severities") or {},
                "failing_controls": [
                    {
                        "id": control_id,
                        "severity": control.get("severity", {}).get(
                            "severity", "Unknown"
                        ),
                    }
                    for control_id, control in controls.items()
                    if control.get("status", {}).get("status") == "failed"
                ],
            }
        )

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
            item["metadata"]["name"]: item.get("spec", {})
            .get("validationFailureAction", "audit")
            .lower()
            for item in cp_raw.get("items", [])
        }
    except ApiException:
        modes = {}

    results = [
        {
            "policy": policy,
            "mode": modes.get(policy, "unknown"),
            "fail": c["fail"],
            "pass": c["pass"],
            "warn": c["warn"],
        }
        for policy, c in sorted(
            counts.items(), key=lambda x: x[1]["fail"], reverse=True
        )
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
            violations.append(
                {
                    "namespace": meta.get("namespace", "cluster"),
                    "policy": r.get("policy"),
                    "rule": r.get("rule"),
                    "severity": r.get("severity", ""),
                    "result": r_result,
                    "message": r.get("message", ""),
                    "resource": resource_name,
                    "kind": resource_kind,
                }
            )

    return json.dumps(violations, indent=2)

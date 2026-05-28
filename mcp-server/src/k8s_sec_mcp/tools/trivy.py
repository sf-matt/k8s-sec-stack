"""trivy-operator tools beyond VulnerabilityReports."""

import json
from kubernetes import client, config as k8s_config

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]
GROUP = "aquasecurity.github.io"


def _k8s_client() -> client.CustomObjectsApi:
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()
    return client.CustomObjectsApi()


def _severity_passes(sev: str, min_severity: str) -> bool:
    if min_severity == "ALL":
        return True
    try:
        return SEVERITY_ORDER.index(sev.upper()) <= SEVERITY_ORDER.index(min_severity.upper())
    except ValueError:
        return True


def _checks_from_report(report: dict, min_severity: str) -> list[dict]:
    checks = []
    for c in report.get("checks", []):
        if c.get("success", True):
            continue
        if not _severity_passes(c.get("severity", "UNKNOWN"), min_severity):
            continue
        checks.append({
            "id": c.get("checkID"),
            "title": c.get("title"),
            "severity": c.get("severity"),
            "messages": c.get("messages", []),
            "remediation": c.get("remediation", ""),
        })
    return sorted(checks, key=lambda c: SEVERITY_ORDER.index(c["severity"].upper()) if c["severity"].upper() in SEVERITY_ORDER else 99)


async def list_config_audit(
    namespace: str = "all",
    severity: str = "HIGH",
) -> str:
    """ConfigAuditReports — workload and cluster-scoped resource misconfigurations."""
    api = _k8s_client()

    items = []

    # namespaced ConfigAuditReports (per workload)
    if namespace == "all":
        items += api.list_cluster_custom_object(GROUP, "v1alpha1", "configauditreports").get("items", [])
    else:
        items += api.list_namespaced_custom_object(group=GROUP, version="v1alpha1", plural="configauditreports", namespace=namespace).get("items", [])

    # cluster-scoped ClusterConfigAuditReports (ClusterRoles, ClusterRoleBindings, etc.)
    # always included regardless of namespace filter — they have no namespace
    if namespace == "all":
        items += api.list_cluster_custom_object(GROUP, "v1alpha1", "clusterconfigauditreports").get("items", [])

    results = []
    for item in items:
        meta = item.get("metadata", {})
        checks = _checks_from_report(item.get("report", {}), severity)
        if not checks:
            continue
        results.append({
            "namespace": meta.get("namespace", "cluster"),
            "workload": meta.get("name"),
            "summary": item.get("report", {}).get("summary", {}),
            "failures": checks,
        })

    results.sort(key=lambda r: (
        r["summary"].get("criticalCount", 0) * -1000 +
        r["summary"].get("highCount", 0) * -100
    ))
    return json.dumps(results, indent=2)


async def list_exposed_secrets(
    namespace: str = "all",
) -> str:
    """ExposedSecretReports — hardcoded secrets, tokens, keys found in image layers."""
    api = _k8s_client()

    if namespace == "all":
        raw = api.list_cluster_custom_object(GROUP, "v1alpha1", "exposedsecretreports")
    else:
        raw = api.list_namespaced_custom_object(group=GROUP, version="v1alpha1", plural="exposedsecretreports", namespace=namespace)

    results = []
    for item in raw.get("items", []):
        meta = item.get("metadata", {})
        report = item.get("report", {})
        secrets = report.get("secrets", [])
        if not secrets:
            continue
        artifact = report.get("artifact", {})
        image = artifact.get("repository", "") + ":" + artifact.get("tag", "")
        results.append({
            "namespace": meta.get("namespace"),
            "workload": meta.get("name"),
            "image": image,
            "secrets": [
                {
                    "target": s.get("target"),
                    "type": s.get("ruleID"),
                    "title": s.get("title"),
                    "severity": s.get("severity"),
                    "match": s.get("match", ""),
                }
                for s in secrets
            ],
        })

    return json.dumps(results, indent=2)


async def list_rbac_issues(
    namespace: str = "all",
    severity: str = "ALL",
) -> str:
    """RBACAssessmentReports — over-permissive roles and service accounts."""
    api = _k8s_client()

    items = []

    # namespaced RBACAssessmentReports
    if namespace == "all":
        ns_raw = api.list_cluster_custom_object(GROUP, "v1alpha1", "rbacassessmentreports")
        items += ns_raw.get("items", [])
    else:
        ns_raw = api.list_namespaced_custom_object(group=GROUP, version="v1alpha1", plural="rbacassessmentreports", namespace=namespace)
        items += ns_raw.get("items", [])

    # cluster-scoped ClusterRBACAssessmentReports (always included)
    if namespace == "all":
        cluster_raw = api.list_cluster_custom_object(GROUP, "v1alpha1", "clusterrbacassessmentreports")
        items += cluster_raw.get("items", [])

    results = []
    for item in items:
        meta = item.get("metadata", {})
        checks = _checks_from_report(item.get("report", {}), severity)
        if not checks:
            continue
        results.append({
            "namespace": meta.get("namespace", "cluster"),
            "role": meta.get("name"),
            "failures": checks,
        })

    return json.dumps(results, indent=2)


async def list_infra_issues(
    severity: str = "ALL",
) -> str:
    """InfraAssessmentReports — node and control-plane hardening failures (kubelet, etcd, API server)."""
    api = _k8s_client()

    items = []

    # namespaced InfraAssessmentReports (per-node collectors)
    ns_raw = api.list_cluster_custom_object(GROUP, "v1alpha1", "infraassessmentreports")
    items += ns_raw.get("items", [])

    # cluster-scoped ClusterInfraAssessmentReports
    cluster_raw = api.list_cluster_custom_object(GROUP, "v1alpha1", "clusterinfraassessmentreports")
    items += cluster_raw.get("items", [])

    results = []
    for item in items:
        meta = item.get("metadata", {})
        checks = _checks_from_report(item.get("report", {}), severity)
        if not checks:
            continue
        results.append({
            "scope": meta.get("namespace", "cluster"),
            "name": meta.get("name"),
            "summary": item.get("report", {}).get("summary", {}),
            "failures": checks,
        })

    return json.dumps(results, indent=2)

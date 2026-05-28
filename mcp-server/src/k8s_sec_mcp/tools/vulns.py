"""trivy-operator VulnerabilityReport tools."""

import json
from kubernetes import client, config as k8s_config

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"]


def _k8s_client() -> client.CustomObjectsApi:
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()
    return client.CustomObjectsApi()


async def list_vuln_reports(
    namespace: str = "all",
    severity: str = "ALL",
    image: str = "",
) -> str:
    api = _k8s_client()

    if namespace == "all":
        raw = api.list_cluster_custom_object(
            group="aquasecurity.github.io",
            version="v1alpha1",
            plural="vulnerabilityreports",
        )
    else:
        raw = api.list_namespaced_custom_object(
            group="aquasecurity.github.io",
            version="v1alpha1",
            plural="vulnerabilityreports",
            namespace=namespace,
        )

    results = []
    threshold = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)

    for item in raw.get("items", []):
        meta = item.get("metadata", {})
        report = item.get("report", {})
        artifact = report.get("artifact", {})
        img = artifact.get("repository", "") + ":" + artifact.get("tag", "")

        if image and image not in img:
            continue

        vulns = []
        for v in report.get("vulnerabilities", []):
            sev = v.get("severity", "UNKNOWN")
            if severity != "ALL" and SEVERITY_ORDER.index(sev) > threshold:
                continue
            vulns.append({
                "id": v.get("vulnerabilityID"),
                "severity": sev,
                "resource": v.get("resource"),
                "installed": v.get("installedVersion"),
                "fixed": v.get("fixedVersion", "no fix"),
                "title": v.get("title", ""),
            })

        if vulns:
            results.append({
                "namespace": meta.get("namespace"),
                "name": meta.get("name"),
                "image": img,
                "vulnerabilities": sorted(vulns, key=lambda v: SEVERITY_ORDER.index(v["severity"])),
            })

    return json.dumps(results, indent=2)

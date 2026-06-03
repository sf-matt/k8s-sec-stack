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


async def list_vuln_summary(
    namespace: str = "all",
    severity: str = "CRITICAL",
) -> str:
    """Deduplicated vulnerability summary per image. Splits unfixable CVEs (fixedVersion empty)
    from fixable ones. Use for policy decisions — unfixable → block-cve-images, fixable → /fix-image."""
    api = _k8s_client()

    if namespace == "all":
        raw = api.list_cluster_custom_object(group="aquasecurity.github.io", version="v1alpha1", plural="vulnerabilityreports")
    else:
        raw = api.list_namespaced_custom_object(group="aquasecurity.github.io", version="v1alpha1", plural="vulnerabilityreports", namespace=namespace)

    threshold = SEVERITY_ORDER.index(severity) if severity in SEVERITY_ORDER else len(SEVERITY_ORDER)
    by_image: dict[str, dict] = {}

    for item in raw.get("items", []):
        report = item.get("report", {})
        artifact = report.get("artifact", {})
        img = artifact.get("repository", "") + ":" + artifact.get("tag", "")

        if img not in by_image:
            by_image[img] = {"image": img, "unfixable": [], "fixable_count": 0}

        seen = {c["id"] for c in by_image[img]["unfixable"]}

        for v in report.get("vulnerabilities", []):
            sev = v.get("severity", "UNKNOWN")
            if SEVERITY_ORDER.index(sev) > threshold:
                continue
            cid = v.get("vulnerabilityID")
            if cid in seen:
                continue
            seen.add(cid)
            if not v.get("fixedVersion", ""):
                by_image[img]["unfixable"].append({"id": cid, "resource": v.get("resource"), "severity": sev})
            else:
                by_image[img]["fixable_count"] += 1

    results = [v for v in by_image.values() if v["unfixable"] or v["fixable_count"] > 0]
    results.sort(key=lambda x: (-len(x["unfixable"]), -x["fixable_count"]))
    return json.dumps(results, indent=2)

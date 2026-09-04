"""trivy-operator VulnerabilityReport tools."""

import json

from kubernetes import client
from kubernetes import config as k8s_config

from k8s_sec_mcp.adapters.trivy import parse_vulnerability_report_list

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
    threshold = (
        SEVERITY_ORDER.index(severity)
        if severity in SEVERITY_ORDER
        else len(SEVERITY_ORDER)
    )

    for report in parse_vulnerability_report_list(raw):
        img = report.image.legacy_reference

        if image and image not in img:
            continue

        vulns = []
        for v in report.findings:
            sev = v.severity
            if severity != "ALL" and SEVERITY_ORDER.index(sev) > threshold:
                continue
            vulns.append(
                {
                    "id": v.vulnerability_id,
                    "severity": sev,
                    "resource": v.resource,
                    "installed": v.installed_version,
                    "fixed": (
                        v.fixed_version if v.fixed_version is not None else "no fix"
                    ),
                    "title": v.title,
                }
            )

        if vulns:
            results.append(
                {
                    "namespace": report.provenance.report_namespace,
                    "name": report.provenance.report_name,
                    "image": img,
                    "vulnerabilities": sorted(
                        vulns, key=lambda v: SEVERITY_ORDER.index(v["severity"])
                    ),
                }
            )

    return json.dumps(results, indent=2)


async def list_vuln_summary(
    namespace: str = "all",
    severity: str = "CRITICAL",
) -> str:
    """Deduplicated vulnerability summary per image. Splits unfixable CVEs (fixedVersion empty)
    from fixable ones. Use for policy decisions — unfixable → block-cve-images, fixable → /fix-image."""
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

    threshold = (
        SEVERITY_ORDER.index(severity)
        if severity in SEVERITY_ORDER
        else len(SEVERITY_ORDER)
    )
    by_image: dict[str, dict] = {}

    for report in parse_vulnerability_report_list(raw):
        img = report.image.legacy_reference

        if img not in by_image:
            by_image[img] = {"image": img, "unfixable": [], "fixable_count": 0}

        seen = {c["id"] for c in by_image[img]["unfixable"]}

        for v in report.findings:
            sev = v.severity
            if SEVERITY_ORDER.index(sev) > threshold:
                continue
            cid = v.vulnerability_id
            if cid in seen:
                continue
            seen.add(cid)
            if not v.fixed_version:
                by_image[img]["unfixable"].append(
                    {"id": cid, "resource": v.resource, "severity": sev}
                )
            else:
                by_image[img]["fixable_count"] += 1

    results = [v for v in by_image.values() if v["unfixable"] or v["fixable_count"] > 0]
    results.sort(key=lambda x: (-len(x["unfixable"]), -x["fixable_count"]))
    return json.dumps(results, indent=2)

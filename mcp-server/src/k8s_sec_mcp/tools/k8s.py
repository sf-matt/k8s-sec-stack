"""Kubernetes resource context tools — read-only, security-correlation focus."""

import json
from datetime import timezone
from kubernetes import client, config as k8s_config
from kubernetes.client.exceptions import ApiException


def _clients():
    try:
        k8s_config.load_incluster_config()
    except k8s_config.ConfigException:
        k8s_config.load_kube_config()
    return client.AppsV1Api(), client.CoreV1Api(), client.NetworkingV1Api()


def _container_summary(containers: list) -> list[dict]:
    return [{"name": c.name, "image": c.image} for c in containers]


async def get_pod_status(namespace: str, pod: str) -> str:
    """
    Check whether a specific pod still exists and return its current state.
    Key for triage: distinguishes an active incident from a historical event.
    Returns existence, phase, age, owner (controller or standalone), and node.
    """
    _, core, _ = _clients()

    try:
        p = core.read_namespaced_pod(name=pod, namespace=namespace)
    except ApiException as e:
        if e.status == 404:
            # Pod gone — return namespace context so the caller knows what's still running
            existing = core.list_namespaced_pod(namespace=namespace)
            running = [
                {"name": ep.metadata.name, "phase": ep.status.phase}
                for ep in existing.items
                if ep.status.phase == "Running"
            ]
            return json.dumps({
                "exists": False,
                "pod": pod,
                "namespace": namespace,
                "note": "Pod no longer exists. Event is historical.",
                "running_pods_in_namespace": running,
            }, indent=2)
        raise

    owners = p.metadata.owner_references or []
    owner = None
    if owners:
        owner = {"kind": owners[0].kind, "name": owners[0].name}

    age_seconds = None
    if p.metadata.creation_timestamp:
        from datetime import datetime
        created = p.metadata.creation_timestamp
        if created.tzinfo is None:
            created = created.replace(tzinfo=timezone.utc)
        age_seconds = int((datetime.now(timezone.utc) - created).total_seconds())

    return json.dumps({
        "exists": True,
        "pod": pod,
        "namespace": namespace,
        "phase": p.status.phase,
        "age_seconds": age_seconds,
        "node": p.spec.node_name,
        "owner": owner,
        "standalone": owner is None,
        "containers": _container_summary(p.spec.containers),
    }, indent=2)


async def list_workloads(namespace: str = "all") -> str:
    """Deployments, DaemonSets, and standalone Pods with image and label context."""
    apps, core, _ = _clients()

    results = []

    # Deployments
    deps = apps.list_deployment_for_all_namespaces() if namespace == "all" else apps.list_namespaced_deployment(namespace)
    for d in deps.items:
        results.append({
            "kind": "Deployment",
            "namespace": d.metadata.namespace,
            "name": d.metadata.name,
            "labels": d.metadata.labels or {},
            "replicas": {"desired": d.spec.replicas, "ready": (d.status.ready_replicas or 0)},
            "containers": _container_summary(d.spec.template.spec.containers),
        })

    # DaemonSets
    dss = apps.list_daemon_set_for_all_namespaces() if namespace == "all" else apps.list_namespaced_daemon_set(namespace)
    for ds in dss.items:
        results.append({
            "kind": "DaemonSet",
            "namespace": ds.metadata.namespace,
            "name": ds.metadata.name,
            "labels": ds.metadata.labels or {},
            "containers": _container_summary(ds.spec.template.spec.containers),
        })

    # Standalone pods (no owner — rogue or one-off)
    pods = core.list_pod_for_all_namespaces() if namespace == "all" else core.list_namespaced_pod(namespace)
    for p in pods.items:
        if p.metadata.owner_references:
            continue
        results.append({
            "kind": "Pod",
            "namespace": p.metadata.namespace,
            "name": p.metadata.name,
            "labels": p.metadata.labels or {},
            "phase": p.status.phase,
            "containers": _container_summary(p.spec.containers),
        })

    return json.dumps(results, indent=2)


async def list_network_exposure(namespace: str = "all") -> str:
    """Services and Ingresses — which workloads are reachable and how."""
    _, core, networking = _clients()

    results = {"services": [], "ingresses": []}

    svcs = core.list_service_for_all_namespaces() if namespace == "all" else core.list_namespaced_service(namespace)
    for s in svcs.items:
        # skip headless and kubernetes internal service
        if s.metadata.name == "kubernetes" and s.metadata.namespace == "default":
            continue
        svc_type = s.spec.type
        entry = {
            "namespace": s.metadata.namespace,
            "name": s.metadata.name,
            "type": svc_type,
            "selector": s.spec.selector or {},
            "ports": [
                {"port": p.port, "target": p.target_port, "protocol": p.protocol,
                 "nodePort": p.node_port}
                for p in (s.spec.ports or [])
            ],
        }
        # flag externally reachable services
        if svc_type in ("NodePort", "LoadBalancer"):
            entry["external"] = True
            if s.status.load_balancer and s.status.load_balancer.ingress:
                entry["loadBalancerIP"] = s.status.load_balancer.ingress[0].ip or s.status.load_balancer.ingress[0].hostname
        results["services"].append(entry)

    ingresses = networking.list_ingress_for_all_namespaces() if namespace == "all" else networking.list_namespaced_ingress(namespace)
    for i in ingresses.items:
        rules = []
        for r in (i.spec.rules or []):
            paths = []
            if r.http:
                for p in r.http.paths:
                    paths.append({
                        "path": p.path,
                        "backend": p.backend.service.name if p.backend.service else None,
                    })
            rules.append({"host": r.host, "paths": paths})
        results["ingresses"].append({
            "namespace": i.metadata.namespace,
            "name": i.metadata.name,
            "rules": rules,
        })

    return json.dumps(results, indent=2)


async def list_network_policies(namespace: str = "all") -> str:
    """NetworkPolicies per namespace — highlights namespaces with no policy (open to lateral movement)."""
    _, core, networking = _clients()

    # collect all non-system namespaces
    all_ns = [
        ns.metadata.name for ns in core.list_namespace().items
        if ns.metadata.name not in ("kube-system", "kube-public", "kube-node-lease")
    ]

    policies_raw = (
        networking.list_network_policy_for_all_namespaces() if namespace == "all"
        else networking.list_namespaced_network_policy(namespace)
    )

    by_ns: dict[str, list] = {}
    for p in policies_raw.items:
        ns = p.metadata.namespace
        by_ns.setdefault(ns, []).append({
            "name": p.metadata.name,
            "podSelector": p.spec.pod_selector.match_labels if p.spec.pod_selector else {},
            "policyTypes": p.spec.policy_types or [],
            "ingressRules": len(p.spec.ingress or []),
            "egressRules": len(p.spec.egress or []),
        })

    results = []
    target_ns = all_ns if namespace == "all" else [namespace]
    for ns in sorted(target_ns):
        results.append({
            "namespace": ns,
            "policyCount": len(by_ns.get(ns, [])),
            "protected": ns in by_ns,
            "policies": by_ns.get(ns, []),
        })

    return json.dumps(results, indent=2)

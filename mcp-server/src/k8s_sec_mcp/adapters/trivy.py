"""Adapter for Trivy Operator VulnerabilityReport objects."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from k8s_sec_mcp.models import (
    EvidenceProvenance,
    ImageIdentity,
    InvalidSourceDataError,
    OwnerReference,
    VulnerabilityEvidence,
    VulnerabilityFinding,
    WorkloadIdentity,
)

API_VERSION = "aquasecurity.github.io/v1alpha1"
KIND = "VulnerabilityReport"
RESOURCE_KIND_LABEL = "trivy-operator.resource.kind"
RESOURCE_NAME_LABEL = "trivy-operator.resource.name"
RESOURCE_NAMESPACE_LABEL = "trivy-operator.resource.namespace"
CONTAINER_NAME_LABEL = "trivy-operator.container.name"
VALID_SEVERITIES = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"}


def parse_vulnerability_report(item: Mapping[str, Any]) -> VulnerabilityEvidence:
    """Normalize one supported Trivy Operator report without guessing identity."""
    if item.get("apiVersion") != API_VERSION or item.get("kind") != KIND:
        raise InvalidSourceDataError("unsupported vulnerability report version")

    metadata = _mapping(item.get("metadata"), "metadata")
    report = _mapping(item.get("report"), "report")
    labels = _mapping(metadata.get("labels", {}), "metadata.labels")
    artifact = _mapping(report.get("artifact"), "report.artifact")
    scanner = _mapping(report.get("scanner", {}), "report.scanner")

    owners = tuple(
        _owner_reference(owner)
        for owner in _list(metadata.get("ownerReferences", []), "ownerReferences")
    )
    controller = next((owner for owner in owners if owner.controller), None)

    workload = WorkloadIdentity(
        namespace=_optional_string(
            labels.get(RESOURCE_NAMESPACE_LABEL, metadata.get("namespace"))
        ),
        kind=_optional_string(
            labels.get(RESOURCE_KIND_LABEL, controller.kind if controller else None)
        ),
        name=_optional_string(
            labels.get(RESOURCE_NAME_LABEL, controller.name if controller else None)
        ),
        uid=controller.uid if controller else None,
        container_name=_optional_string(labels.get(CONTAINER_NAME_LABEL)),
        owner_references=owners,
    )

    findings = tuple(
        _vulnerability(vulnerability)
        for vulnerability in _list(
            report.get("vulnerabilities", []), "report.vulnerabilities"
        )
    )
    return VulnerabilityEvidence(
        provenance=EvidenceProvenance(
            source="trivy-operator",
            api_version=API_VERSION,
            kind=KIND,
            report_name=_optional_string(metadata.get("name")),
            report_namespace=_optional_string(metadata.get("namespace")),
            report_uid=_optional_string(metadata.get("uid")),
            resource_version=_optional_string(metadata.get("resourceVersion")),
            observed_generation=_optional_int(metadata.get("generation")),
            observed_at=_optional_string(
                report.get("updateTimestamp", metadata.get("creationTimestamp"))
            ),
            scanner_name=_optional_string(scanner.get("name")),
            scanner_version=_optional_string(scanner.get("version")),
        ),
        workload=workload,
        image=ImageIdentity(
            repository=_string(artifact.get("repository", ""), "artifact.repository"),
            tag=_string(artifact.get("tag", ""), "artifact.tag"),
            digest=_optional_string(artifact.get("digest")),
        ),
        findings=findings,
    )


def parse_vulnerability_report_list(
    raw: Mapping[str, Any],
) -> list[VulnerabilityEvidence]:
    raw = _mapping(raw, "VulnerabilityReportList")
    return [
        parse_vulnerability_report(item)
        for item in _list(raw.get("items", []), "items")
    ]


def _owner_reference(value: Any) -> OwnerReference:
    owner = _mapping(value, "ownerReference")
    controller = owner.get("controller", False)
    if not isinstance(controller, bool):
        raise InvalidSourceDataError("ownerReference.controller must be boolean")
    return OwnerReference(
        api_version=_optional_string(owner.get("apiVersion")),
        kind=_optional_string(owner.get("kind")),
        name=_optional_string(owner.get("name")),
        uid=_optional_string(owner.get("uid")),
        controller=controller,
    )


def _vulnerability(value: Any) -> VulnerabilityFinding:
    finding = _mapping(value, "vulnerability")
    severity = _string(finding.get("severity", "UNKNOWN"), "severity").upper()
    if severity not in VALID_SEVERITIES:
        severity = "UNKNOWN"
    return VulnerabilityFinding(
        vulnerability_id=_optional_string(finding.get("vulnerabilityID")),
        severity=severity,
        resource=_optional_string(finding.get("resource")),
        installed_version=_optional_string(finding.get("installedVersion")),
        fixed_version=_optional_string(finding.get("fixedVersion")),
        title=_string(finding.get("title", ""), "title"),
    )


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InvalidSourceDataError(f"{field} must be an object")
    return value


def _list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise InvalidSourceDataError(f"{field} must be an array")
    return value


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise InvalidSourceDataError(f"{field} must be a string")
    return value


def _optional_string(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise InvalidSourceDataError("optional identity field must be a string")
    return value


def _optional_int(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise InvalidSourceDataError("generation must be an integer")
    return value

"""Provider-neutral evidence models used between source adapters and MCP tools."""

from __future__ import annotations

from dataclasses import dataclass


class InvalidSourceDataError(ValueError):
    """Raised when upstream evidence cannot satisfy a supported source shape."""


@dataclass(frozen=True)
class OwnerReference:
    api_version: str | None
    kind: str | None
    name: str | None
    uid: str | None
    controller: bool


@dataclass(frozen=True)
class EvidenceProvenance:
    source: str
    api_version: str
    kind: str
    report_name: str | None
    report_namespace: str | None
    report_uid: str | None
    resource_version: str | None
    observed_generation: int | None
    observed_at: str | None
    scanner_name: str | None
    scanner_version: str | None


@dataclass(frozen=True)
class WorkloadIdentity:
    namespace: str | None
    kind: str | None
    name: str | None
    uid: str | None
    container_name: str | None
    owner_references: tuple[OwnerReference, ...]


@dataclass(frozen=True)
class ImageIdentity:
    repository: str
    tag: str
    digest: str | None

    @property
    def legacy_reference(self) -> str:
        """Preserve the Phase 2A image spelling, including an empty tag."""
        return f"{self.repository}:{self.tag}"


@dataclass(frozen=True)
class VulnerabilityFinding:
    vulnerability_id: str | None
    severity: str
    resource: str | None
    installed_version: str | None
    fixed_version: str | None
    title: str


@dataclass(frozen=True)
class VulnerabilityEvidence:
    provenance: EvidenceProvenance
    workload: WorkloadIdentity
    image: ImageIdentity
    findings: tuple[VulnerabilityFinding, ...]

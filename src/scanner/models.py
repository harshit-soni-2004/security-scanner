"""Data model for instances and potential security exposures."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Severity(str, Enum):
    """Configured severity of a potential exposure. Not an exploitability rating."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


SEVERITY_RANK: dict[Severity, int] = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


@dataclass(frozen=True)
class SecurityGroupRef:
    """A security group attached to an instance or one of its network interfaces."""

    group_id: str
    group_name: str


@dataclass(frozen=True)
class Instance:
    """EC2 instance fields the scanner needs. Terminated instances are never included."""

    instance_id: str
    name: str
    instance_type: str
    state: str
    private_ip: str | None
    public_ip: str | None
    ipv6_addresses: tuple[str, ...]
    availability_zone: str
    vpc_id: str | None
    subnet_id: str | None
    security_groups: tuple[SecurityGroupRef, ...]
    team: str
    owner: str
    environment: str

    @property
    def has_public_ip(self) -> bool:
        return bool(self.public_ip)


@dataclass(frozen=True)
class Finding:
    """One potential exposure: a public inbound rule hitting one monitored port."""

    instance_id: str
    instance_name: str
    instance_type: str
    private_ip: str | None
    public_ip: str | None
    security_group_id: str
    security_group_name: str
    port: int
    protocol: str
    source: str
    severity: Severity
    title: str
    description: str
    recommendation: str
    rule_description: str | None
    has_public_ip: bool


@dataclass
class InstanceResult:
    """One scanned instance and its rule-level findings.

    finding_count is the number of rule-level findings.
    unique_exposed_ports is the number of distinct ports among those findings.
    """

    instance: Instance
    findings: list[Finding] = field(default_factory=list)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def unique_exposed_ports(self) -> int:
        return len({finding.port for finding in self.findings})

    @property
    def severity_counts(self) -> dict[Severity, int]:
        counts = {severity: 0 for severity in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1
        return counts

    @property
    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max(
            self.findings, key=lambda finding: SEVERITY_RANK[finding.severity]
        ).severity

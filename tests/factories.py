"""Shared fixtures for scanner tests. No AWS calls."""

from __future__ import annotations

from pathlib import Path

from scanner.config import (
    AppConfig,
    AwsConfig,
    EmailConfig,
    ReportConfig,
    ScannerSettings,
    SeverityConfig,
)
from scanner.models import Instance, SecurityGroupRef, Severity

CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "scanner.yaml"


def make_config(
    *,
    ports: tuple[int, ...] = (22, 80, 443, 3389),
    protocols: tuple[str, ...] = ("tcp",),
    sources: tuple[str, ...] = ("0.0.0.0/0", "::/0"),
    critical: tuple[int, ...] = (22, 3389),
    high: tuple[int, ...] = (80, 443),
    medium: tuple[int, ...] = (),
    low: tuple[int, ...] = (),
    default: Severity = Severity.MEDIUM,
    names: dict[int, str] | None = None,
    region: str = "ap-south-1",
    output_directory: str = "reports",
    formats: tuple[str, ...] = ("html", "csv"),
    overwrite: bool = False,
) -> AppConfig:
    if names is None:
        names = {22: "SSH", 80: "HTTP", 443: "HTTPS", 3389: "RDP"}
    return AppConfig(
        aws=AwsConfig(region=region),
        scanner=ScannerSettings(
            monitored_ports=ports,
            monitored_protocols=protocols,
            source_cidrs=sources,
            include_stopped_instances=False,
            port_names=names,
            severity=SeverityConfig(
                critical_ports=critical,
                high_ports=high,
                medium_ports=medium,
                low_ports=low,
                default_severity=default,
            ),
        ),
        report=ReportConfig(
            output_directory=output_directory,
            formats=formats,
            overwrite_existing=overwrite,
            team_tag_key="Team",
            owner_tag_key="Owner",
            environment_tag_key="Environment",
        ),
        email=EmailConfig(
            enabled=False,
            sender="",
            recipients=(),
            subject_prefix="Daily AWS Security Scan",
        ),
    )


def make_instance(
    instance_id: str = "i-abc",
    name: str = "web",
    groups: tuple[SecurityGroupRef, ...] = (SecurityGroupRef("sg-1", "web"),),
    public_ip: str | None = "203.0.113.10",
    team: str = "platform",
) -> Instance:
    return Instance(
        instance_id=instance_id,
        name=name,
        instance_type="t3.micro",
        state="running",
        private_ip="10.0.0.5",
        public_ip=public_ip,
        ipv6_addresses=(),
        availability_zone="az-a",
        vpc_id="vpc-1",
        subnet_id="subnet-1",
        security_groups=groups,
        team=team,
        owner="owner",
        environment="dev",
    )


def permission(
    protocol: str,
    from_port: int | None,
    to_port: int | None,
    cidrs: list[str] | None = None,
    ipv6: list[str] | None = None,
    description: str | None = None,
    user_group_pairs: list[dict[str, str]] | None = None,
    prefix_lists: list[dict[str, str]] | None = None,
) -> dict[str, object]:
    ip_ranges = []
    for cidr in cidrs or []:
        item: dict[str, str] = {"CidrIp": cidr}
        if description:
            item["Description"] = description
        ip_ranges.append(item)
    ipv6_ranges = []
    for cidr in ipv6 or []:
        item = {"CidrIpv6": cidr}
        if description:
            item["Description"] = description
        ipv6_ranges.append(item)
    rule: dict[str, object] = {
        "IpProtocol": protocol,
        "IpRanges": ip_ranges,
        "Ipv6Ranges": ipv6_ranges,
    }
    if from_port is not None:
        rule["FromPort"] = from_port
    if to_port is not None:
        rule["ToPort"] = to_port
    if user_group_pairs:
        rule["UserIdGroupPairs"] = user_group_pairs
    if prefix_lists:
        rule["PrefixListIds"] = prefix_lists
    return rule


def security_group(
    group_id: str, name: str, rules: list[dict[str, object]]
) -> dict[str, dict[str, object]]:
    return {"GroupId": group_id, "GroupName": name, "IpPermissions": rules}

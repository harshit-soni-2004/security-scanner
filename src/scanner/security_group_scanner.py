"""Match inbound security-group rules against the monitored public sources."""

from __future__ import annotations

from typing import Any

from scanner.config import AppConfig
from scanner.models import Finding, Instance, SecurityGroupRef

# ICMP has no TCP/UDP port range. Prefix lists and security-group references are not public CIDRs.
_IGNORED_PROTOCOLS = {"icmp", "icmpv6", "1", "58"}


def exposures_for_instance(
    instance: Instance,
    security_groups: dict[str, dict[str, Any]],
    config: AppConfig,
) -> list[Finding]:
    """Return one finding per matching instance, group, port, protocol, and source."""

    findings: list[Finding] = []
    for ref in instance.security_groups:
        group = security_groups.get(ref.group_id)
        if not group:
            continue
        group_name = str(group.get("GroupName") or ref.group_name)
        for permission in group.get("IpPermissions", []):
            findings.extend(
                _permission_findings(
                    instance,
                    SecurityGroupRef(ref.group_id, group_name),
                    permission,
                    config,
                )
            )
    return findings


def _permission_findings(
    instance: Instance,
    group: SecurityGroupRef,
    permission: dict[str, Any],
    config: AppConfig,
) -> list[Finding]:
    protocol = _normalize_protocol(permission.get("IpProtocol"))
    if protocol is None:
        return []
    monitored_protocols = set(config.scanner.monitored_protocols)
    if protocol != "all" and protocol not in monitored_protocols:
        return []
    ports = _matching_ports(permission, protocol, set(config.scanner.monitored_ports))
    if not ports:
        return []
    sources = _public_sources(permission, set(config.scanner.source_cidrs))
    findings: list[Finding] = []
    for port in ports:
        for source, rule_description in sources:
            findings.append(
                _build_finding(
                    instance, group, port, protocol, source, rule_description, config
                )
            )
    return findings


def _normalize_protocol(raw: Any) -> str | None:
    value = str(raw or "").strip().lower()
    if value in _IGNORED_PROTOCOLS:
        return None
    if value in {"-1", "all"}:
        return "all"
    if value in {"tcp", "6"}:
        return "tcp"
    if value in {"udp", "17"}:
        return "udp"
    return None


def _matching_ports(
    permission: dict[str, Any], protocol: str, monitored: set[int]
) -> list[int]:
    if protocol == "all":
        return sorted(monitored)
    from_port = permission.get("FromPort")
    to_port = permission.get("ToPort")
    if isinstance(from_port, bool) or isinstance(to_port, bool):
        return []
    if not isinstance(from_port, int) or not isinstance(to_port, int):
        return []
    return sorted(port for port in monitored if from_port <= port <= to_port)


def _public_sources(
    permission: dict[str, Any], source_cidrs: set[str]
) -> list[tuple[str, str | None]]:
    """Exact configured CIDRs only. Broader private ranges and group references are ignored."""

    matches: list[tuple[str, str | None]] = []
    for item in permission.get("IpRanges", []):
        cidr = item.get("CidrIp")
        if isinstance(cidr, str) and cidr in source_cidrs:
            matches.append((cidr, _description(item)))
    for item in permission.get("Ipv6Ranges", []):
        cidr = item.get("CidrIpv6")
        if isinstance(cidr, str) and cidr in source_cidrs:
            matches.append((cidr, _description(item)))
    return matches


def _description(item: dict[str, Any]) -> str | None:
    text = item.get("Description")
    if isinstance(text, str) and text.strip():
        return text.strip()
    return None


def _build_finding(
    instance: Instance,
    group: SecurityGroupRef,
    port: int,
    protocol: str,
    source: str,
    rule_description: str | None,
    config: AppConfig,
) -> Finding:
    severity = config.scanner.severity.for_port(port)
    port_name = config.scanner.port_names.get(port)
    shown_protocol = "all" if protocol == "all" else protocol
    if port_name:
        title = f"Potential public {port_name} exposure"
    else:
        title = f"Public exposure on port {port}"
    description = (
        f"Security group {group.group_name} ({group.group_id}) allows {shown_protocol} "
        f"from {source} to port {port}"
        + (f" ({port_name})" if port_name else "")
        + ". This is a potential security exposure based on the inbound rule."
    )
    if rule_description:
        description += f" Rule description: {rule_description}."
    if not instance.has_public_ip:
        description += (
            " This instance has no public IP, so a public security group rule has lower "
            "reachability from the internet."
        )
    return Finding(
        instance_id=instance.instance_id,
        instance_name=instance.name,
        instance_type=instance.instance_type,
        private_ip=instance.private_ip,
        public_ip=instance.public_ip,
        security_group_id=group.group_id,
        security_group_name=group.group_name,
        port=port,
        protocol=shown_protocol,
        source=source,
        severity=severity,
        title=title,
        description=description,
        recommendation=recommendation_for(port, port_name or f"port {port}"),
        rule_description=rule_description,
        has_public_ip=instance.has_public_ip,
    )


def recommendation_for(port: int, port_name: str) -> str:
    if port == 22:
        return (
            "Restrict public SSH to approved CIDRs or a VPN. Prefer Systems Manager "
            "Session Manager instead of public SSH."
        )
    if port == 3389:
        return (
            "Restrict public RDP to approved CIDRs or a VPN. Prefer Systems Manager "
            "Session Manager instead of public Remote Desktop."
        )
    if port == 80:
        return (
            "Review whether public HTTP is intentional and fronted by a load balancer or WAF. "
            "Otherwise remove the public CIDR from the inbound rule."
        )
    if port == 443:
        return (
            "Review whether public HTTPS is intentional and fronted by a load balancer or WAF. "
            "Otherwise remove the public CIDR from the inbound rule."
        )
    return (
        f"Review the public {port_name} rule. Restrict it to approved CIDRs or a VPN, and "
        "remove 0.0.0.0/0 or ::/0 unless this exposure is approved."
    )

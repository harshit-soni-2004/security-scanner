"""Read-only EC2 and STS inventory. Describe APIs only."""

from __future__ import annotations

import logging
from typing import Any

import boto3
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError, NoCredentialsError

from scanner.models import Instance, SecurityGroupRef

logger = logging.getLogger(__name__)

RETRY_CONFIG = Config(
    retries={"max_attempts": 5, "mode": "standard"},
    connect_timeout=10,
    read_timeout=60,
)
SECURITY_GROUP_BATCH_SIZE = 100
UNKNOWN = "unknown"


def build_clients(region: str) -> tuple[Any, Any]:
    """Create EC2 and STS clients for one region. Credentials come from the environment."""

    session = boto3.Session(region_name=region)
    return (
        session.client("ec2", config=RETRY_CONFIG),
        session.client("sts", config=RETRY_CONFIG),
    )


def get_account_id(sts_client: Any) -> str:
    """Return the caller account, or 'unavailable' when STS cannot be read."""

    try:
        return str(sts_client.get_caller_identity()["Account"])
    except (ClientError, BotoCoreError, NoCredentialsError, KeyError):
        logger.warning(
            "Could not determine the AWS account ID. The report will say unavailable."
        )
        return "unavailable"


def list_instances(
    ec2_client: Any,
    *,
    include_stopped: bool,
    team_tag_key: str,
    owner_tag_key: str,
    environment_tag_key: str,
) -> list[Instance]:
    """Page through DescribeInstances. Terminated instances are excluded by the filter."""

    states = ["running", "stopped"] if include_stopped else ["running"]
    paginator = ec2_client.get_paginator("describe_instances")
    instances: list[Instance] = []
    pages = paginator.paginate(
        Filters=[{"Name": "instance-state-name", "Values": states}]
    )
    for page in pages:
        for reservation in page.get("Reservations", []):
            for raw in reservation.get("Instances", []):
                state = str((raw.get("State") or {}).get("Name") or "")
                if state == "terminated":
                    continue
                instances.append(
                    _parse_instance(
                        raw,
                        team_tag_key=team_tag_key,
                        owner_tag_key=owner_tag_key,
                        environment_tag_key=environment_tag_key,
                    )
                )
    return instances


def fetch_security_groups(
    ec2_client: Any, group_ids: list[str]
) -> dict[str, dict[str, Any]]:
    """Describe each unique security group once, in batches of 100."""

    unique_ids = sorted({group_id for group_id in group_ids if group_id})
    if not unique_ids:
        return {}
    logger.info("Scanning %s security groups", len(unique_ids))
    found: dict[str, dict[str, Any]] = {}
    paginator = ec2_client.get_paginator("describe_security_groups")
    for start in range(0, len(unique_ids), SECURITY_GROUP_BATCH_SIZE):
        batch = unique_ids[start : start + SECURITY_GROUP_BATCH_SIZE]
        for page in paginator.paginate(GroupIds=batch):
            for group in page.get("SecurityGroups", []):
                group_id = group.get("GroupId")
                if group_id:
                    found[group_id] = group
    return found


def _parse_instance(
    raw: dict[str, Any],
    *,
    team_tag_key: str,
    owner_tag_key: str,
    environment_tag_key: str,
) -> Instance:
    tags = _tag_map(raw.get("Tags", []))
    groups = _security_groups(raw)
    ipv6 = _ipv6_addresses(raw)
    placement = raw.get("Placement") or {}
    return Instance(
        instance_id=str(raw.get("InstanceId") or UNKNOWN),
        name=tags.get("Name", UNKNOWN),
        instance_type=str(raw.get("InstanceType") or UNKNOWN),
        state=str((raw.get("State") or {}).get("Name") or UNKNOWN),
        private_ip=raw.get("PrivateIpAddress"),
        public_ip=raw.get("PublicIpAddress"),
        ipv6_addresses=tuple(ipv6),
        availability_zone=str(placement.get("AvailabilityZone") or UNKNOWN),
        vpc_id=raw.get("VpcId"),
        subnet_id=raw.get("SubnetId"),
        security_groups=tuple(groups),
        team=tags.get(team_tag_key, UNKNOWN),
        owner=tags.get(owner_tag_key, UNKNOWN),
        environment=tags.get(environment_tag_key, UNKNOWN),
    )


def _tag_map(tags: list[dict[str, Any]]) -> dict[str, str]:
    return {
        str(tag.get("Key")): str(tag.get("Value"))
        for tag in tags
        if tag.get("Key") is not None and tag.get("Value") is not None
    }


def _security_groups(raw: dict[str, Any]) -> list[SecurityGroupRef]:
    """Union of instance-level groups and groups on every network interface."""

    seen: dict[str, str] = {}
    for group in raw.get("SecurityGroups", []):
        group_id = group.get("GroupId")
        if group_id:
            seen[str(group_id)] = str(group.get("GroupName") or group_id)
    for interface in raw.get("NetworkInterfaces", []):
        for group in interface.get("Groups", []):
            group_id = group.get("GroupId")
            if group_id and str(group_id) not in seen:
                seen[str(group_id)] = str(group.get("GroupName") or group_id)
    return [SecurityGroupRef(group_id, name) for group_id, name in sorted(seen.items())]


def _ipv6_addresses(raw: dict[str, Any]) -> list[str]:
    addresses: list[str] = []
    for interface in raw.get("NetworkInterfaces", []):
        for item in interface.get("Ipv6Addresses", []):
            address = item.get("Ipv6Address")
            if address:
                addresses.append(str(address))
    return addresses

"""Inventory parsing with mocked paginators. No AWS calls."""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError

from scanner.aws_inventory import fetch_security_groups, get_account_id, list_instances


def test_pagination_and_running_filter() -> None:
    ec2 = MagicMock()
    paginator = MagicMock()
    ec2.get_paginator.return_value = paginator
    paginator.paginate.return_value = [
        {"Reservations": [{"Instances": [_raw("i-1")]}]},
        {
            "Reservations": [
                {"Instances": [_raw("i-2"), _raw("i-term", state="terminated")]}
            ]
        },
    ]
    instances = list_instances(
        ec2,
        include_stopped=False,
        team_tag_key="Team",
        owner_tag_key="Owner",
        environment_tag_key="Environment",
    )
    assert [item.instance_id for item in instances] == ["i-1", "i-2"]
    paginator.paginate.assert_called_once_with(
        Filters=[{"Name": "instance-state-name", "Values": ["running"]}]
    )


def test_stopped_instances_included_when_configured() -> None:
    ec2 = MagicMock()
    paginator = MagicMock()
    ec2.get_paginator.return_value = paginator
    paginator.paginate.return_value = []
    list_instances(
        ec2,
        include_stopped=True,
        team_tag_key="Team",
        owner_tag_key="Owner",
        environment_tag_key="Environment",
    )
    paginator.paginate.assert_called_once_with(
        Filters=[{"Name": "instance-state-name", "Values": ["running", "stopped"]}]
    )


def test_multi_eni_groups_and_unknown_tags() -> None:
    raw = _raw("i-eni")
    raw["Tags"] = []
    raw["SecurityGroups"] = [{"GroupId": "sg-a", "GroupName": "alpha"}]
    raw["NetworkInterfaces"] = [
        {
            "Groups": [
                {"GroupId": "sg-a", "GroupName": "alpha"},
                {"GroupId": "sg-b", "GroupName": "beta"},
            ],
            "Ipv6Addresses": [{"Ipv6Address": "2001:db8::1"}],
        }
    ]
    ec2 = MagicMock()
    paginator = MagicMock()
    ec2.get_paginator.return_value = paginator
    paginator.paginate.return_value = [{"Reservations": [{"Instances": [raw]}]}]
    instance = list_instances(
        ec2,
        include_stopped=False,
        team_tag_key="Team",
        owner_tag_key="Owner",
        environment_tag_key="Environment",
    )[0]
    assert [ref.group_id for ref in instance.security_groups] == ["sg-a", "sg-b"]
    assert instance.name == "unknown"
    assert instance.team == "unknown"
    assert instance.ipv6_addresses == ("2001:db8::1",)


def test_security_group_cache_batches_unique_ids() -> None:
    calls: list[list[str]] = []

    class Paginator:
        def paginate(self, GroupIds: list[str]):
            calls.append(list(GroupIds))
            return [
                {
                    "SecurityGroups": [
                        {"GroupId": group_id, "GroupName": group_id}
                        for group_id in GroupIds
                    ]
                }
            ]

    ec2 = MagicMock()
    ec2.get_paginator.return_value = Paginator()
    ids = [f"sg-{index:03d}" for index in range(101)]
    found = fetch_security_groups(ec2, ids + ["sg-000"])
    assert len(calls) == 2
    assert len(calls[0]) == 100
    assert calls[1] == ["sg-100"]
    assert len(found) == 101


def test_account_id_failure_is_unavailable() -> None:
    sts = MagicMock()
    sts.get_caller_identity.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetCallerIdentity"
    )
    assert get_account_id(sts) == "unavailable"


def _raw(instance_id: str, state: str = "running") -> dict:
    return {
        "InstanceId": instance_id,
        "InstanceType": "t3.micro",
        "State": {"Name": state},
        "PrivateIpAddress": "10.0.0.5",
        "PublicIpAddress": "203.0.113.10",
        "Placement": {"AvailabilityZone": "az-a"},
        "VpcId": "vpc-1",
        "SubnetId": "subnet-1",
        "SecurityGroups": [{"GroupId": "sg-1", "GroupName": "web"}],
        "NetworkInterfaces": [],
        "Tags": [
            {"Key": "Name", "Value": "box"},
            {"Key": "Team", "Value": "platform"},
            {"Key": "Owner", "Value": "ada"},
            {"Key": "Environment", "Value": "dev"},
        ],
    }

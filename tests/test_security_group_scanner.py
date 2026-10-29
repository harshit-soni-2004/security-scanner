"""Security group rule matching."""

from factories import make_config, make_instance, permission, security_group

from scanner.models import SecurityGroupRef, Severity
from scanner.vulnerability_analyzer import analyze


def test_single_public_monitored_port() -> None:
    findings = _findings(
        [permission("tcp", 22, 22, ["0.0.0.0/0"], description="admin")]
    )
    assert len(findings) == 1
    assert findings[0].port == 22
    assert findings[0].protocol == "tcp"
    assert findings[0].severity.value == "CRITICAL"
    assert findings[0].rule_description == "admin"
    assert findings[0].title == "Potential public SSH exposure"


def test_non_monitored_port_is_ignored() -> None:
    findings = _findings([permission("tcp", 25, 25, ["0.0.0.0/0"])])
    assert findings == []


def test_range_keeps_only_monitored_ports() -> None:
    config = make_config(ports=(22, 25, 80), names={22: "SSH", 25: "SMTP", 80: "HTTP"})
    findings = _findings([permission("tcp", 20, 30, ["0.0.0.0/0"])], config=config)
    assert [item.port for item in findings] == [22, 25]


def test_range_outside_monitored_ports() -> None:
    findings = _findings([permission("tcp", 1000, 1001, ["0.0.0.0/0"])])
    assert findings == []


def test_all_protocol_emits_each_monitored_port() -> None:
    config = make_config(ports=(22, 80, 443))
    findings = _findings([permission("-1", None, None, ["0.0.0.0/0"])], config=config)
    assert [item.port for item in findings] == [22, 80, 443]
    assert {item.protocol for item in findings} == {"all"}


def test_ipv6_public_source() -> None:
    findings = _findings([permission("tcp", 443, 443, ipv6=["::/0"])])
    assert len(findings) == 1
    assert findings[0].source == "::/0"
    assert findings[0].severity.value == "HIGH"


def test_private_cidr_security_group_and_prefix_list_are_ignored() -> None:
    findings = _findings(
        [
            permission("tcp", 22, 22, ["10.0.0.0/8"]),
            permission(
                "tcp",
                22,
                22,
                user_group_pairs=[{"GroupId": "sg-other"}],
            ),
            permission("tcp", 22, 22, prefix_lists=[{"PrefixListId": "pl-1"}]),
        ]
    )
    assert findings == []


def test_udp_ignored_unless_monitored_and_numeric_protocols() -> None:
    assert _findings([permission("udp", 22, 22, ["0.0.0.0/0"])]) == []
    udp_config = make_config(protocols=("udp",))
    udp_findings = _findings(
        [permission("17", 22, 22, ["0.0.0.0/0"])], config=udp_config
    )
    assert len(udp_findings) == 1
    assert udp_findings[0].protocol == "udp"
    tcp_findings = _findings([permission("6", 80, 80, ["0.0.0.0/0"])])
    assert tcp_findings[0].protocol == "tcp"


def test_icmp_is_ignored() -> None:
    assert _findings([permission("icmp", None, None, ["0.0.0.0/0"])]) == []


def test_two_security_groups_keep_both_findings() -> None:
    instance = make_instance(
        groups=(SecurityGroupRef("sg-1", "one"), SecurityGroupRef("sg-2", "two"))
    )
    groups = {
        "sg-1": security_group(
            "sg-1", "one", [permission("tcp", 22, 22, ["0.0.0.0/0"])]
        ),
        "sg-2": security_group(
            "sg-2", "two", [permission("tcp", 22, 22, ["0.0.0.0/0"])]
        ),
    }
    findings = analyze([instance], groups, make_config())[0].findings
    assert len(findings) == 2
    assert {item.security_group_id for item in findings} == {"sg-1", "sg-2"}


def test_default_severity_and_fallback_title() -> None:
    config = make_config(
        ports=(25,), names={}, critical=(), high=(), default=Severity.LOW
    )
    findings = _findings([permission("tcp", 25, 25, ["0.0.0.0/0"])], config=config)
    assert findings[0].severity.value == "LOW"
    assert findings[0].title == "Public exposure on port 25"


def _findings(rules, config=None):
    config = config or make_config()
    instance = make_instance()
    groups = {"sg-1": security_group("sg-1", "web", rules)}
    return analyze([instance], groups, config)[0].findings

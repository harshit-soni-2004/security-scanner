"""Report content, escaping, and file names."""

from datetime import datetime, timezone

from factories import make_config, make_instance, permission, security_group

from scanner.models import Finding, Instance, InstanceResult, SecurityGroupRef, Severity
from scanner.report_generator import (
    ScanMetadata,
    render_csv,
    render_html,
    write_reports,
)
from scanner.vulnerability_analyzer import analyze


def test_csv_header_when_empty() -> None:
    text = render_csv([], _metadata())
    assert text.splitlines() == [
        (
            "Report Date,AWS Region,Instance ID,Instance Name,Instance Type,Private IP,Public IP,"
            "Security Group ID,Security Group Name,Port,Protocol,Source CIDR,Severity,Finding,"
            "Description,Recommendation"
        )
    ]


def test_csv_formula_injection_is_neutralized() -> None:
    result = InstanceResult(
        instance=make_instance(name="=cmd"),
        findings=[
            Finding(
                instance_id="i-abc",
                instance_name="=cmd",
                instance_type="+type",
                private_ip="-10",
                public_ip="@ip",
                security_group_id="sg-1",
                security_group_name="web",
                port=22,
                protocol="tcp",
                source="0.0.0.0/0",
                severity=Severity.CRITICAL,
                title="Potential public SSH exposure",
                description="desc",
                recommendation="restrict",
                rule_description=None,
                has_public_ip=True,
            )
        ],
    )
    text = render_csv([result], _metadata())
    assert "'=cmd" in text
    assert "'+type" in text
    assert "'-10" in text
    assert "'@ip" in text


def test_html_sections_and_escaping() -> None:
    instance = make_instance(name="<script>alert(1)</script>")
    groups = {
        "sg-1": security_group(
            "sg-1", "web", [permission("tcp", 22, 22, ["0.0.0.0/0"])]
        )
    }
    clean = make_instance(
        instance_id="i-clean", name="quiet", public_ip=None, groups=()
    )
    results = analyze([instance, clean], groups, make_config())
    html = render_html(results, _metadata())
    assert "Weekly AWS EC2 Security Exposure Report" in html
    assert "Executive Summary" in html
    assert "Security Posture" in html
    assert "Instance Summary" in html
    assert "Detailed Findings" in html
    assert "Instances With No Monitored Exposures" in html
    assert "Recommended Actions" in html
    assert "max-width: 1400px" in html
    assert "No Findings" in html
    assert "does not prove that an instance is exploitable." in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert "CRITICAL" in html


def test_known_finding_text_is_preserved() -> None:
    instance = Instance(
        instance_id="i-00529c1eb77f1f1aa",
        name="for_instance_01",
        instance_type="t3.micro",
        state="running",
        private_ip="172.31.0.10",
        public_ip="203.0.113.20",
        ipv6_addresses=(),
        availability_zone="ap-south-1a",
        vpc_id="vpc-1",
        subnet_id="subnet-1",
        security_groups=(SecurityGroupRef("sg-0fb1a2521d551ec13", "launch-wizard-1"),),
        team="unknown",
        owner="unknown",
        environment="unknown",
    )
    finding = Finding(
        instance_id=instance.instance_id,
        instance_name=instance.name,
        instance_type=instance.instance_type,
        private_ip=instance.private_ip,
        public_ip=instance.public_ip,
        security_group_id="sg-0fb1a2521d551ec13",
        security_group_name="launch-wizard-1",
        port=22,
        protocol="tcp",
        source="0.0.0.0/0",
        severity=Severity.CRITICAL,
        title="Potential public SSH exposure",
        description="Potential security exposure on TCP 22 from 0.0.0.0/0.",
        recommendation="Restrict public SSH.",
        rule_description=None,
        has_public_ip=True,
    )
    html = render_html([InstanceResult(instance, [finding])], _metadata())
    for value in (
        "for_instance_01",
        "i-00529c1eb77f1f1aa",
        "launch-wizard-1",
        "sg-0fb1a2521d551ec13",
        "0.0.0.0/0",
        "CRITICAL",
        "22",
    ):
        assert value in html


def test_timestamped_directory_contains_html_and_csv(tmp_path) -> None:
    when = datetime(2026, 10, 5, 18, 30, tzinfo=timezone.utc)
    written = write_reports(
        make_config(output_directory=str(tmp_path), formats=("html", "csv")),
        [],
        _metadata(when),
    )
    directory = tmp_path / "2026-10-05-18-30-report"
    assert directory.is_dir()
    names = {path.name for path in written}
    assert names == {"weekly-security-report.html", "weekly-security-findings.csv"}
    assert all(path.parent == directory for path in written)
    assert "Weekly AWS EC2 Security Exposure Report" in (
        directory / "weekly-security-report.html"
    ).read_text(encoding="utf-8")


def test_directory_name_uses_utc(tmp_path) -> None:
    from datetime import timedelta

    local = datetime(
        2026, 10, 5, 23, 45, tzinfo=timezone(timedelta(hours=5, minutes=30))
    )
    written = write_reports(
        make_config(output_directory=str(tmp_path), formats=("csv",)),
        [],
        _metadata(local),
    )
    assert written[0].parent.name == "2026-10-05-18-15-report"
    assert written[0].name == "weekly-security-findings.csv"


def test_existing_report_is_not_overwritten(tmp_path) -> None:
    when = datetime(2026, 10, 5, 18, 30, 15, tzinfo=timezone.utc)
    metadata = _metadata(when)
    config = make_config(
        output_directory=str(tmp_path), formats=("html",), overwrite=False
    )
    first = write_reports(config, [], metadata)
    second = write_reports(config, [], metadata)
    assert first[0].parent.name == "2026-10-05-18-30-report"
    assert first[0].name == "weekly-security-report.html"
    assert second[0].parent.name == "2026-10-05-18-30-report-183015"
    assert second[0].name == "weekly-security-report.html"
    assert first[0].read_text(encoding="utf-8")
    assert "2026-10-05-18-30-report.csv" not in {
        path.name for path in tmp_path.rglob("*")
    }


def _metadata(when: datetime | None = None) -> ScanMetadata:
    return ScanMetadata(
        generated_at=when or datetime(2026, 10, 5, tzinfo=timezone.utc),
        region="ap-south-1",
        account_id="unavailable",
        scanner_version="0.1.0",
        scope="Running EC2 instances; security group inbound rules.",
        demo=False,
    )

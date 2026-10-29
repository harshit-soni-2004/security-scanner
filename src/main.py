"""Command-line entry point. Read-only against AWS. Non-interactive."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path

from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
)

from scanner import __version__
from scanner.aws_inventory import (
    build_clients,
    fetch_security_groups,
    get_account_id,
    list_instances,
)
from scanner.config import AppConfig, ConfigError, apply_email_environment, load_config
from scanner.models import SEVERITY_RANK, InstanceResult, SecurityGroupRef
from scanner.report_generator import ScanMetadata, write_reports
from scanner.vulnerability_analyzer import analyze

logger = logging.getLogger(__name__)

AUTH_ERROR_CODES = {
    "UnauthorizedOperation",
    "AuthFailure",
    "AccessDenied",
    "AccessDeniedException",
    "ExpiredToken",
    "ExpiredTokenException",
    "InvalidClientTokenId",
    "UnrecognizedClientException",
}
FAIL_ON_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    logging.basicConfig(
        level=getattr(logging, args.log_level), format="%(levelname)s %(message)s"
    )
    try:
        config, warnings = load_config(args.config)
        config = _apply_overrides(config, args)
    except ConfigError as exc:
        logger.error("%s", exc)
        return 2
    for warning in warnings:
        logger.warning("%s", warning)
    if args.validate_config:
        logger.info("Configuration is valid.")
        return 0
    if args.preview_email and args.send_email:
        logger.error("Use either --preview-email or --send-email, not both.")
        return 2
    if args.preview_email and not args.demo:
        logger.error(
            "--preview-email requires --demo. It writes the email locally and does not call AWS or SES."
        )
        return 2
    if args.send_email and not args.demo:
        logger.error("--send-email requires --demo. A normal scan does not send email.")
        return 2
    try:
        if args.demo:
            results, account_id = _demo_scan(config)
        else:
            results, account_id = _aws_scan(config)
        paths, metadata = _write(config, results, account_id, demo=args.demo)
        if args.preview_email:
            preview_error = _write_email_preview(config, results, metadata, paths)
            if preview_error is not None:
                return preview_error
        if args.send_email:
            send_error = _send_demo_email(config, results, metadata, paths)
            if send_error is not None:
                return send_error
    except NoCredentialsError:
        logger.error(
            "AWS credentials were not found. Use AWS_PROFILE or another standard credential source."
        )
        return 3
    except EndpointConnectionError as exc:
        logger.error("Could not connect to AWS in the selected region: %s", exc)
        return 4
    except ClientError as exc:
        return _client_error_exit(exc)
    except BotoCoreError as exc:
        logger.error("AWS request failed: %s", exc)
        return 4
    except Exception:
        logger.exception("Unexpected error")
        return 1
    logger.info("Completed")
    return findings_exit_code(results, args.fail_on)


def findings_exit_code(results: list[InstanceResult], fail_on: str | None) -> int:
    """Return 5 when a finding is at or above the optional threshold. Default is 0."""

    if not fail_on:
        return 0
    threshold = FAIL_ON_RANK[fail_on]
    for result in results:
        for finding in result.findings:
            if SEVERITY_RANK[finding.severity] >= threshold:
                logger.error(
                    "Findings at or above %s. Exiting 5 because --fail-on %s was set.",
                    finding.severity.value,
                    fail_on,
                )
                return 5
    return 0


def client_error_code(exc: ClientError) -> int:
    code = str(exc.response.get("Error", {}).get("Code", ""))
    message = str(exc.response.get("Error", {}).get("Message", ""))
    if code in AUTH_ERROR_CODES:
        return 3
    if code == "OptInRequired" or "region" in message.lower():
        return 4
    return 4


def _client_error_exit(exc: ClientError) -> int:
    code = str(exc.response.get("Error", {}).get("Code", "Unknown"))
    message = str(exc.response.get("Error", {}).get("Message", ""))
    exit_code = client_error_code(exc)
    if exit_code == 3:
        logger.error("AWS authorization failed (%s): %s", code, message)
    else:
        logger.error("AWS API error (%s): %s", code, message)
    return exit_code


def _aws_scan(config: AppConfig) -> tuple[list[InstanceResult], str]:
    logger.info("Starting EC2 security exposure scan")
    logger.info("Region: %s", config.aws.region)
    ec2_client, sts_client = build_clients(config.aws.region)
    account_id = get_account_id(sts_client)
    instances = list_instances(
        ec2_client,
        include_stopped=config.scanner.include_stopped_instances,
        team_tag_key=config.report.team_tag_key,
        owner_tag_key=config.report.owner_tag_key,
        environment_tag_key=config.report.environment_tag_key,
    )
    logger.info("Instances in scope: %s", len(instances))
    if not instances:
        logger.warning("No instances matched the scan scope.")
    group_ids = [
        ref.group_id for instance in instances for ref in instance.security_groups
    ]
    groups = fetch_security_groups(ec2_client, group_ids)
    results = analyze(instances, groups, config)
    logger.info("Findings: %s", sum(result.finding_count for result in results))
    return results, account_id


def execute_scan(
    config: AppConfig,
) -> tuple[list[InstanceResult], str, list[Path], ScanMetadata]:
    """Run the read-only AWS scan and write reports. Callers choose the output directory."""

    results, account_id = _aws_scan(config)
    paths, metadata = _write(config, results, account_id, demo=False)
    return results, account_id, paths, metadata


def _write(
    config: AppConfig, results: list[InstanceResult], account_id: str, *, demo: bool
) -> tuple[list[Path], ScanMetadata]:
    logger.info("Generating reports")
    scope = (
        "Running and stopped EC2 instances; security group inbound rules; "
        "configured public IPv4 and IPv6 sources."
        if config.scanner.include_stopped_instances
        else (
            "Running EC2 instances; security group inbound rules; "
            "configured public IPv4 and IPv6 sources."
        )
    )
    metadata = ScanMetadata(
        generated_at=datetime.now(timezone.utc),
        region=config.aws.region,
        account_id=account_id,
        scanner_version=__version__,
        scope=scope,
        demo=demo,
    )
    paths = write_reports(config, results, metadata)
    for path in paths:
        logger.info("Wrote %s", path)
    return paths, metadata


def _write_email_preview(
    config: AppConfig,
    results: list[InstanceResult],
    metadata: ScanMetadata,
    paths: list[Path],
) -> int | None:
    """Build the SES message from the demo reports and save it. Returns an exit code on failure."""

    from scanner.email_reporter import write_email_preview

    try:
        write_email_preview(
            apply_email_environment(config),
            results,
            metadata,
            paths,
            paths[0].parent,
        )
    except ConfigError as exc:
        logger.error("%s", exc)
        return 2
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 2
    return None


def _send_demo_email(
    config: AppConfig,
    results: list[InstanceResult],
    metadata: ScanMetadata,
    paths: list[Path],
) -> int | None:
    """Send the demo report with the existing SES sender. Returns an exit code on failure."""

    from scanner.email_reporter import send_scan_email

    logger.info("Demo scan complete. Sending the report with SES SendRawEmail.")
    try:
        message_id = send_scan_email(
            apply_email_environment(config), results, metadata, paths
        )
    except ConfigError as exc:
        logger.error("%s", exc)
        return 2
    except FileNotFoundError as exc:
        logger.error("%s", exc)
        return 2
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", "Unknown"))
        message = str(exc.response.get("Error", {}).get("Message", ""))
        logger.error("SES rejected the email (%s): %s", code, message)
        return 4
    logger.info("SES send succeeded. MessageId=%s", message_id)
    return None


def _demo_scan(config: AppConfig) -> tuple[list[InstanceResult], str]:
    """Build a labelled fictional report. This function does not call AWS."""

    logger.info("Starting demo mode. No AWS calls will be made.")
    from scanner.models import Instance

    config = _demo_config_with_medium(config)

    exposed = Instance(
        instance_id="i-demo0000000000001",
        name="demo-web",
        instance_type="t3.micro",
        state="running",
        private_ip="10.0.1.10",
        public_ip="203.0.113.10",
        ipv6_addresses=(),
        availability_zone="demo-az-a",
        vpc_id="vpc-demo0001",
        subnet_id="subnet-demo0001",
        security_groups=(SecurityGroupRef("sg-demo0001", "demo-public"),),
        team="platform",
        owner="demo-owner",
        environment="dev",
    )
    clean = Instance(
        instance_id="i-demo0000000000002",
        name="demo-app",
        instance_type="t3.micro",
        state="running",
        private_ip="10.0.2.20",
        public_ip=None,
        ipv6_addresses=(),
        availability_zone="demo-az-b",
        vpc_id="vpc-demo0001",
        subnet_id="subnet-demo0002",
        security_groups=(SecurityGroupRef("sg-demo0002", "demo-private"),),
        team="platform",
        owner="demo-owner",
        environment="dev",
    )
    groups = {
        "sg-demo0001": {
            "GroupId": "sg-demo0001",
            "GroupName": "demo-public",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "demo ssh"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 80,
                    "ToPort": 80,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "demo http"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0", "Description": "demo https"}],
                },
                {
                    "IpProtocol": "tcp",
                    "FromPort": 8080,
                    "ToPort": 8080,
                    "IpRanges": [
                        {"CidrIp": "0.0.0.0/0", "Description": "demo alt http"}
                    ],
                },
            ],
        },
        "sg-demo0002": {
            "GroupId": "sg-demo0002",
            "GroupName": "demo-private",
            "IpPermissions": [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                }
            ],
        },
    }
    results = analyze([exposed, clean], groups, config)
    logger.info("Findings: %s", sum(result.finding_count for result in results))
    return results, "000000000000"


def _demo_config_with_medium(config: AppConfig) -> AppConfig:
    """Add one demo-only port so default MEDIUM formatting can be reviewed.

    Real scans keep the configured monitored ports. This change is not written back.
    """

    from dataclasses import replace

    from scanner.models import Severity

    if any(
        config.scanner.severity.for_port(port) is Severity.MEDIUM
        for port in config.scanner.monitored_ports
    ):
        return config
    names = dict(config.scanner.port_names)
    names.setdefault(8080, "Alt-HTTP")
    scanner = replace(
        config.scanner,
        monitored_ports=config.scanner.monitored_ports + (8080,),
        port_names=names,
    )
    return replace(config, scanner=scanner)


def _apply_overrides(config: AppConfig, args: argparse.Namespace) -> AppConfig:
    from dataclasses import replace

    from scanner.config import ALLOWED_FORMATS, AwsConfig

    aws = config.aws
    report = config.report
    if args.region is not None:
        region = args.region.strip()
        if not region:
            raise ConfigError("--region must be a non-empty string.")
        aws = AwsConfig(region=region)
    if args.output_dir is not None:
        if not args.output_dir.strip():
            raise ConfigError("--output-dir must be a non-empty path.")
        report = replace(report, output_directory=args.output_dir.strip())
    if args.formats is not None:
        formats = tuple(
            item.strip().lower() for item in args.formats.split(",") if item.strip()
        )
        if not formats or any(item not in ALLOWED_FORMATS for item in formats):
            raise ConfigError(
                "--formats must be a comma-separated list of html, csv, xlsx, or json."
            )
        report = replace(report, formats=formats)
    if aws is config.aws and report is config.report:
        return config
    return replace(config, aws=aws, report=report)


def _parse_args(argv: list[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Read-only EC2 security exposure scanner. It does not modify AWS resources."
    )
    parser.add_argument(
        "--config", default="config/scanner.yaml", help="Path to scanner.yaml"
    )
    parser.add_argument(
        "--region", help="AWS region override. No AWS call is made for this flag alone."
    )
    parser.add_argument("--output-dir", help="Report directory override")
    parser.add_argument(
        "--formats", help="Comma-separated formats: html, csv, xlsx, json"
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
    )
    parser.add_argument(
        "--validate-config",
        action="store_true",
        help="Validate the config and exit. Does not call AWS.",
    )
    parser.add_argument(
        "--demo",
        action="store_true",
        help="Write a report from fictional data. Does not call EC2 or STS.",
    )
    parser.add_argument(
        "--preview-email",
        action="store_true",
        help=(
            "With --demo, write email-preview.eml and email-preview.html beside the reports. "
            "Does not call AWS or SES. Sender and recipients come from the email environment variables."
        ),
    )
    parser.add_argument(
        "--send-email",
        action="store_true",
        help=(
            "With --demo, send the report through the existing SES sender. "
            "Uses SECURITY_SCANNER_EMAIL_SENDER, SECURITY_SCANNER_EMAIL_RECIPIENTS, "
            "and SECURITY_SCANNER_EMAIL_ENABLED. Does not call EC2 or STS."
        ),
    )
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low"],
        help="Exit 5 when a finding is at or above this severity. Default: do not fail on findings.",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())

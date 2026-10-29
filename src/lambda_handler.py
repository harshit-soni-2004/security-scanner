"""AWS Lambda entry point. EventBridge and scheduling are configured outside this repository."""

from __future__ import annotations

import logging
import os
from dataclasses import replace
from pathlib import Path
from typing import Any

from main import execute_scan
from scanner.config import apply_email_environment, load_config, require_email_delivery
from scanner.models import InstanceResult

logger = logging.getLogger(__name__)

DEFAULT_CONFIG = Path(__file__).resolve().parents[1] / "config" / "scanner.yaml"
LAMBDA_OUTPUT_DIR = "/tmp/security-reports"
LAMBDA_FORMATS = ("html", "xlsx", "csv")


def lambda_handler(event: Any, context: Any) -> dict[str, Any]:
    """Scan one region, write reports under /tmp, and send them with SES.

    A scan, report, or email failure raises and fails the Lambda invocation.
    This function does not schedule itself.
    """

    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    logger.info("Security scanner Lambda invocation started")
    config_path = os.environ.get("SECURITY_SCANNER_CONFIG", str(DEFAULT_CONFIG))
    config, warnings = load_config(config_path)
    for warning in warnings:
        logger.warning("%s", warning)
    config = _lambda_config(config, event)
    require_email_delivery(config)
    logger.info("Scan region: %s", config.aws.region)
    logger.info("Report directory: %s", config.report.output_directory)
    results, _account_id, paths, metadata = execute_scan(config)
    findings_count = sum(result.finding_count for result in results)
    logger.info("Instances scanned: %s", len(results))
    logger.info("Findings: %s", findings_count)
    message_id = send_email(config, results, metadata, paths)
    names = [path.name for path in paths]
    logger.info("Reports generated: %s", ", ".join(names))
    return {
        "status": "ok",
        "scan_timestamp": metadata.generated_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "region": metadata.region,
        "instances_scanned": len(results),
        "findings_count": findings_count,
        "reports_generated": names,
        "email_delivery_status": "sent",
        "message_id": message_id,
    }


def send_email(config, results: list[InstanceResult], metadata, paths):
    from scanner.email_reporter import send_scan_email

    return send_scan_email(config, results, metadata, paths)


def _lambda_config(config, event: Any):
    from scanner.config import AwsConfig

    region = _region(config.aws.region, event)
    output_directory = os.environ.get("SECURITY_SCANNER_OUTPUT_DIR", LAMBDA_OUTPUT_DIR)
    updated = replace(
        config,
        aws=AwsConfig(region=region),
        report=replace(
            config.report,
            output_directory=output_directory,
            formats=LAMBDA_FORMATS,
        ),
    )
    return apply_email_environment(updated)


def _region(configured: str, event: Any) -> str:
    if isinstance(event, dict):
        value = event.get("region")
        if isinstance(value, str) and value.strip():
            return value.strip()
    for name in ("AWS_REGION", "AWS_DEFAULT_REGION"):
        value = os.environ.get(name, "").strip()
        if value:
            return value
    return configured

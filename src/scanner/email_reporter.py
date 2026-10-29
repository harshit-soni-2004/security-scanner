"""Send the generated reports with SES SendRawEmail. No third-party mail services."""

from __future__ import annotations

import logging
from email.mime.application import MIMEApplication
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

from scanner.config import AppConfig, require_email_delivery
from scanner.models import InstanceResult, Severity
from scanner.report_generator import ScanMetadata

logger = logging.getLogger(__name__)

ATTACHMENT_NAMES = (
    "weekly-security-report.html",
    "weekly-security-report.xlsx",
    "weekly-security-findings.csv",
)


def write_email_preview(
    config: AppConfig,
    results: list[InstanceResult],
    metadata: ScanMetadata,
    report_paths: list[Path],
    output_directory: Path,
) -> Path:
    """Write the SES message to disk for local inspection. Does not call AWS or SES."""

    require_email_delivery(config)
    attachments = _required_attachments(report_paths)
    message = _build_message(config, results, metadata, attachments)
    output_directory.mkdir(parents=True, exist_ok=True)
    eml_path = output_directory / "email-preview.eml"
    eml_path.write_bytes(message.as_bytes())
    html_path = output_directory / "email-preview.html"
    html_path.write_text(_preview_page(message), encoding="utf-8")
    logger.info("Wrote email preview %s", eml_path)
    logger.info("Wrote email preview %s", html_path)
    return eml_path


def send_scan_email(
    config: AppConfig,
    results: list[InstanceResult],
    metadata: ScanMetadata,
    report_paths: list[Path],
    ses_client: object | None = None,
) -> str:
    """Email the HTML report and attach HTML, XLSX, and CSV. Returns the SES message id."""

    require_email_delivery(config)
    attachments = _required_attachments(report_paths)
    message = _build_message(config, results, metadata, attachments)
    client = (
        ses_client
        if ses_client is not None
        else boto3.client("ses", region_name=config.aws.region)
    )
    try:
        response = client.send_raw_email(
            Source=config.email.sender,
            Destinations=list(config.email.recipients),
            RawMessage={"Data": message.as_string()},
        )
    except ClientError as exc:
        code = str(exc.response.get("Error", {}).get("Code", "Unknown"))
        logger.error("SES send failed (%s).", code)
        raise
    message_id = str(response.get("MessageId", ""))
    logger.info(
        "SES email sent to %s recipient(s). MessageId=%s",
        len(config.email.recipients),
        message_id,
    )
    return message_id


def _required_attachments(report_paths: list[Path]) -> dict[str, Path]:
    by_name = {path.name: path for path in report_paths}
    missing = [name for name in ATTACHMENT_NAMES if name not in by_name]
    if missing:
        names = ", ".join(missing)
        raise FileNotFoundError(
            f"Cannot email the report. Missing generated file(s): {names}."
        )
    return {name: by_name[name] for name in ATTACHMENT_NAMES}


def _build_message(
    config: AppConfig,
    results: list[InstanceResult],
    metadata: ScanMetadata,
    attachments: dict[str, Path],
) -> MIMEMultipart:
    when = metadata.generated_at
    report_date = when.strftime("%Y-%m-%d")
    message = MIMEMultipart("mixed")
    message["Subject"] = f"{config.email.subject_prefix} - {report_date}"
    message["From"] = config.email.sender
    message["To"] = ", ".join(config.email.recipients)

    html_report = attachments["weekly-security-report.html"].read_text(encoding="utf-8")
    summary = _summary_html(results, metadata)
    body = MIMEMultipart("alternative")
    body.attach(MIMEText(_summary_text(results, metadata), "plain", "utf-8"))
    body.attach(MIMEText(_html_with_summary(html_report, summary), "html", "utf-8"))
    message.attach(body)

    for name in ATTACHMENT_NAMES:
        payload = attachments[name].read_bytes()
        part = MIMEApplication(payload, Name=name)
        part.add_header("Content-Disposition", "attachment", filename=name)
        message.attach(part)
    return message


def _preview_page(message: MIMEMultipart) -> str:
    """Browser view of the same HTML body, with the message headers shown above it."""

    html_body = ""
    for part in message.walk():
        if part.get_filename():
            continue
        if part.get_content_type() == "text/html":
            payload = part.get_payload(decode=True)
            html_body = payload.decode("utf-8") if isinstance(payload, bytes) else ""
            break
    banner = (
        "<section class='local-email-preview'>"
        "<p>Local preview only. This banner is not part of the SES message.</p>"
        f"<p><strong>Subject:</strong> {_escape(message['Subject'] or '')}</p>"
        f"<p><strong>From:</strong> {_escape(message['From'] or '')}</p>"
        f"<p><strong>To:</strong> {_escape(message['To'] or '')}</p>"
        "</section><hr>"
    )
    if "<body>" in html_body:
        return html_body.replace("<body>", "<body>\n" + banner, 1)
    return banner + html_body


def _html_with_summary(report_html: str, summary_html: str) -> str:
    if "<body>" in report_html:
        return report_html.replace("<body>", "<body>\n" + summary_html, 1)
    return summary_html + report_html


def _summary_text(results: list[InstanceResult], metadata: ScanMetadata) -> str:
    totals = _totals(results)
    when = metadata.generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    status = _status(totals)
    return "\n".join(
        [
            "Daily AWS security exposure scan",
            f"Scan date: {when}",
            f"AWS region: {metadata.region}",
            f"Instances scanned: {len(results)}",
            f"Critical findings: {totals[Severity.CRITICAL]}",
            f"High findings: {totals[Severity.HIGH]}",
            f"Medium findings: {totals[Severity.MEDIUM]}",
            f"Low findings: {totals[Severity.LOW]}",
            f"Overall status: {status}",
            "",
            "The full HTML report is included below and attached, with the Excel and CSV files.",
        ]
    )


def _summary_html(results: list[InstanceResult], metadata: ScanMetadata) -> str:
    text = _summary_text(results, metadata)
    lines = "".join(f"<li>{_escape(line)}</li>" for line in text.splitlines() if line)
    return (
        '<section class="email-summary"><h2>Scan summary</h2><ul>'
        + lines
        + "</ul></section>"
    )


def _escape(value: str) -> str:
    return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _totals(results: list[InstanceResult]) -> dict[Severity, int]:
    totals = {severity: 0 for severity in Severity}
    for result in results:
        for severity, count in result.severity_counts.items():
            totals[severity] += count
    return totals


def _status(totals: dict[Severity, int]) -> str:
    if totals[Severity.CRITICAL]:
        return "CRITICAL FINDINGS DETECTED"
    if totals[Severity.HIGH] or totals[Severity.MEDIUM]:
        return "HIGH OR MEDIUM FINDINGS DETECTED"
    if totals[Severity.LOW]:
        return "LOW FINDINGS DETECTED"
    return "NO MONITORED PUBLIC EXPOSURES"

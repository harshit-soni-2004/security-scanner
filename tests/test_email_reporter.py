"""SES message construction. No AWS calls."""

from datetime import datetime, timezone
from email import message_from_bytes, message_from_string
from pathlib import Path

import pytest
from botocore.exceptions import ClientError
from factories import make_config, make_instance

from scanner.config import ConfigError, apply_email_environment, require_email_delivery
from scanner.email_reporter import send_scan_email, write_email_preview
from scanner.models import Finding, InstanceResult, Severity
from scanner.report_generator import ScanMetadata


def test_email_includes_summary_html_body_and_three_attachments(tmp_path) -> None:
    paths = _reports(tmp_path)
    captured: dict[str, object] = {}

    class FakeSes:
        def send_raw_email(self, **kwargs):
            captured.update(kwargs)
            return {"MessageId": "msg-123"}

    config = _email_config()
    message_id = send_scan_email(
        config,
        [_finding_result()],
        _metadata(),
        paths,
        ses_client=FakeSes(),
    )
    assert message_id == "msg-123"
    assert captured["Source"] == "scanner@example.com"
    assert captured["Destinations"] == ["ops@example.com"]
    raw = str(captured["RawMessage"]["Data"])
    parsed = message_from_string(raw)
    assert parsed["Subject"].startswith("Daily AWS Security Scan - ")
    html_parts = []
    attachments = []
    for part in parsed.walk():
        filename = part.get_filename()
        if filename:
            attachments.append(filename)
        elif part.get_content_type() == "text/html":
            html_parts.append(part.get_payload(decode=True).decode("utf-8"))
    assert "weekly-security-report.html" in attachments
    assert "weekly-security-report.xlsx" in attachments
    assert "weekly-security-findings.csv" in attachments
    body = "\n".join(html_parts)
    assert "Instances scanned" in body
    assert "Critical findings" in body
    assert "REPORT-BODY-MARKER" in body
    assert "CRITICAL FINDINGS DETECTED" in body


def test_missing_sender_fails_without_sending() -> None:
    disabled = make_config()
    with pytest.raises(ConfigError, match="disabled"):
        require_email_delivery(disabled)
    missing_sender = apply_email_environment(
        _email_config(),
        {"SECURITY_SCANNER_EMAIL_SENDER": ""},
    )
    with pytest.raises(ConfigError, match="sender"):
        require_email_delivery(missing_sender)


def test_environment_overrides_yaml_addresses() -> None:
    config = apply_email_environment(
        make_config(),
        {
            "SECURITY_SCANNER_EMAIL_ENABLED": "true",
            "SECURITY_SCANNER_EMAIL_SENDER": "from@example.com",
            "SECURITY_SCANNER_EMAIL_RECIPIENTS": "one@example.com, two@example.com",
        },
    )
    assert config.email.enabled is True
    assert config.email.sender == "from@example.com"
    assert config.email.recipients == ("one@example.com", "two@example.com")


def test_preview_writes_the_ses_message_without_calling_ses(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.setattr("scanner.email_reporter.boto3.client", _fail_if_called)
    paths = _reports(tmp_path)
    output = tmp_path / "preview"
    eml_path = write_email_preview(
        _email_config(),
        [_finding_result()],
        _metadata(),
        paths,
        output,
    )
    parsed = message_from_bytes(eml_path.read_bytes())
    attachments = [part.get_filename() for part in parsed.walk() if part.get_filename()]
    assert parsed["Subject"] == "Daily AWS Security Scan - 2026-10-06"
    assert parsed["From"] == "scanner@example.com"
    assert parsed["To"] == "ops@example.com"
    assert attachments == [
        "weekly-security-report.html",
        "weekly-security-report.xlsx",
        "weekly-security-findings.csv",
    ]
    raw = eml_path.read_text(encoding="utf-8")
    assert "Local preview only" not in raw
    html = (output / "email-preview.html").read_text(encoding="utf-8")
    assert "Local preview only" in html
    assert "scanner@example.com" in html
    assert "ops@example.com" in html
    assert "REPORT-BODY-MARKER" in html
    assert "Critical findings" in html


def test_preview_requires_sender_and_recipients(tmp_path) -> None:
    paths = _reports(tmp_path)
    enabled = apply_email_environment(
        make_config(), {"SECURITY_SCANNER_EMAIL_ENABLED": "true"}
    )
    with pytest.raises(ConfigError, match="sender"):
        write_email_preview(enabled, [], _metadata(), paths, tmp_path)


def test_ses_failure_is_raised_and_not_logged_with_the_message(
    tmp_path, caplog
) -> None:
    paths = _reports(tmp_path)

    class FakeSes:
        def send_raw_email(self, **kwargs):
            raise ClientError(
                {"Error": {"Code": "MessageRejected", "Message": "rejected"}},
                "SendRawEmail",
            )

    caplog.set_level("ERROR")
    with pytest.raises(ClientError):
        send_scan_email(_email_config(), [], _metadata(), paths, ses_client=FakeSes())
    assert "MessageRejected" in caplog.text
    assert "RawMessage" not in caplog.text
    assert "REPORT-BODY-MARKER" not in caplog.text


def _fail_if_called(*_args, **_kwargs):
    raise AssertionError("boto3 must not be called for an email preview")


def _email_config():
    config = make_config()
    return apply_email_environment(
        config,
        {
            "SECURITY_SCANNER_EMAIL_ENABLED": "true",
            "SECURITY_SCANNER_EMAIL_SENDER": "scanner@example.com",
            "SECURITY_SCANNER_EMAIL_RECIPIENTS": "ops@example.com",
        },
    )


def _reports(directory: Path) -> list[Path]:
    html = directory / "weekly-security-report.html"
    xlsx = directory / "weekly-security-report.xlsx"
    csv = directory / "weekly-security-findings.csv"
    html.write_text(
        "<html><body><p>REPORT-BODY-MARKER</p></body></html>\n",
        encoding="utf-8",
    )
    xlsx.write_bytes(b"xlsx")
    csv.write_text("Report Date\n", encoding="utf-8")
    return [html, xlsx, csv]


def _metadata() -> ScanMetadata:
    return ScanMetadata(
        generated_at=datetime(2026, 10, 6, 7, 20, tzinfo=timezone.utc),
        region="ap-south-1",
        account_id="unavailable",
        scanner_version="0.1.0",
        scope="Running EC2 instances.",
        demo=False,
    )


def _finding_result() -> InstanceResult:
    instance = make_instance()
    return InstanceResult(
        instance=instance,
        findings=[
            Finding(
                instance_id=instance.instance_id,
                instance_name=instance.name,
                instance_type=instance.instance_type,
                private_ip=instance.private_ip,
                public_ip=instance.public_ip,
                security_group_id="sg-1",
                security_group_name="web",
                port=22,
                protocol="tcp",
                source="0.0.0.0/0",
                severity=Severity.CRITICAL,
                title="Potential public SSH exposure",
                description="exposure",
                recommendation="Restrict SSH.",
                rule_description=None,
                has_public_ip=True,
            )
        ],
    )

"""Lambda orchestration. AWS and SES are mocked."""

from datetime import datetime, timezone

import pytest
from factories import CONFIG_PATH, make_config

from lambda_handler import LAMBDA_OUTPUT_DIR, lambda_handler
from scanner.config import ConfigError
from scanner.report_generator import ScanMetadata, write_reports


def test_lambda_uses_tmp_and_sends_email(monkeypatch) -> None:
    _clear_email_env(monkeypatch)
    monkeypatch.delenv("AWS_REGION", raising=False)
    monkeypatch.delenv("AWS_DEFAULT_REGION", raising=False)
    monkeypatch.setenv("SECURITY_SCANNER_EMAIL_SENDER", "scanner@example.com")
    monkeypatch.setenv("SECURITY_SCANNER_EMAIL_RECIPIENTS", "ops@example.com")
    monkeypatch.setenv("SECURITY_SCANNER_CONFIG", str(CONFIG_PATH))
    seen: dict[str, object] = {}

    def fake_scan(config):
        seen["output"] = config.report.output_directory
        seen["formats"] = config.report.formats
        seen["region"] = config.aws.region
        return (
            [],
            "unavailable",
            [],
            _metadata(),
        )

    monkeypatch.setattr("lambda_handler.execute_scan", fake_scan)
    monkeypatch.setattr("lambda_handler.send_email", lambda *args: "msg-1")
    response = lambda_handler({}, None)
    assert seen["output"] == LAMBDA_OUTPUT_DIR
    assert seen["formats"] == ("html", "xlsx", "csv")
    assert seen["region"] == "ap-south-1"
    assert response["status"] == "ok"
    assert response["instances_scanned"] == 0
    assert response["findings_count"] == 0
    assert response["email_delivery_status"] == "sent"
    assert response["message_id"] == "msg-1"
    assert response["region"] == "ap-south-1"


def test_lambda_report_directory_is_supplied_by_the_caller(tmp_path) -> None:
    output = tmp_path / "security-reports"
    config = make_config(output_directory=str(output), formats=("html", "csv"))
    written = write_reports(config, [], _metadata())
    assert (
        written[0].parent.parent == output
        or written[0].parent == output
        or str(written[0]).startswith(str(output))
    )
    assert written[0].is_file()


def test_missing_email_configuration_fails_before_the_scan(monkeypatch) -> None:
    _clear_email_env(monkeypatch)
    monkeypatch.setenv("SECURITY_SCANNER_CONFIG", str(CONFIG_PATH))

    def boom(config):
        raise AssertionError("scan should not run")

    monkeypatch.setattr("lambda_handler.execute_scan", boom)
    with pytest.raises(ConfigError, match="sender"):
        lambda_handler({}, None)


def test_scan_failure_does_not_send_email(monkeypatch) -> None:
    _clear_email_env(monkeypatch)
    monkeypatch.setenv("SECURITY_SCANNER_CONFIG", str(CONFIG_PATH))
    monkeypatch.setenv("SECURITY_SCANNER_EMAIL_SENDER", "scanner@example.com")
    monkeypatch.setenv("SECURITY_SCANNER_EMAIL_RECIPIENTS", "ops@example.com")

    def boom(config):
        raise RuntimeError("inventory failed")

    sent = {"called": False}
    monkeypatch.setattr("lambda_handler.execute_scan", boom)

    def send(*args):
        sent["called"] = True
        return "nope"

    monkeypatch.setattr("lambda_handler.send_email", send)
    with pytest.raises(RuntimeError, match="inventory failed"):
        lambda_handler({}, None)
    assert sent["called"] is False


def test_email_failure_fails_the_invocation(monkeypatch) -> None:
    _clear_email_env(monkeypatch)
    monkeypatch.setenv("SECURITY_SCANNER_CONFIG", str(CONFIG_PATH))
    monkeypatch.setenv("SECURITY_SCANNER_EMAIL_SENDER", "scanner@example.com")
    monkeypatch.setenv("SECURITY_SCANNER_EMAIL_RECIPIENTS", "ops@example.com")
    monkeypatch.setattr(
        "lambda_handler.execute_scan",
        lambda config: ([], "unavailable", [], _metadata()),
    )

    def send(*args):
        raise RuntimeError("ses down")

    monkeypatch.setattr("lambda_handler.send_email", send)
    with pytest.raises(RuntimeError, match="ses down"):
        lambda_handler({}, None)


def _clear_email_env(monkeypatch) -> None:
    for name in (
        "SECURITY_SCANNER_EMAIL_SENDER",
        "SECURITY_SCANNER_EMAIL_RECIPIENTS",
        "SECURITY_SCANNER_EMAIL_ENABLED",
        "SECURITY_SCANNER_OUTPUT_DIR",
    ):
        monkeypatch.delenv(name, raising=False)


def _metadata() -> ScanMetadata:
    return ScanMetadata(
        generated_at=datetime(2026, 10, 6, tzinfo=timezone.utc),
        region="ap-south-1",
        account_id="unavailable",
        scanner_version="0.1.0",
        scope="Running EC2 instances.",
        demo=False,
    )

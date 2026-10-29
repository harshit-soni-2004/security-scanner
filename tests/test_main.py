"""CLI exit codes. AWS clients are mocked."""

from unittest.mock import MagicMock

from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError
from factories import CONFIG_PATH

from main import client_error_code, main


def test_validate_config_makes_no_aws_call(monkeypatch) -> None:
    monkeypatch.setattr("scanner.aws_inventory.boto3.Session", _fail_if_called)
    assert main(["--config", str(CONFIG_PATH), "--validate-config"]) == 0


def test_demo_does_not_call_aws_or_ses(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("scanner.aws_inventory.boto3.Session", _fail_if_called)
    monkeypatch.setattr("scanner.email_reporter.boto3.client", _fail_if_called)
    code = main(["--config", str(CONFIG_PATH), "--demo", "--output-dir", str(tmp_path)])
    assert code == 0


def test_demo_makes_no_aws_call(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("scanner.aws_inventory.boto3.Session", _fail_if_called)
    code = main(["--config", str(CONFIG_PATH), "--demo", "--output-dir", str(tmp_path)])
    assert code == 0
    html_path = next(tmp_path.rglob("weekly-security-report.html"))
    html = html_path.read_text(encoding="utf-8")
    assert html_path.parent.name.endswith("-report")
    names = {path.name for path in html_path.parent.iterdir()}
    assert names == {
        "weekly-security-report.html",
        "weekly-security-report.xlsx",
        "weekly-security-findings.csv",
    }
    assert "DEMO DATA" in html
    assert "fictional" in html


def test_missing_config_exits_2(tmp_path) -> None:
    assert main(["--config", str(tmp_path / "missing.yaml")]) == 2


def test_auth_and_api_exit_codes(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr(
        "main.build_clients",
        _raise(ClientError(_error("AccessDenied"), "DescribeInstances")),
    )
    assert main(["--config", str(CONFIG_PATH), "--output-dir", str(tmp_path)]) == 3

    monkeypatch.setattr("main.build_clients", _raise(NoCredentialsError()))
    assert main(["--config", str(CONFIG_PATH), "--output-dir", str(tmp_path)]) == 3

    monkeypatch.setattr(
        "main.build_clients",
        _raise(ClientError(_error("OptInRequired", "opt in"), "DescribeInstances")),
    )
    assert main(["--config", str(CONFIG_PATH), "--output-dir", str(tmp_path)]) == 4

    monkeypatch.setattr(
        "main.build_clients",
        _raise(EndpointConnectionError(endpoint_url="https://ec2.example")),
    )
    assert main(["--config", str(CONFIG_PATH), "--output-dir", str(tmp_path)]) == 4


def test_unexpected_error_exits_1(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("main.build_clients", _raise(RuntimeError("boom")))
    assert main(["--config", str(CONFIG_PATH), "--output-dir", str(tmp_path)]) == 1


def test_fail_on_threshold(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("scanner.aws_inventory.boto3.Session", _fail_if_called)
    code = main(
        [
            "--config",
            str(CONFIG_PATH),
            "--demo",
            "--fail-on",
            "critical",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 5


def test_empty_inventory_writes_header(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("main.build_clients", lambda region: (MagicMock(), MagicMock()))
    monkeypatch.setattr("main.get_account_id", lambda sts: "unavailable")
    monkeypatch.setattr("main.list_instances", lambda *args, **kwargs: [])
    monkeypatch.setattr("main.fetch_security_groups", lambda *args, **kwargs: {})
    code = main(
        [
            "--config",
            str(CONFIG_PATH),
            "--output-dir",
            str(tmp_path),
            "--formats",
            "csv",
        ]
    )
    assert code == 0
    text = next(tmp_path.rglob("weekly-security-findings.csv")).read_text(
        encoding="utf-8"
    )
    assert text.startswith("Report Date,AWS Region,")
    assert len(text.splitlines()) == 1


def test_preview_email_writes_local_message_without_aws(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("scanner.aws_inventory.boto3.Session", _fail_if_called)
    monkeypatch.setattr("scanner.email_reporter.boto3.client", _fail_if_called)
    monkeypatch.setenv("SECURITY_SCANNER_EMAIL_SENDER", "from@example.com")
    monkeypatch.setenv(
        "SECURITY_SCANNER_EMAIL_RECIPIENTS", "one@example.com,two@example.com"
    )
    code = main(
        [
            "--config",
            str(CONFIG_PATH),
            "--demo",
            "--preview-email",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 0
    eml = next(tmp_path.rglob("email-preview.eml"))
    html = eml.parent / "email-preview.html"
    assert "from@example.com" in eml.read_text(encoding="utf-8")
    assert "one@example.com" in html.read_text(encoding="utf-8")
    names = {path.name for path in eml.parent.iterdir()}
    assert "weekly-security-report.html" in names
    assert "weekly-security-report.xlsx" in names
    assert "weekly-security-findings.csv" in names


def test_demo_does_not_write_an_email_preview(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("scanner.aws_inventory.boto3.Session", _fail_if_called)
    monkeypatch.setattr("scanner.email_reporter.boto3.client", _fail_if_called)
    monkeypatch.setenv("SECURITY_SCANNER_EMAIL_SENDER", "from@example.com")
    monkeypatch.setenv("SECURITY_SCANNER_EMAIL_RECIPIENTS", "one@example.com")
    code = main(["--config", str(CONFIG_PATH), "--demo", "--output-dir", str(tmp_path)])
    assert code == 0
    assert list(tmp_path.rglob("email-preview.eml")) == []


def test_preview_email_without_demo_does_not_scan(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("main.build_clients", _fail_if_called)
    code = main(
        [
            "--config",
            str(CONFIG_PATH),
            "--preview-email",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 2
    assert list(tmp_path.rglob("*")) == []


def test_preview_email_missing_sender_exits_2(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("scanner.aws_inventory.boto3.Session", _fail_if_called)
    monkeypatch.setattr("scanner.email_reporter.boto3.client", _fail_if_called)
    monkeypatch.delenv("SECURITY_SCANNER_EMAIL_SENDER", raising=False)
    monkeypatch.delenv("SECURITY_SCANNER_EMAIL_RECIPIENTS", raising=False)
    code = main(
        [
            "--config",
            str(CONFIG_PATH),
            "--demo",
            "--preview-email",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 2
    assert list(tmp_path.rglob("email-preview.eml")) == []


def test_send_email_calls_ses_and_not_ec2(monkeypatch, tmp_path, caplog) -> None:
    monkeypatch.setattr("scanner.aws_inventory.boto3.Session", _fail_if_called)
    captured: dict[str, object] = {}

    class FakeSes:
        def send_raw_email(self, **kwargs):
            captured.update(kwargs)
            return {"MessageId": "ses-msg-1"}

    monkeypatch.setattr(
        "scanner.email_reporter.boto3.client", lambda *args, **kwargs: FakeSes()
    )
    monkeypatch.setenv("SECURITY_SCANNER_EMAIL_ENABLED", "true")
    monkeypatch.setenv("SECURITY_SCANNER_EMAIL_SENDER", "from@example.com")
    monkeypatch.setenv(
        "SECURITY_SCANNER_EMAIL_RECIPIENTS", "one@example.com,two@example.com"
    )
    caplog.set_level("INFO")
    code = main(
        [
            "--config",
            str(CONFIG_PATH),
            "--demo",
            "--send-email",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 0
    assert captured["Source"] == "from@example.com"
    assert captured["Destinations"] == ["one@example.com", "two@example.com"]
    assert "Sending the report with SES" in caplog.text
    assert "MessageId=ses-msg-1" in caplog.text
    assert list(tmp_path.rglob("email-preview.eml")) == []
    assert list(tmp_path.rglob("weekly-security-report.html"))


def test_send_email_ses_rejection_exits_4(monkeypatch, tmp_path, caplog) -> None:
    monkeypatch.setattr("scanner.aws_inventory.boto3.Session", _fail_if_called)

    class FakeSes:
        def send_raw_email(self, **kwargs):
            raise ClientError(
                {
                    "Error": {
                        "Code": "MessageRejected",
                        "Message": "Email address is not verified.",
                    }
                },
                "SendRawEmail",
            )

    monkeypatch.setattr(
        "scanner.email_reporter.boto3.client", lambda *args, **kwargs: FakeSes()
    )
    monkeypatch.setenv("SECURITY_SCANNER_EMAIL_SENDER", "from@example.com")
    monkeypatch.setenv("SECURITY_SCANNER_EMAIL_RECIPIENTS", "one@example.com")
    caplog.set_level("ERROR")
    code = main(
        [
            "--config",
            str(CONFIG_PATH),
            "--demo",
            "--send-email",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 4
    assert "MessageRejected" in caplog.text
    assert "Email address is not verified." in caplog.text
    assert "RawMessage" not in caplog.text


def test_send_email_without_demo_does_not_scan(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("main.build_clients", _fail_if_called)
    code = main(
        [
            "--config",
            str(CONFIG_PATH),
            "--send-email",
            "--output-dir",
            str(tmp_path),
        ]
    )
    assert code == 2
    assert list(tmp_path.rglob("*")) == []


def test_invalid_region_message_is_connectivity() -> None:
    exc = ClientError(
        _error("InvalidParameterValue", "Invalid region: nope"), "DescribeInstances"
    )
    assert client_error_code(exc) == 4


def _error(code: str, message: str = "denied") -> dict:
    return {"Error": {"Code": code, "Message": message}}


def _raise(exc: Exception):
    def _inner(region: str):
        raise exc

    return _inner


def _fail_if_called(*args, **kwargs):
    raise AssertionError("AWS session created")

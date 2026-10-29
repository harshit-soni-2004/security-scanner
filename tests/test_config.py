"""Config loading and validation."""

import pytest
from factories import CONFIG_PATH

from scanner.config import ConfigError, load_config


def test_shipped_config_is_valid() -> None:
    config, warnings = load_config(CONFIG_PATH)
    assert config.aws.region == "ap-south-1"
    assert config.scanner.monitored_ports == (22, 80, 443, 3389)
    assert config.email.sender == ""
    assert config.email.recipients == ()
    assert warnings == []


def test_unknown_key_fails(tmp_path) -> None:
    path = tmp_path / "scanner.yaml"
    path.write_text("aws: {region: eu-west-1}\nextra: true\n", encoding="utf-8")
    with pytest.raises(ConfigError, match="Unknown config key"):
        load_config(path)


def test_bad_port_fails(tmp_path) -> None:
    path = tmp_path / "scanner.yaml"
    path.write_text(
        _base().replace("monitored_ports: [22]", "monitored_ports: [0]"),
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="outside 1-65535"):
        load_config(path)


def test_overlapping_severity_fails(tmp_path) -> None:
    text = _base().replace("high_ports: []", "high_ports: [22]")
    path = tmp_path / "scanner.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match="both"):
        load_config(path)


def test_bad_cidr_fails(tmp_path) -> None:
    text = _base().replace('["10.1.0.0/16"]', '["10.1.0.0/99"]')
    path = tmp_path / "scanner.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match="Invalid CIDR"):
        load_config(path)


def test_unmonitored_severity_port_warns(tmp_path) -> None:
    text = _base().replace("critical_ports: [22]", "critical_ports: [22, 25]")
    path = tmp_path / "scanner.yaml"
    path.write_text(text, encoding="utf-8")
    _config, warnings = load_config(path)
    assert any("25" in warning for warning in warnings)


def _base() -> str:
    return """
aws:
  region: eu-west-1
scanner:
  monitored_ports: [22]
  monitored_protocols: [tcp]
  source_cidrs: ["10.1.0.0/16"]
  include_stopped_instances: false
  port_names: {22: SSH}
  severity:
    critical_ports: [22]
    high_ports: []
    medium_ports: []
    low_ports: []
    default_severity: MEDIUM
report:
  output_directory: reports
  formats: [html]
  overwrite_existing: false
  team_tag_key: Team
  owner_tag_key: Owner
  environment_tag_key: Environment
email:
  enabled: false
  sender: ""
  recipients: []
  subject_prefix: "Daily AWS Security Scan"
"""

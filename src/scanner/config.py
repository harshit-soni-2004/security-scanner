"""Load and validate scanner configuration. No credentials belong in the YAML."""

from __future__ import annotations

import ipaddress
import os
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

import yaml

from scanner.models import Severity

ALLOWED_FORMATS = {"html", "csv", "xlsx", "json"}
ALLOWED_PROTOCOLS = {"tcp", "udp"}
TOP_LEVEL_KEYS = {"aws", "scanner", "report", "email"}
EMAIL_KEYS = {"enabled", "sender", "recipients", "subject_prefix"}
AWS_KEYS = {"region"}
SCANNER_KEYS = {
    "monitored_ports",
    "monitored_protocols",
    "source_cidrs",
    "include_stopped_instances",
    "port_names",
    "severity",
}
SEVERITY_KEYS = {
    "critical_ports",
    "high_ports",
    "medium_ports",
    "low_ports",
    "default_severity",
}
REPORT_KEYS = {
    "output_directory",
    "formats",
    "overwrite_existing",
    "team_tag_key",
    "owner_tag_key",
    "environment_tag_key",
}


class ConfigError(Exception):
    """The configuration file is missing or invalid."""


@dataclass(frozen=True)
class AwsConfig:
    region: str


@dataclass(frozen=True)
class SeverityConfig:
    critical_ports: tuple[int, ...]
    high_ports: tuple[int, ...]
    medium_ports: tuple[int, ...]
    low_ports: tuple[int, ...]
    default_severity: Severity

    def for_port(self, port: int) -> Severity:
        if port in self.critical_ports:
            return Severity.CRITICAL
        if port in self.high_ports:
            return Severity.HIGH
        if port in self.medium_ports:
            return Severity.MEDIUM
        if port in self.low_ports:
            return Severity.LOW
        return self.default_severity


@dataclass(frozen=True)
class ScannerSettings:
    monitored_ports: tuple[int, ...]
    monitored_protocols: tuple[str, ...]
    source_cidrs: tuple[str, ...]
    include_stopped_instances: bool
    port_names: dict[int, str]
    severity: SeverityConfig


@dataclass(frozen=True)
class ReportConfig:
    output_directory: str
    formats: tuple[str, ...]
    overwrite_existing: bool
    team_tag_key: str
    owner_tag_key: str
    environment_tag_key: str


@dataclass(frozen=True)
class EmailConfig:
    enabled: bool
    sender: str
    recipients: tuple[str, ...]
    subject_prefix: str


@dataclass(frozen=True)
class AppConfig:
    aws: AwsConfig
    scanner: ScannerSettings
    report: ReportConfig
    email: EmailConfig


def load_config(path: str | Path) -> tuple[AppConfig, list[str]]:
    """Return validated config and non-fatal warnings. Raises ConfigError on failure."""

    config_path = Path(path)
    if not config_path.is_file():
        raise ConfigError(f"Config file not found: {config_path}")
    try:
        raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"Could not parse YAML in {config_path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ConfigError("Config must be a YAML mapping.")
    return parse_config(raw)


def parse_config(raw: dict[str, Any]) -> tuple[AppConfig, list[str]]:
    """Validate an already-loaded mapping. Unknown keys fail closed."""

    _reject_unknown(raw, TOP_LEVEL_KEYS, "config")
    aws_raw = _require_mapping(raw, "aws")
    scanner_raw = _require_mapping(raw, "scanner")
    report_raw = _require_mapping(raw, "report")
    email_raw = _require_mapping(raw, "email")
    _reject_unknown(aws_raw, AWS_KEYS, "aws")
    _reject_unknown(scanner_raw, SCANNER_KEYS, "scanner")
    _reject_unknown(report_raw, REPORT_KEYS, "report")
    _reject_unknown(email_raw, EMAIL_KEYS, "email")

    region = _require_str(aws_raw, "region", "aws")
    ports = _require_ports(scanner_raw, "monitored_ports")
    protocols = _require_protocols(scanner_raw)
    cidrs = _require_cidrs(scanner_raw)
    include_stopped = _require_bool(scanner_raw, "include_stopped_instances", "scanner")
    port_names = _require_port_names(scanner_raw)
    severity, warnings = _require_severity(scanner_raw, set(ports))
    formats = _require_formats(report_raw)
    output_directory = _require_str(report_raw, "output_directory", "report")
    overwrite = _require_bool(report_raw, "overwrite_existing", "report")

    config = AppConfig(
        aws=AwsConfig(region=region),
        scanner=ScannerSettings(
            monitored_ports=tuple(ports),
            monitored_protocols=tuple(protocols),
            source_cidrs=tuple(cidrs),
            include_stopped_instances=include_stopped,
            port_names=port_names,
            severity=severity,
        ),
        report=ReportConfig(
            output_directory=output_directory,
            formats=tuple(formats),
            overwrite_existing=overwrite,
            team_tag_key=_require_str(report_raw, "team_tag_key", "report"),
            owner_tag_key=_require_str(report_raw, "owner_tag_key", "report"),
            environment_tag_key=_require_str(
                report_raw, "environment_tag_key", "report"
            ),
        ),
        email=_parse_email(email_raw),
    )
    return config, warnings


def apply_email_environment(
    config: AppConfig, env: Mapping[str, str] | None = None
) -> AppConfig:
    """Override email settings from the process environment. YAML stays the default."""

    source = os.environ if env is None else env
    email = config.email
    if "SECURITY_SCANNER_EMAIL_ENABLED" in source:
        email = replace(
            email, enabled=_parse_enabled(source["SECURITY_SCANNER_EMAIL_ENABLED"])
        )
    if "SECURITY_SCANNER_EMAIL_SENDER" in source:
        email = replace(email, sender=source["SECURITY_SCANNER_EMAIL_SENDER"].strip())
    if "SECURITY_SCANNER_EMAIL_RECIPIENTS" in source:
        recipients = tuple(
            part.strip()
            for part in source["SECURITY_SCANNER_EMAIL_RECIPIENTS"].split(",")
            if part.strip()
        )
        email = replace(email, recipients=recipients)
    if email is config.email:
        return config
    return replace(config, email=email)


def require_email_delivery(config: AppConfig) -> None:
    """Fail closed when a caller is about to send mail without a sender or recipients."""

    if not config.email.enabled:
        raise ConfigError(
            "Email is disabled. Set email.enabled to true or SECURITY_SCANNER_EMAIL_ENABLED=true."
        )
    if not config.email.sender:
        raise ConfigError(
            "Email sender is missing. Set email.sender or SECURITY_SCANNER_EMAIL_SENDER."
        )
    if not config.email.recipients:
        raise ConfigError(
            "Email recipients are missing. Set email.recipients or "
            "SECURITY_SCANNER_EMAIL_RECIPIENTS."
        )


def _reject_unknown(mapping: dict[str, Any], allowed: set[str], label: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    if unknown:
        names = ", ".join(unknown)
        raise ConfigError(f"Unknown {label} key(s): {names}.")


def _require_mapping(raw: dict[str, Any], key: str) -> dict[str, Any]:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise ConfigError(f"'{key}' must be a mapping.")
    return value


def _require_str(mapping: dict[str, Any], key: str, label: str) -> str:
    value = mapping.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"{label}.{key} must be a non-empty string.")
    return value.strip()


def _require_bool(mapping: dict[str, Any], key: str, label: str) -> bool:
    value = mapping.get(key)
    if not isinstance(value, bool):
        raise ConfigError(f"{label}.{key} must be true or false.")
    return value


def _require_ports(mapping: dict[str, Any], key: str) -> list[int]:
    value = mapping.get(key)
    if not isinstance(value, list) or not value:
        raise ConfigError(f"scanner.{key} must be a non-empty list of ports.")
    ports: list[int] = []
    for item in value:
        ports.append(_as_port(item, f"scanner.{key}"))
    if len(set(ports)) != len(ports):
        raise ConfigError(f"scanner.{key} contains a duplicate port.")
    return ports


def _as_port(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{label} values must be integers from 1 to 65535.")
    if value < 1 or value > 65535:
        raise ConfigError(f"{label} port {value} is outside 1-65535.")
    return value


def _require_protocols(mapping: dict[str, Any]) -> list[str]:
    value = mapping.get("monitored_protocols")
    if not isinstance(value, list) or not value:
        raise ConfigError("scanner.monitored_protocols must be a non-empty list.")
    protocols: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ConfigError("scanner.monitored_protocols values must be tcp or udp.")
        name = item.strip().lower()
        if name not in ALLOWED_PROTOCOLS:
            raise ConfigError(f"Unsupported protocol '{item}'. Use tcp or udp.")
        protocols.append(name)
    return protocols


def _require_cidrs(mapping: dict[str, Any]) -> list[str]:
    value = mapping.get("source_cidrs")
    if not isinstance(value, list) or not value:
        raise ConfigError("scanner.source_cidrs must be a non-empty list.")
    cidrs: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ConfigError("scanner.source_cidrs values must be strings.")
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError as exc:
            raise ConfigError(f"Invalid CIDR '{item}': {exc}") from exc
        cidrs.append(str(network))
    return cidrs


def _require_port_names(mapping: dict[str, Any]) -> dict[int, str]:
    value = mapping.get("port_names")
    if not isinstance(value, dict):
        raise ConfigError("scanner.port_names must be a mapping of port to name.")
    names: dict[int, str] = {}
    for key, name in value.items():
        port = _as_port(
            int(key) if isinstance(key, str) and key.isdigit() else key, "port_names"
        )
        if not isinstance(name, str) or not name.strip():
            raise ConfigError(f"port_names[{port}] must be a non-empty string.")
        names[port] = name.strip()
    return names


def _require_severity(
    mapping: dict[str, Any], monitored: set[int]
) -> tuple[SeverityConfig, list[str]]:
    raw = mapping.get("severity")
    if not isinstance(raw, dict):
        raise ConfigError("scanner.severity must be a mapping.")
    _reject_unknown(raw, SEVERITY_KEYS, "scanner.severity")
    lists = {
        "critical_ports": _optional_port_list(raw, "critical_ports"),
        "high_ports": _optional_port_list(raw, "high_ports"),
        "medium_ports": _optional_port_list(raw, "medium_ports"),
        "low_ports": _optional_port_list(raw, "low_ports"),
    }
    seen: dict[int, str] = {}
    for name, ports in lists.items():
        for port in ports:
            if port in seen:
                raise ConfigError(
                    f"Port {port} is in both scanner.severity.{seen[port]} and {name}."
                )
            seen[port] = name
    default_name = raw.get("default_severity")
    if not isinstance(default_name, str) or default_name.strip().upper() not in {
        item.value for item in Severity
    }:
        raise ConfigError(
            "scanner.severity.default_severity must be CRITICAL, HIGH, MEDIUM, or LOW."
        )
    warnings: list[str] = []
    for port in sorted(seen):
        if port not in monitored:
            warnings.append(
                f"Severity port {port} is not in monitored_ports, so it will not produce findings."
            )
    severity = SeverityConfig(
        critical_ports=tuple(lists["critical_ports"]),
        high_ports=tuple(lists["high_ports"]),
        medium_ports=tuple(lists["medium_ports"]),
        low_ports=tuple(lists["low_ports"]),
        default_severity=Severity(default_name.strip().upper()),
    )
    return severity, warnings


def _optional_port_list(mapping: dict[str, Any], key: str) -> list[int]:
    value = mapping.get(key, [])
    if not isinstance(value, list):
        raise ConfigError(f"scanner.severity.{key} must be a list.")
    return [_as_port(item, f"scanner.severity.{key}") for item in value]


def _parse_email(mapping: dict[str, Any]) -> EmailConfig:
    sender = mapping.get("sender", "")
    if not isinstance(sender, str):
        raise ConfigError("email.sender must be a string.")
    prefix = mapping.get("subject_prefix")
    if not isinstance(prefix, str) or not prefix.strip():
        raise ConfigError("email.subject_prefix must be a non-empty string.")
    enabled = mapping.get("enabled")
    if not isinstance(enabled, bool):
        raise ConfigError("email.enabled must be true or false.")
    recipients = mapping.get("recipients", [])
    if not isinstance(recipients, list):
        raise ConfigError("email.recipients must be a list.")
    cleaned: list[str] = []
    for item in recipients:
        if not isinstance(item, str) or not item.strip():
            raise ConfigError("email.recipients entries must be non-empty strings.")
        cleaned.append(item.strip())
    return EmailConfig(
        enabled=enabled,
        sender=sender.strip(),
        recipients=tuple(cleaned),
        subject_prefix=prefix.strip(),
    )


def _parse_enabled(value: str) -> bool:
    normalized = value.strip().lower()
    if normalized in {"true", "1", "yes"}:
        return True
    if normalized in {"false", "0", "no"}:
        return False
    raise ConfigError("SECURITY_SCANNER_EMAIL_ENABLED must be true or false.")


def _require_formats(mapping: dict[str, Any]) -> list[str]:
    value = mapping.get("formats")
    if not isinstance(value, list) or not value:
        raise ConfigError("report.formats must be a non-empty list.")
    formats: list[str] = []
    for item in value:
        if not isinstance(item, str) or item.strip().lower() not in ALLOWED_FORMATS:
            raise ConfigError(
                f"Unsupported report format '{item}'. Use html, csv, xlsx, or json."
            )
        formats.append(item.strip().lower())
    return formats

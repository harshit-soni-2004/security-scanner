"""HTML, CSV, and optional JSON reports. Dynamic values are escaped."""

from __future__ import annotations

import csv
import html
import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path

from scanner.config import AppConfig
from scanner.models import Finding, InstanceResult, Severity

logger = logging.getLogger(__name__)

DISCLAIMER = (
    "This tool identifies potential security exposures based on AWS Security Group "
    "configuration. It does not prove that an instance is exploitable."
)
NO_FINDING_STATUS = "No Findings"
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


@dataclass(frozen=True)
class ScanMetadata:
    generated_at: datetime
    region: str
    account_id: str
    scanner_version: str
    scope: str
    demo: bool


REPORT_FILES = {
    "html": "weekly-security-report.html",
    "xlsx": "weekly-security-report.xlsx",
    "csv": "weekly-security-findings.csv",
    "json": "weekly-security-findings.json",
}


def write_reports(
    config: AppConfig,
    results: list[InstanceResult],
    metadata: ScanMetadata,
) -> list[Path]:
    """Write the configured report formats into a UTC timestamped directory.

    Existing files are not overwritten when overwrite_existing is false.
    """

    when = metadata.generated_at.astimezone(timezone.utc)
    directory = _run_directory(
        Path(config.report.output_directory),
        when,
        config.report.overwrite_existing,
    )
    written: list[Path] = []
    if "html" in config.report.formats:
        path = directory / REPORT_FILES["html"]
        path.write_text(render_html(results, metadata), encoding="utf-8")
        written.append(path)
    if "xlsx" in config.report.formats:
        from scanner.excel_report import write_xlsx

        path = directory / REPORT_FILES["xlsx"]
        write_xlsx(path, results, metadata)
        written.append(path)
    if "csv" in config.report.formats:
        path = directory / REPORT_FILES["csv"]
        path.write_text(render_csv(results, metadata), encoding="utf-8", newline="")
        written.append(path)
    if "json" in config.report.formats:
        path = directory / REPORT_FILES["json"]
        path.write_text(render_json(results, metadata), encoding="utf-8")
        written.append(path)
    return written


def _run_directory(base: Path, when: datetime, overwrite: bool) -> Path:
    """Create reports/YYYY-MM-DD-HH-MM-report, or a suffixed directory if it exists."""

    base.mkdir(parents=True, exist_ok=True)
    name = when.strftime("%Y-%m-%d-%H-%M-report")
    path = base / name
    if overwrite or not path.exists():
        path.mkdir(parents=True, exist_ok=True)
        return path
    stamped = base / f"{name}-{when.strftime('%H%M%S')}"
    logger.info(
        "Report directory %s already exists; writing %s", path.name, stamped.name
    )
    if not stamped.exists():
        stamped.mkdir()
        return stamped
    counter = 2
    while True:
        candidate = base / f"{name}-{when.strftime('%H%M%S')}-{counter}"
        if not candidate.exists():
            logger.info(
                "Report directory %s already exists; writing %s",
                stamped.name,
                candidate.name,
            )
            candidate.mkdir()
            return candidate
        counter += 1


def render_html(results: list[InstanceResult], metadata: ScanMetadata) -> str:
    when = metadata.generated_at.astimezone(timezone.utc)
    totals = _totals(results)
    with_findings = [result for result in results if result.finding_count]
    without_findings = [result for result in results if not result.finding_count]
    stamp = when.strftime("%Y-%m-%d %H:%M:%S UTC")
    demo_banner = ""
    if metadata.demo:
        demo_banner = '<p class="demo">DEMO DATA. This report uses fictional instances and is not from AWS.</p>'
    parts = [
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Weekly AWS EC2 Security Exposure Report</title>",
        f"<style>{_CSS}</style>",
        "</head>",
        "<body>",
        '<div class="page">',
        '<header class="report-header">',
        '<p class="kicker">AWS Security Exposure Scanner</p>',
        "<h1>Weekly AWS EC2<br>Security Exposure Report</h1>",
        demo_banner,
        _meta_cards(metadata, when),
        "</header>",
        "<section>",
        "<h2>Executive Summary</h2>",
        _summary_cards(totals, len(results), len(with_findings)),
        "</section>",
        "<section>",
        "<h2>Security Posture</h2>",
        _posture_block(totals),
        "</section>",
        "<section>",
        "<h2>Instance Summary</h2>",
        _instance_table(results),
        "</section>",
        "<section>",
        "<h2>Detailed Findings</h2>",
        _finding_cards(with_findings),
        "</section>",
        '<section class="quiet-section">',
        "<h2>Instances With No Monitored Exposures</h2>",
        _clean_table(without_findings),
        "</section>",
        "<section>",
        "<h2>Recommended Actions</h2>",
        _recommended_actions(results),
        "</section>",
        "<footer>",
        '<p class="footer-title">Weekly AWS EC2 Security Exposure Report</p>',
        "<p>Generated by AWS Security Exposure Scanner</p>",
        f"<p>{html.escape(DISCLAIMER)}</p>",
        f"<p>Scan timestamp: {html.escape(stamp)}</p>",
        (
            '<p class="limits">Limitations: one region and account per run. This scan does not '
            "analyze network ACLs, route tables, internet gateways, or load balancers, and it "
            "does not perform OS-level vulnerability scanning. Security-group references and "
            "prefix-list sources are not evaluated. The scanner does not modify infrastructure.</p>"
        ),
        "</footer>",
        "</div>",
        "</body>",
        "</html>",
    ]
    return "\n".join(parts) + "\n"


def render_csv(results: list[InstanceResult], metadata: ScanMetadata) -> str:
    when = metadata.generated_at.astimezone(timezone.utc)
    report_date = when.strftime("%Y-%m-%d")
    columns = [
        "Report Date",
        "AWS Region",
        "Instance ID",
        "Instance Name",
        "Instance Type",
        "Private IP",
        "Public IP",
        "Security Group ID",
        "Security Group Name",
        "Port",
        "Protocol",
        "Source CIDR",
        "Severity",
        "Finding",
        "Description",
        "Recommendation",
    ]
    rows: list[list[str]] = []
    for result in results:
        for finding in result.findings:
            rows.append(
                [
                    report_date,
                    metadata.region,
                    finding.instance_id,
                    finding.instance_name,
                    finding.instance_type,
                    _blank(finding.private_ip),
                    _blank(finding.public_ip),
                    finding.security_group_id,
                    finding.security_group_name,
                    str(finding.port),
                    finding.protocol,
                    finding.source,
                    finding.severity.value,
                    finding.title,
                    finding.description,
                    finding.recommendation,
                ]
            )
    buffer = StringIO()
    writer = csv.writer(buffer, lineterminator="\n")
    writer.writerow(columns)
    for row in rows:
        writer.writerow([_neutralize(cell) for cell in row])
    return buffer.getvalue()


def render_json(results: list[InstanceResult], metadata: ScanMetadata) -> str:
    when = metadata.generated_at.astimezone(timezone.utc)
    payload = {
        "report_date": when.strftime("%Y-%m-%d"),
        "scan_timestamp_utc": when.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "region": metadata.region,
        "account_id": metadata.account_id,
        "scanner_version": metadata.scanner_version,
        "demo": metadata.demo,
        "findings": [
            _finding_dict(result, finding)
            for result in results
            for finding in result.findings
        ],
    }
    return json.dumps(payload, indent=2) + "\n"


def _finding_dict(result: InstanceResult, finding: Finding) -> dict[str, object]:
    return {
        "instance_id": finding.instance_id,
        "instance_name": finding.instance_name,
        "instance_type": finding.instance_type,
        "private_ip": finding.private_ip,
        "public_ip": finding.public_ip,
        "security_group_id": finding.security_group_id,
        "security_group_name": finding.security_group_name,
        "port": finding.port,
        "protocol": finding.protocol,
        "source": finding.source,
        "severity": finding.severity.value,
        "title": finding.title,
        "description": finding.description,
        "recommendation": finding.recommendation,
        "rule_description": finding.rule_description,
        "has_public_ip": finding.has_public_ip,
        "finding_count": result.finding_count,
        "unique_exposed_ports": result.unique_exposed_ports,
    }


def _totals(results: list[InstanceResult]) -> dict[Severity, int]:
    counts = {severity: 0 for severity in Severity}
    for result in results:
        for severity, count in result.severity_counts.items():
            counts[severity] += count
    return counts


def _meta_cards(metadata: ScanMetadata, when: datetime) -> str:
    fields = [
        ("Report Date", when.strftime("%Y-%m-%d")),
        ("Scan Time", when.strftime("%H:%M:%S UTC")),
        ("AWS Account", metadata.account_id),
        ("Region", metadata.region),
        ("Scanner Version", metadata.scanner_version),
        ("Scan Scope", metadata.scope),
    ]
    cards = []
    for label, value in fields:
        cards.append(
            f"<div><dt>{html.escape(label)}</dt><dd>{html.escape(value)}</dd></div>"
        )
    return '<dl class="meta">' + "".join(cards) + "</dl>"


def _summary_cards(totals: dict[Severity, int], scanned: int, affected: int) -> str:
    primary = [
        ("EC2 Instances", scanned, "neutral"),
        ("With Findings", affected, "alert" if affected else "clear"),
        ("Total Findings", sum(totals.values()), "neutral"),
        ("Critical", totals[Severity.CRITICAL], "critical"),
    ]
    secondary = [
        ("High", totals[Severity.HIGH], "high"),
        ("Medium", totals[Severity.MEDIUM], "medium"),
        ("Low", totals[Severity.LOW], "low"),
    ]
    return (
        '<div class="cards">'
        + "".join(_metric_card(label, value, tone) for label, value, tone in primary)
        + "</div>"
        + '<div class="cards secondary">'
        + "".join(_metric_card(label, value, tone) for label, value, tone in secondary)
        + "</div>"
    )


def _metric_card(label: str, value: int, tone: str) -> str:
    return (
        f'<article class="card {tone}">'
        f"<p>{html.escape(label)}</p><strong>{value}</strong></article>"
    )


def _posture_block(totals: dict[Severity, int]) -> str:
    label, tone = _posture(totals)
    return (
        f'<p class="posture {tone}"><span>Overall Status</span>'
        f"<strong>{html.escape(label)}</strong></p>"
    )


def _posture(totals: dict[Severity, int]) -> tuple[str, str]:
    if totals[Severity.CRITICAL]:
        return "CRITICAL FINDINGS DETECTED", "critical"
    if totals[Severity.HIGH] or totals[Severity.MEDIUM]:
        return "HIGH OR MEDIUM FINDINGS DETECTED", "high"
    if totals[Severity.LOW]:
        return "LOW FINDINGS DETECTED", "low"
    return "NO MONITORED PUBLIC EXPOSURES", "clear"


def _instance_table(results: list[InstanceResult]) -> str:
    header = (
        '<div class="table-wrap"><table class="summary-table"><thead><tr>'
        "<th>Status</th><th>Instance</th><th>Instance ID</th><th>Team</th>"
        "<th>Private IP</th><th>Public IP</th><th>Findings</th>"
        "<th>Highest Severity</th></tr></thead><tbody>"
    )
    if not results:
        return (
            header
            + '<tr><td colspan="8">No instances matched the scan scope.</td></tr>'
            + "</tbody></table></div>"
        )
    rows = []
    for result in results:
        instance = result.instance
        if result.finding_count:
            tone = result.highest_severity.value.lower()
            status = '<span class="status-label">Findings</span>'
        else:
            tone = "clear"
            status = '<span class="status-label">No Findings</span>'
        highest = result.highest_severity.value if result.highest_severity else "None"
        rows.append(
            f'<tr class="{tone}">'
            f"<td>{status}</td>"
            f"<td>{html.escape(instance.name)}</td>"
            f'<td class="mono">{html.escape(instance.instance_id)}</td>'
            f"<td>{html.escape(instance.team)}</td>"
            f'<td class="mono">{html.escape(_blank(instance.private_ip) or "—")}</td>'
            f'<td class="mono">{html.escape(_blank(instance.public_ip) or "—")}</td>'
            f"<td>{result.finding_count}</td>"
            f"<td>{_severity_label(highest)}</td>"
            "</tr>"
        )
    return header + "".join(rows) + "</tbody></table></div>"


def _finding_cards(results: list[InstanceResult]) -> str:
    if not results:
        return "<p>No potential security exposures were found.</p>"
    cards = []
    for result in results:
        instance = result.instance
        tone = result.highest_severity.value.lower()
        label = (
            "1 Potential Security Exposure"
            if result.finding_count == 1
            else f"{result.finding_count} Potential Security Exposures"
        )
        groups = ", ".join(
            f"{ref.group_name} ({ref.group_id})" for ref in instance.security_groups
        )
        reachability = (
            "This instance has a public IP."
            if instance.has_public_ip
            else (
                "This instance has no public IP. A public security group rule has lower "
                "reachability from the internet."
            )
        )
        finding_rows = []
        advice = []
        for finding in result.findings:
            vulnerability = finding.title
            if finding.rule_description:
                vulnerability = f"{vulnerability} ({finding.rule_description})"
            finding_rows.append(
                "<tr>"
                f"<td>{_severity_label(finding.severity.value)}</td>"
                f"<td>{html.escape(vulnerability)}</td>"
                f"<td>{finding.port}</td>"
                f"<td>{html.escape(finding.protocol.upper())}</td>"
                f'<td class="mono">{html.escape(finding.source)}</td>'
                "<td>"
                f"{html.escape(finding.security_group_name)}"
                f'<span class="sub">{html.escape(finding.security_group_id)}</span>'
                "</td></tr>"
            )
            advice.append(
                '<div class="advice">'
                f"<p>Recommendation · port {finding.port}</p>"
                f"<p>{html.escape(finding.recommendation)}</p></div>"
            )
        cards.append(
            f'<article class="finding-card {tone}">'
            f'<p class="badge">{html.escape(result.highest_severity.value)}</p>'
            f"<h3>{html.escape(instance.name)}</h3>"
            f'<p class="mono">{html.escape(instance.instance_id)}</p>'
            f'<p class="count">{html.escape(label)}. Unique ports: {result.unique_exposed_ports}.</p>'
            '<dl class="instance-meta">'
            f"<div><dt>Type</dt><dd>{html.escape(instance.instance_type)}</dd></div>"
            f"<div><dt>Private IP</dt><dd>{html.escape(_blank(instance.private_ip) or '—')}</dd></div>"
            f"<div><dt>Public IP</dt><dd>{html.escape(_blank(instance.public_ip) or '—')}</dd></div>"
            f"<div><dt>Availability Zone</dt><dd>{html.escape(instance.availability_zone)}</dd></div>"
            f"<div><dt>Team</dt><dd>{html.escape(instance.team)}</dd></div>"
            f"<div><dt>Security Groups</dt><dd>{html.escape(groups) or '—'}</dd></div>"
            "</dl>"
            f'<p class="reach">{html.escape(reachability)}</p>'
            '<div class="table-wrap"><table><thead><tr>'
            "<th>Severity</th><th>Finding</th><th>Port</th><th>Protocol</th>"
            "<th>Source</th><th>Security Group</th></tr></thead><tbody>"
            + "".join(finding_rows)
            + "</tbody></table></div>"
            + "".join(advice)
            + "</article>"
        )
    return "\n".join(cards)


def _clean_table(results: list[InstanceResult]) -> str:
    header = (
        '<div class="table-wrap"><table class="clean-table"><thead><tr>'
        "<th>Instance</th><th>Instance ID</th><th>Team</th><th>Status</th>"
        "</tr></thead><tbody>"
    )
    if not results:
        return header + '<tr><td colspan="4">None.</td></tr></tbody></table></div>'
    rows = []
    for result in results:
        rows.append(
            "<tr>"
            f"<td>{html.escape(result.instance.name)}</td>"
            f'<td class="mono">{html.escape(result.instance.instance_id)}</td>'
            f"<td>{html.escape(result.instance.team)}</td>"
            f"<td>{html.escape(NO_FINDING_STATUS)}</td>"
            "</tr>"
        )
    return header + "".join(rows) + "</tbody></table></div>"


def _recommended_actions(results: list[InstanceResult]) -> str:
    grouped: dict[str, list[tuple[str, str]]] = defaultdict(list)
    for result in results:
        for finding in result.findings:
            grouped[_issue_name(finding.port)].append(
                (result.instance.instance_id, finding.recommendation)
            )
    items = []
    for title in _ISSUE_ORDER:
        entries = grouped.get(title, [])
        if not entries:
            continue
        instances = sorted({instance_id for instance_id, _action in entries})
        action = entries[0][1]
        items.append(
            "<li>"
            f"<h3>{html.escape(title)}</h3>"
            f"<p>Affected instances: {len(instances)}</p>"
            f"<p>{html.escape(', '.join(instances))}</p>"
            f"<p>Action: {html.escape(action)}</p>"
            "</li>"
        )
    if not items:
        return "<p>No remediation items. No monitored public exposures were found.</p>"
    return '<ol class="actions">' + "".join(items) + "</ol>"


def _issue_name(port: int) -> str:
    if port == 22:
        return "Public SSH Exposure"
    if port == 3389:
        return "Public RDP Exposure"
    if port == 80:
        return "Public HTTP Exposure"
    if port == 443:
        return "Public HTTPS Exposure"
    return "Other monitored port exposure"


_ISSUE_ORDER = (
    "Public SSH Exposure",
    "Public RDP Exposure",
    "Public HTTP Exposure",
    "Public HTTPS Exposure",
    "Other monitored port exposure",
)


def _severity_label(value: str) -> str:
    css = value.lower() if value in {item.value for item in Severity} else "none"
    return f'<span class="severity {css}">{html.escape(value)}</span>'


def _blank(value: str | None) -> str:
    return value or ""


def _neutralize(value: str) -> str:
    if value.startswith(_FORMULA_PREFIXES):
        return "'" + value
    return value


_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; }
body {
  margin: 0; background: #eef2f6; color: #1f2933;
  font-family: "Segoe UI", Helvetica, Arial, sans-serif; line-height: 1.45;
}
.page { max-width: 1400px; margin: 0 auto; padding: 24px; }
h1, h2, h3 { color: #102a43; margin: 0; }
h1 { font-size: 2rem; line-height: 1.15; font-weight: 650; }
h2 { font-size: 1.15rem; margin: 0 0 12px; }
.kicker { margin: 0 0 8px; letter-spacing: 0.06em; text-transform: uppercase;
  font-size: 0.75rem; color: #52606d; font-weight: 700; }
.report-header, section, footer {
  background: #fff; border: 1px solid #d9e2ec; border-radius: 10px;
  padding: 20px; margin: 0 0 16px;
}
.demo { background: #fff8e8; border: 1px solid #f0c36d; padding: 8px 12px; border-radius: 6px; }
.meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 10px; margin: 18px 0 0; }
.meta div { background: #f8fafc; border: 1px solid #e4e7eb; border-radius: 8px; padding: 10px 12px; }
.meta dt { font-size: 0.72rem; letter-spacing: 0.04em; text-transform: uppercase; color: #627d98; }
.meta dd { margin: 4px 0 0; font-size: 0.95rem; overflow-wrap: anywhere; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; }
.cards.secondary { margin-top: 12px; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); }
.card { border: 1px solid #e4e7eb; border-radius: 8px; padding: 12px 14px; background: #f8fafc; }
.card p { margin: 0; font-size: 0.75rem; letter-spacing: 0.04em; text-transform: uppercase; color: #52606d; }
.card strong { display: block; margin-top: 6px; font-size: 1.8rem; line-height: 1; }
.card.critical { background: #fdf2f4; border-color: #f3c1cb; }
.card.critical strong { color: #8b1e3f; }
.card.high { background: #fff7ed; border-color: #f5d0a6; }
.card.high strong { color: #9a3412; }
.card.medium { background: #fffbeb; border-color: #f3e2a4; }
.card.medium strong { color: #854d0e; }
.card.low { background: #f8fafc; border-color: #d9e2ec; }
.card.alert strong { color: #9a3412; }
.card.clear { background: #f3faf5; border-color: #ccebd6; }
.posture { display: flex; flex-direction: column; gap: 4px; margin: 0; padding: 14px 16px;
  border-radius: 8px; border: 1px solid #d9e2ec; }
.posture span { font-size: 0.75rem; letter-spacing: 0.04em; text-transform: uppercase; color: #52606d; }
.posture strong { font-size: 1.15rem; }
.posture.critical { background: #fdf2f4; border-color: #e8b4bf; }
.posture.critical strong { color: #8b1e3f; }
.posture.high { background: #fff7ed; border-color: #f5d0a6; }
.posture.high strong { color: #9a3412; }
.posture.low { background: #f8fafc; }
.posture.clear { background: #f3faf5; border-color: #b7e4c7; }
.posture.clear strong { color: #166534; }
.table-wrap { overflow-x: auto; }
table { border-collapse: collapse; width: 100%; margin: 0; }
th, td { border-bottom: 1px solid #e4e7eb; padding: 8px 10px; text-align: left;
  vertical-align: top; overflow-wrap: anywhere; }
th { font-size: 0.75rem; letter-spacing: 0.03em; text-transform: uppercase;
  color: #52606d; background: #f8fafc; }
.mono { font-family: Consolas, "Courier New", monospace; font-size: 0.86rem; }
tr.critical td { background: #fffafa; }
tr.high td { background: #fffdfb; }
tr.medium td { background: #fffef8; }
tr.low td { background: #fbfcfd; }
tr.clear td { background: #f7fcf8; }
.status-label { font-weight: 700; }
tr.critical .status-label { color: #8b1e3f; }
tr.high .status-label, tr.medium .status-label { color: #9a3412; }
tr.clear .status-label { color: #166534; }
.severity { font-weight: 700; padding: 2px 6px; border-radius: 4px; white-space: nowrap; }
.severity.critical { background: #f8d0d8; color: #8b1e3f; }
.severity.high { background: #fde6c8; color: #9a3412; }
.severity.medium { background: #fbf3d0; color: #854d0e; }
.severity.low { background: #e8eef5; color: #334e68; }
.severity.none { background: #eef2f6; color: #52606d; }
.finding-card { border: 1px solid #d9e2ec; border-left: 4px solid #9fb3c8;
  border-radius: 8px; padding: 16px; margin: 0 0 14px; break-inside: avoid; }
.finding-card.critical { border-left-color: #8b1e3f; }
.finding-card.high { border-left-color: #c2410c; }
.finding-card.medium { border-left-color: #ca8a04; }
.finding-card.low { border-left-color: #64748b; }
.badge { display: inline-block; margin: 0 0 8px; font-size: 0.75rem; font-weight: 700;
  letter-spacing: 0.04em; padding: 3px 8px; border-radius: 999px; background: #eef2f6; }
.finding-card.critical .badge { background: #f8d0d8; color: #8b1e3f; }
.finding-card.high .badge { background: #fde6c8; color: #9a3412; }
.finding-card.medium .badge { background: #fbf3d0; color: #854d0e; }
.finding-card h3 { font-size: 1.2rem; }
.count { margin: 4px 0 10px; color: #334e68; }
.instance-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
  gap: 8px; margin: 0 0 10px; }
.instance-meta div { background: #f8fafc; border-radius: 6px; padding: 8px 10px; }
.instance-meta dt { font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em; color: #627d98; }
.instance-meta dd { margin: 2px 0 0; overflow-wrap: anywhere; }
.reach, .advice p { margin: 8px 0; }
.advice { background: #f8fafc; border-radius: 6px; padding: 10px 12px; margin-top: 8px; }
.advice p:first-child { margin: 0 0 4px; font-size: 0.75rem; font-weight: 700;
  letter-spacing: 0.04em; text-transform: uppercase; color: #52606d; }
.sub { display: block; color: #627d98; font-family: Consolas, "Courier New", monospace; font-size: 0.8rem; }
.quiet-section { background: #f7fcf8; }
.clean-table td:last-child { color: #166534; font-weight: 700; }
.actions { margin: 0; padding-left: 1.2rem; }
.actions li { margin: 0 0 12px; }
.actions h3 { font-size: 1rem; }
.actions p { margin: 2px 0; }
footer { color: #334e68; font-size: 0.92rem; }
.footer-title { font-weight: 700; color: #102a43; }
.limits { color: #627d98; }
@media (max-width: 720px) {
  .page { padding: 16px; }
  h1 { font-size: 1.6rem; }
  .cards { grid-template-columns: 1fr 1fr; }
}
@media print {
  @page { margin: 12mm; }
  body { background: #fff; }
  .page { max-width: none; margin: 0; padding: 0; }
  .report-header, section, footer { border: 0; border-radius: 0; padding: 0 0 12px; }
  .finding-card, .posture, .card, tr { break-inside: avoid; }
  h2, h3 { break-after: avoid; }
  thead { display: table-header-group; }
  * { print-color-adjust: exact; -webkit-print-color-adjust: exact; }
}
"""

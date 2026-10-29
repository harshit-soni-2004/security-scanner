# EC2 security exposure scanner

Read-only scanner for potential public exposure on EC2 security groups. It lists instances in one region, reads inbound security-group rules, and writes HTML, XLSX, and CSV reports.

This tool identifies potential security exposures based on AWS Security Group configuration. It does not prove that an instance is exploitable.

It evaluates the public sources configured in `config/scanner.yaml` (by default IPv4 `0.0.0.0/0` and IPv6 `::/0`). It does not scan the operating system. It does not modify AWS infrastructure, and it does not change the Terraform modules in this repository.

A finding is one row per instance, security group, monitored port, protocol, and matching source. `finding_count` is that row count. `unique_exposed_ports` is the number of distinct ports on that instance.

## Project structure

```text
security_scanner/
  src/main.py                 Local CLI
  src/lambda_handler.py       Lambda entry point: lambda_handler
  src/scanner/
    aws_inventory.py          EC2 and STS reads
    security_group_scanner.py Inbound rule matching
    vulnerability_analyzer.py Finding aggregation
    report_generator.py       HTML, CSV, and optional JSON
    excel_report.py           XLSX workbook
    email_reporter.py         SES SendRawEmail and local email preview
    config.py                 YAML loading and email environment overrides
  config/scanner.yaml         Defaults. No credentials or recipient addresses.
  reports/                    Generated output. Not committed.
  tests/
  requirements.txt
  requirements-dev.txt
  pytest.ini
```

Git stores the source. It does not run the scan. This directory has no Jenkinsfile, cron file, or GitHub Actions workflow.

## Local setup

Python 3.11 or newer.

From `security_scanner/`:

```powershell
python -m pip install -r requirements.txt -r requirements-dev.txt
python src/main.py --config config/scanner.yaml --validate-config
```

`--validate-config` checks the YAML and does not call AWS.

## Testing

From `security_scanner/`:

```powershell
pytest
ruff check .
ruff format --check .
python -m compileall src
```

Tests mock boto3. They do not call AWS and they do not send email.

## Demo mode

```powershell
python src/main.py --config config/scanner.yaml --demo
```

Demo mode uses fictional instances and security groups. It does not scan real AWS infrastructure and it does not send email. The report is labelled fictional. It includes a Critical finding, a High finding, a Medium finding, and one instance with no findings. The Medium row uses a demo-only port and does not change the ports used for a real scan.

## Email preview

Set placeholder addresses in the environment, then write the message locally:

```powershell
$env:SECURITY_SCANNER_EMAIL_ENABLED = "true"
$env:SECURITY_SCANNER_EMAIL_SENDER = "sender@example.com"
$env:SECURITY_SCANNER_EMAIL_RECIPIENTS = "one@example.com, two@example.com"
python src/main.py --config config/scanner.yaml --demo --preview-email
```

This creates `email-preview.eml` and `email-preview.html` beside the reports. Open the HTML file in a browser. The preview does not call SES and does not send an email. `--preview-email` without `--demo` exits 2 and does not scan.

## SES test

Sender and recipients come from the environment, not from Git:

| Variable | Purpose |
| --- | --- |
| `SECURITY_SCANNER_EMAIL_ENABLED` | `true` or `false`. Overrides `email.enabled`. |
| `SECURITY_SCANNER_EMAIL_SENDER` | From address. Must be an SES identity in the target account. |
| `SECURITY_SCANNER_EMAIL_RECIPIENTS` | Comma-separated To addresses. |

Do not commit these values. SES credentials and verified identities belong in the local AWS configuration or the Lambda execution role.

One local send, using fictional scan data and the existing SES sender:

```powershell
python src/main.py --config config/scanner.yaml --demo --send-email
```

`--send-email` requires `--demo`. It does not call EC2 or STS. Success logs the SES message id. A rejected message exits 4. A normal scan, and `--demo` without this flag, do not send email. `--preview-email` never calls SES.

A real inventory scan uses the standard boto3 credential chain (`AWS_PROFILE`, environment variables, SSO, or a role):

```powershell
$env:AWS_PROFILE = "my-readonly-profile"
python src/main.py --config config/scanner.yaml
```

## AWS deployment architecture

AWS infrastructure is not in this repository. The intended production path is:

```text
EventBridge Scheduler
        ↓
Lambda
        ↓
lambda_handler.py
        ↓
Security Scanner
        ↓
HTML / XLSX / CSV reports
        ↓
AWS SES
        ↓
Email recipients
```

Deploy the handler as `lambda_handler.lambda_handler` with `security_scanner/src` on the Python path, and include `config/scanner.yaml` in the package. Lambda writes reports under `/tmp/security-reports` unless `SECURITY_SCANNER_OUTPUT_DIR` is set. Set the sender and recipients with the environment variables above. `SECURITY_SCANNER_CONFIG` overrides the config path. `AWS_REGION` is used when the invocation event does not include `region`.

## AWS team responsibilities

The AWS or platform team configures this outside the repository:

- Lambda deployment and the Python package
- Lambda execution role and IAM permissions
- EC2 read permissions (`ec2:DescribeInstances`, `ec2:DescribeSecurityGroups`)
- SES configuration, sender verification, and `ses:SendRawEmail`
- EventBridge Scheduler, once per day, invoking the Lambda function
- CloudWatch logging and monitoring

This repository does not create that infrastructure.

## Security boundary

The scanner is read-only against AWS infrastructure. It does not:

- create or terminate EC2 instances
- modify security groups
- modify networking
- modify IAM
- modify S3
- modify Secrets Manager
- modify infrastructure through Terraform

AWS APIs the code calls:

| API | Where |
| --- | --- |
| EC2 `DescribeInstances` | Inventory |
| EC2 `DescribeSecurityGroups` | Inventory |
| STS `GetCallerIdentity` | Account ID on a real scan. No IAM permission is required. If it fails, the report shows `unavailable`. |
| SES `SendRawEmail` | Lambda handler, and the local CLI only when `--send-email` is set |

Example permissions for the Lambda execution role. Review them against your organization's security requirements. `ec2:DescribeInstances` and `ec2:DescribeSecurityGroups` do not support resource-level restrictions, so the resource is `*`.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ReadOnlyEc2Inventory",
      "Effect": "Allow",
      "Action": ["ec2:DescribeInstances", "ec2:DescribeSecurityGroups"],
      "Resource": "*",
      "Condition": {
        "StringEquals": {"aws:RequestedRegion": "<region>"}
      }
    },
    {
      "Sid": "SendScanReport",
      "Effect": "Allow",
      "Action": "ses:SendRawEmail",
      "Resource": "*"
    }
  ]
}
```

## Configuration

Edit `config/scanner.yaml`. Unknown keys fail closed (exit 2). Leave `email.sender` and `email.recipients` empty in Git.

| Setting | Meaning |
| --- | --- |
| `aws.region` | Region for this run. Override with `--region`. |
| `scanner.monitored_ports` | Ports that can produce a finding. Integers 1–65535. |
| `scanner.monitored_protocols` | `tcp` and/or `udp`. A rule is checked only when its protocol is listed, or when the protocol is `-1` (all). |
| `scanner.source_cidrs` | Exact sources treated as public. Default `0.0.0.0/0` and `::/0`. |
| `scanner.include_stopped_instances` | When false, only `running` instances are requested. Terminated instances are never included. |
| `scanner.port_names` | Names used in titles. A port without a name uses `Public exposure on port N`. |
| `scanner.severity` | `critical_ports`, `high_ports`, `medium_ports`, `low_ports`, and `default_severity` for any other monitored port. A port may appear in only one list. A severity port that is not monitored logs a warning. |
| `report.formats` | `html`, `csv`, `xlsx`, and optional `json`. |
| `report.output_directory` | Base directory. Each run adds a UTC child directory. |
| `report.overwrite_existing` | When false, an existing run directory is left in place and the new run is written to a `-HHMMSS` directory. |
| `report.*_tag_key` | Tag keys for Team, Owner, and Environment. Missing tags become `unknown`. |
| `email.enabled` | When true, Lambda sends the report after the sender and recipients are set. The CLI sends only with `--send-email`. |
| `email.sender` | From address. Leave empty in Git. |
| `email.recipients` | To addresses. Leave empty in Git. |
| `email.subject_prefix` | Subject text before the UTC date. |

Report dates use the scan time in UTC.

## Reports

Each run creates one UTC directory under `report.output_directory`:

```text
reports/
└── YYYY-MM-DD-HH-MM-report/
    ├── weekly-security-report.html
    ├── weekly-security-report.xlsx
    └── weekly-security-findings.csv
```

The timestamp is the directory name. The files inside keep stable names. Do not commit `reports/`.

HTML is the human-readable report: summary cards, a security-posture line, an instance table, one card per affected instance, instances with no findings, and recommended actions.

XLSX has four worksheets: Summary, Instance Summary, Detailed Findings, and Recommendations. Severity and status are written as text. Color is supplementary: red for Critical, yellow or orange for High or Medium, green for an instance with no findings.

CSV columns, in order: Report Date, AWS Region, Instance ID, Instance Name, Instance Type, Private IP, Public IP, Security Group ID, Security Group Name, Port, Protocol, Source CIDR, Severity, Finding, Description, Recommendation. The header is written even when there are no findings. Cells that start with `=`, `+`, `-`, `@`, tab, or carriage return are prefixed with a quote.

JSON, when requested, is `weekly-security-findings.json` in the same directory.

The email uses that HTML report as the HTML body, with a short scan summary inserted after `<body>`. The HTML, XLSX, and CSV files are attached. Lambda builds those files under `/tmp` and then calls SES.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Success. Findings alone do not fail the run. |
| 1 | Unexpected error. |
| 2 | Config error, including missing email settings when a send or preview was requested. |
| 3 | AWS credentials or authorization (`NoCredentialsError`, `AccessDenied`, `UnauthorizedOperation`, `AuthFailure`, expired token). |
| 4 | AWS API, region, opt-in, connectivity, or SES rejection. |
| 5 | A finding is at or above `--fail-on` (`critical`, `high`, `medium`, or `low`). |

An empty inventory is a successful run: the report shows zeros and the log warns that nothing matched.

## Limitations

- One region and one account per run.
- No network ACL, route table, internet gateway, or load balancer analysis.
- Security-group-to-security-group sources and prefix lists are not evaluated.
- ICMP rules are ignored because they have no TCP/UDP ports.
- A broad CIDR that is not an exact configured source (for example `0.0.0.0/1`) is not flagged.
- No accepted-risk or suppression list.
- No week-over-week comparison.
- Slack is not implemented.

Passing these tests does not by itself make the deployment production-ready. The Lambda role, SES identities, and daily schedule are still configured by the AWS team.

# CMMC Control Validator

[![Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

A Python-based tool for validating Infrastructure as Code (IaC) configurations against CMMC Level 2 and NIST SP 800-171 security controls. Designed for organizations preparing for CMMC certification or maintaining continuous compliance.

## Overview

CMMC Control Validator parses Terraform configurations and evaluates them against the 110 practices required for CMMC Level 2 certification. It provides:

- **Automated Compliance Checking**: Scan Terraform files for security misconfigurations
- **Gap Analysis Reports**: Identify which controls are met, partially met, or missing
- **POA&M Generation**: Create Plan of Action & Milestones documents for remediation tracking
- **Control Mapping**: Understand how AWS resources map to NIST 800-171 requirements

## Features

### Control Families Covered

| Family | Description | Controls |
|--------|-------------|----------|
| AC | Access Control | 22 |
| AU | Audit and Accountability | 9 |
| AT | Awareness and Training | 3 |
| CM | Configuration Management | 9 |
| IA | Identification and Authentication | 11 |
| IR | Incident Response | 3 |
| MA | Maintenance | 6 |
| MP | Media Protection | 8 |
| PE | Physical Protection | 6 |
| PS | Personnel Security | 2 |
| RA | Risk Assessment | 3 |
| CA | Security Assessment | 4 |
| SC | System and Communications Protection | 16 |
| SI | System and Information Integrity | 7 |

### AWS Resources Validated

- IAM (Users, Roles, Policies, Groups)
- S3 Buckets (Encryption, Public Access, Logging)
- Security Groups and NACLs
- RDS and Aurora Clusters
- EBS Volumes
- CloudTrail
- KMS Keys
- VPC Flow Logs
- GuardDuty
- AWS Config
- Load Balancers
- EC2 Instances
- Secrets Manager

## Installation

### From PyPI

```bash
pip install cmmc-control-validator
```

### From Source

```bash
git clone https://github.com/cameronhopkin/cmmc-control-validator.git
cd cmmc-control-validator
pip install -e .
```

### Requirements

- Python 3.9+
- click
- pyhcl2
- jinja2

## Quick Start

### Validate Terraform Configuration

```bash
# Basic validation with text output
cmmc-validator validate ./terraform/

# JSON output
cmmc-validator validate ./terraform/ --format json --output results.json

# HTML report
cmmc-validator validate ./terraform/ --format html --output report.html
```

### Generate Gap Analysis Report

```bash
cmmc-validator gap-report ./terraform/ \
    --output gap-analysis.html \
    --org "Acme Corp" \
    --system "Production AWS Environment"
```

### Generate POA&M

```bash
cmmc-validator poam ./terraform/ \
    --output poam.csv \
    --org "Acme Corp" \
    --system "Production AWS Environment"
```

### List All Controls

```bash
cmmc-validator list-controls
```

## Usage Examples

### Programmatic Usage

```python
from cmmc_validator import TerraformParser, ControlMapper, FindingCollection

# Parse Terraform files
parser = TerraformParser()
result = parser.parse_directory("./terraform/")

# Validate against controls
mapper = ControlMapper()
findings = FindingCollection(scan_target="./terraform/")

for resource in result.get_aws_resources():
    resource_findings = mapper.validate_terraform_resource(
        resource.resource_type,
        resource.config
    )
    findings.add_all(resource_findings)

# Check compliance
print(f"Compliance Rate: {findings.compliance_rate:.1f}%")
print(f"Total Findings: {len(findings)}")

# Get high-priority items
for finding in findings.get_priority_findings(5):
    print(f"[{finding.severity}] {finding.control.id}: {finding.message}")
```

### CI/CD Integration

```yaml
# .github/workflows/compliance.yml
name: CMMC Compliance Check

on: [push, pull_request]

jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install CMMC Validator
        run: pip install cmmc-control-validator

      - name: Run Compliance Check
        run: |
          cmmc-validator validate ./terraform/ \
            --format json \
            --output compliance-results.json

      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: compliance-report
          path: compliance-results.json
```

### Pre-commit Hook

```yaml
# .pre-commit-config.yaml
repos:
  - repo: local
    hooks:
      - id: cmmc-validate
        name: CMMC Compliance Check
        entry: cmmc-validator validate
        language: python
        files: \.tf$
        pass_filenames: false
        args: ['./terraform/', '--format', 'text']
```

## Output Formats

### Text Output

```
============================================================
CMMC Level 2 Validation Summary
============================================================

Compliance Status:
  compliant: 45
  non_compliant: 12
  partial: 8
  not_applicable: 3

Compliance Rate: 66.2%

Priority Remediation Items:
  [HIGH] SC.L2-3.13.16: S3 bucket missing server-side encryption
  [HIGH] AC.L2-3.1.1: Security group allows unrestricted SSH access
  [HIGH] AU.L2-3.3.1: CloudTrail not enabled for all regions

Findings by Family:
  AC: 15
  SC: 10
  AU: 8
```

### JSON Output

```json
{
  "scan_target": "./terraform/",
  "scan_time": "2025-11-15T10:30:00Z",
  "summary": {
    "total_findings": 68,
    "compliant": 45,
    "non_compliant": 12,
    "partial": 8,
    "not_applicable": 3,
    "compliance_rate": 66.2
  },
  "findings": [...]
}
```

### HTML Report

Generates a professional HTML report suitable for sharing with assessors or management, including:

- Executive summary
- Compliance status dashboard
- Detailed findings by control family
- Remediation recommendations
- Resource inventory

## Control Mapping

The validator maps AWS Terraform resources to CMMC/NIST controls:

| Resource Type | Controls | Checks |
|--------------|----------|--------|
| aws_iam_policy | AC.L2-3.1.1, AC.L2-3.1.2, AC.L2-3.1.5 | Least privilege, no wildcards |
| aws_s3_bucket | SC.L2-3.13.16, AC.L2-3.1.3 | Encryption, public access |
| aws_security_group | AC.L2-3.1.1, SC.L2-3.13.1 | Ingress/egress restrictions |
| aws_cloudtrail | AU.L2-3.3.1, AU.L2-3.3.2 | Multi-region, encryption |
| aws_kms_key | SC.L2-3.13.11 | Key rotation, FIPS |

## Configuration

Create a `.cmmc-validator.yaml` in your project root:

```yaml
# .cmmc-validator.yaml
exclude_resources:
  - aws_iam_policy.legacy_*
  - aws_security_group.dev_*

severity_threshold: medium  # Only report medium and above

custom_rules:
  require_tags:
    - Environment
    - Owner
    - CMMCScope
```

## Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
git clone https://github.com/cameronhopkin/cmmc-control-validator.git
cd cmmc-control-validator
python -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
pytest
```

## References

- [CMMC Model Overview](https://dodcio.defense.gov/CMMC/)
- [NIST SP 800-171 Rev 2](https://csrc.nist.gov/publications/detail/sp/800-171/rev-2/final)
- [AWS CMMC Resources](https://aws.amazon.com/compliance/cmmc/)

## License

MIT License - see [LICENSE](LICENSE) for details.

## Author

Cameron Hopkin - [GitHub](https://github.com/cameronhopkin)

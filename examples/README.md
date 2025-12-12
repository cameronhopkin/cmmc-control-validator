# CMMC Control Validator Examples

This directory contains example Terraform configurations to demonstrate the CMMC Control Validator.

## Directory Structure

```
examples/
├── compliant/          # CMMC-compliant infrastructure patterns
│   └── main.tf
└── non-compliant/      # Common compliance violations
    └── main.tf
```

## Usage

### Validate Compliant Example

```bash
cmmc-validator validate examples/compliant/
```

Expected result: High compliance rate with minimal findings.

### Validate Non-Compliant Example

```bash
cmmc-validator validate examples/non-compliant/
```

Expected result: Multiple findings across various control families.

### Generate Gap Report

```bash
cmmc-validator gap-report examples/non-compliant/ \
    --output gap-analysis.html \
    --org "Example Corp" \
    --system "Development Environment"
```

### Generate POA&M

```bash
cmmc-validator poam examples/non-compliant/ \
    --output poam.csv \
    --org "Example Corp" \
    --system "Development Environment"
```

## Compliant Patterns Demonstrated

The `compliant/` directory shows:

- **S3 Encryption**: Server-side encryption with KMS
- **Public Access Blocking**: All public access blocked
- **VPC Flow Logs**: Comprehensive traffic logging
- **CloudTrail**: Multi-region with integrity validation
- **Security Groups**: Properly restricted ingress/egress
- **KMS Key Rotation**: Automatic key rotation enabled
- **GuardDuty**: Threat detection enabled
- **AWS Config**: Configuration recording enabled
- **Least Privilege IAM**: Specific actions and resources

## Non-Compliant Patterns Demonstrated

The `non-compliant/` directory shows common violations:

| Violation | Control | Resource |
|-----------|---------|----------|
| Unencrypted S3 | SC.L2-3.13.16 | `aws_s3_bucket.unencrypted` |
| Public S3 access | AC.L2-3.1.1 | `aws_s3_bucket.public` |
| No KMS rotation | SC.L2-3.13.11 | `aws_kms_key.no_rotation` |
| Open SSH | AC.L2-3.1.1 | `aws_security_group.open_ssh` |
| Open RDP | AC.L2-3.1.1 | `aws_security_group.open_rdp` |
| Wildcard IAM | AC.L2-3.1.5 | `aws_iam_policy.admin_access` |
| Public IAM trust | AC.L2-3.1.1 | `aws_iam_role.public_trust` |
| Unencrypted CloudTrail | AU.L2-3.3.1 | `aws_cloudtrail.unencrypted` |
| Unencrypted RDS | SC.L2-3.13.16 | `aws_db_instance.unencrypted` |
| Unencrypted EBS | SC.L2-3.13.16 | `aws_ebs_volume.unencrypted` |
| No VPC Flow Logs | SI.L2-3.14.6 | `aws_vpc.no_flow_logs` |
| HTTP listener | SC.L2-3.13.8 | `aws_lb_listener.http` |
| IMDSv1 allowed | CM.L2-3.4.2 | `aws_instance.insecure` |
| GuardDuty disabled | SI.L2-3.14.6 | `aws_guardduty_detector.disabled` |

## Control Coverage

These examples cover the following CMMC Level 2 control families:

- **AC** - Access Control
- **AU** - Audit and Accountability
- **CM** - Configuration Management
- **SC** - System and Communications Protection
- **SI** - System and Information Integrity

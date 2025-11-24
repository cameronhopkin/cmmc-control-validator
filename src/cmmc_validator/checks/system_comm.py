#!/usr/bin/env python3
"""
CMMC Control Validator - System and Communications Protection Checks
Automated checks for SC (System and Communications Protection) family controls.

Author: Cameron Hopkin
License: MIT
"""
from typing import Dict

from ..core.control_mapper import Control, Finding, ComplianceStatus


def check_system_comms(
    control: Control,
    resource_type: str,
    config: Dict
) -> Finding:
    """
    Check System and Communications Protection controls.

    Args:
        control: The control being checked
        resource_type: Terraform resource type
        config: Resource configuration

    Returns:
        Finding with compliance status
    """
    # Route to specific checks based on resource type
    if resource_type == "aws_s3_bucket":
        return _check_s3_encryption(control, config)
    elif resource_type in ("aws_ebs_volume", "aws_rds_instance", "aws_rds_cluster"):
        return _check_storage_encryption(control, resource_type, config)
    elif resource_type == "aws_kms_key":
        return _check_kms_key(control, config)
    elif resource_type in ("aws_lb_listener", "aws_cloudfront_distribution"):
        return _check_transit_encryption(control, resource_type, config)
    elif resource_type in ("aws_vpc", "aws_security_group", "aws_network_acl"):
        return _check_boundary_protection(control, resource_type, config)
    else:
        return Finding(
            control=control,
            status=ComplianceStatus.UNKNOWN,
            resource_type=resource_type,
            resource_name=config.get("name", "unknown"),
            message="Manual review required for SC controls",
            remediation="Review encryption and boundary protection configuration"
        )


def _check_s3_encryption(control: Control, config: Dict) -> Finding:
    """Check S3 bucket encryption configuration."""
    bucket_name = config.get("bucket", "unknown")

    # Check for server-side encryption
    sse_config = config.get("server_side_encryption_configuration")

    if not sse_config:
        return Finding(
            control=control,
            status=ComplianceStatus.NON_COMPLIANT,
            resource_type="aws_s3_bucket",
            resource_name=bucket_name,
            message="S3 bucket does not have server-side encryption enabled",
            remediation="Enable SSE-S3 or SSE-KMS encryption on the bucket",
            severity="high"
        )

    # Check encryption type
    # Prefer KMS over S3-managed keys for CUI
    if isinstance(sse_config, dict):
        rules = sse_config.get("rule", [])
        if isinstance(rules, dict):
            rules = [rules]

        for rule in rules:
            sse_algo = rule.get("apply_server_side_encryption_by_default", {})
            if sse_algo.get("sse_algorithm") == "aws:kms":
                return Finding(
                    control=control,
                    status=ComplianceStatus.COMPLIANT,
                    resource_type="aws_s3_bucket",
                    resource_name=bucket_name,
                    message="S3 bucket encrypted with KMS (recommended for CUI)",
                    remediation=""
                )
            elif sse_algo.get("sse_algorithm") == "AES256":
                return Finding(
                    control=control,
                    status=ComplianceStatus.PARTIAL,
                    resource_type="aws_s3_bucket",
                    resource_name=bucket_name,
                    message="S3 bucket uses SSE-S3; SSE-KMS recommended for CUI",
                    remediation="Consider upgrading to SSE-KMS for better key management",
                    severity="low"
                )

    # If we detected SSE config but couldn't parse details
    return Finding(
        control=control,
        status=ComplianceStatus.PARTIAL,
        resource_type="aws_s3_bucket",
        resource_name=bucket_name,
        message="S3 encryption detected but configuration should be verified",
        remediation="Verify SSE-KMS is configured for CUI data",
        severity="medium"
    )


def _check_storage_encryption(
    control: Control,
    resource_type: str,
    config: Dict
) -> Finding:
    """Check EBS/RDS encryption configuration."""
    resource_name = config.get("name", config.get("identifier", "unknown"))

    # Check if encryption is enabled
    encrypted = config.get("encrypted", False)
    storage_encrypted = config.get("storage_encrypted", False)

    is_encrypted = encrypted or storage_encrypted

    if not is_encrypted:
        return Finding(
            control=control,
            status=ComplianceStatus.NON_COMPLIANT,
            resource_type=resource_type,
            resource_name=resource_name,
            message=f"{resource_type} does not have encryption enabled",
            remediation="Enable encryption at rest using KMS",
            severity="high"
        )

    # Check for KMS key (preferred over default)
    kms_key = config.get("kms_key_id", config.get("kms_key_arn"))

    if kms_key:
        return Finding(
            control=control,
            status=ComplianceStatus.COMPLIANT,
            resource_type=resource_type,
            resource_name=resource_name,
            message="Storage encrypted with customer-managed KMS key",
            remediation=""
        )
    else:
        return Finding(
            control=control,
            status=ComplianceStatus.PARTIAL,
            resource_type=resource_type,
            resource_name=resource_name,
            message="Storage encrypted with AWS-managed key; CMK recommended for CUI",
            remediation="Consider using customer-managed KMS key for better control",
            severity="low"
        )


def _check_kms_key(control: Control, config: Dict) -> Finding:
    """Check KMS key configuration."""
    key_alias = config.get("alias", config.get("description", "unknown"))

    issues = []

    # Check key rotation
    enable_rotation = config.get("enable_key_rotation", False)
    if not enable_rotation:
        issues.append("Key rotation is not enabled")

    # Check key policy for overly permissive access
    policy = config.get("policy", "")
    if '"Principal": "*"' in str(policy):
        issues.append("Key policy allows public access")

    # Check deletion window
    deletion_window = config.get("deletion_window_in_days", 30)
    if deletion_window < 7:
        issues.append(f"Deletion window is only {deletion_window} days")

    if issues:
        return Finding(
            control=control,
            status=ComplianceStatus.PARTIAL,
            resource_type="aws_kms_key",
            resource_name=key_alias,
            message="; ".join(issues),
            remediation="Enable key rotation and review key policy",
            severity="medium"
        )

    return Finding(
        control=control,
        status=ComplianceStatus.COMPLIANT,
        resource_type="aws_kms_key",
        resource_name=key_alias,
        message="KMS key properly configured",
        remediation=""
    )


def _check_transit_encryption(
    control: Control,
    resource_type: str,
    config: Dict
) -> Finding:
    """Check encryption in transit configuration."""
    resource_name = config.get("name", config.get("id", "unknown"))

    if resource_type == "aws_lb_listener":
        protocol = config.get("protocol", "")
        ssl_policy = config.get("ssl_policy", "")

        if protocol == "HTTPS" or protocol == "TLS":
            # Check for strong SSL policy
            weak_policies = ["ELBSecurityPolicy-2015-05", "ELBSecurityPolicy-TLS-1-0-2015-04"]
            if ssl_policy in weak_policies:
                return Finding(
                    control=control,
                    status=ComplianceStatus.PARTIAL,
                    resource_type=resource_type,
                    resource_name=resource_name,
                    message=f"Using weak SSL policy: {ssl_policy}",
                    remediation="Use ELBSecurityPolicy-TLS-1-2-2017-01 or newer",
                    severity="medium"
                )
            return Finding(
                control=control,
                status=ComplianceStatus.COMPLIANT,
                resource_type=resource_type,
                resource_name=resource_name,
                message="Load balancer listener uses HTTPS/TLS",
                remediation=""
            )
        elif protocol == "HTTP":
            return Finding(
                control=control,
                status=ComplianceStatus.NON_COMPLIANT,
                resource_type=resource_type,
                resource_name=resource_name,
                message="Load balancer listener uses unencrypted HTTP",
                remediation="Configure HTTPS listener with valid certificate",
                severity="high"
            )

    elif resource_type == "aws_cloudfront_distribution":
        viewer_protocol = config.get("viewer_protocol_policy", "")

        if viewer_protocol == "https-only":
            return Finding(
                control=control,
                status=ComplianceStatus.COMPLIANT,
                resource_type=resource_type,
                resource_name=resource_name,
                message="CloudFront enforces HTTPS only",
                remediation=""
            )
        elif viewer_protocol == "redirect-to-https":
            return Finding(
                control=control,
                status=ComplianceStatus.COMPLIANT,
                resource_type=resource_type,
                resource_name=resource_name,
                message="CloudFront redirects HTTP to HTTPS",
                remediation=""
            )
        else:
            return Finding(
                control=control,
                status=ComplianceStatus.NON_COMPLIANT,
                resource_type=resource_type,
                resource_name=resource_name,
                message="CloudFront allows unencrypted HTTP connections",
                remediation="Set viewer_protocol_policy to https-only or redirect-to-https",
                severity="high"
            )

    return Finding(
        control=control,
        status=ComplianceStatus.UNKNOWN,
        resource_type=resource_type,
        resource_name=resource_name,
        message="Could not determine transit encryption status",
        remediation="Manual review required"
    )


def _check_boundary_protection(
    control: Control,
    resource_type: str,
    config: Dict
) -> Finding:
    """Check network boundary protection configuration."""
    resource_name = config.get("name", config.get("tags", {}).get("Name", "unknown"))

    if resource_type == "aws_vpc":
        # Check for flow logs
        # Note: Flow logs are typically separate resources, so this is limited
        return Finding(
            control=control,
            status=ComplianceStatus.UNKNOWN,
            resource_type=resource_type,
            resource_name=resource_name,
            message="VPC boundary protection requires verification of flow logs and network ACLs",
            remediation="Ensure VPC flow logs are enabled and NACLs restrict traffic",
            severity="medium"
        )

    elif resource_type == "aws_network_acl":
        # Check for overly permissive rules
        ingress_rules = config.get("ingress", [])
        egress_rules = config.get("egress", [])

        issues = []
        for rule in ingress_rules:
            if rule.get("cidr_block") == "0.0.0.0/0" and rule.get("action") == "allow":
                if rule.get("from_port") == 0 and rule.get("to_port") == 65535:
                    issues.append("NACL allows all inbound traffic from 0.0.0.0/0")

        if issues:
            return Finding(
                control=control,
                status=ComplianceStatus.PARTIAL,
                resource_type=resource_type,
                resource_name=resource_name,
                message="; ".join(issues),
                remediation="Restrict NACL rules to required traffic only",
                severity="medium"
            )

        return Finding(
            control=control,
            status=ComplianceStatus.COMPLIANT,
            resource_type=resource_type,
            resource_name=resource_name,
            message="Network ACL provides boundary protection",
            remediation=""
        )

    return Finding(
        control=control,
        status=ComplianceStatus.UNKNOWN,
        resource_type=resource_type,
        resource_name=resource_name,
        message="Manual review required for boundary protection",
        remediation="Verify network segmentation and monitoring"
    )

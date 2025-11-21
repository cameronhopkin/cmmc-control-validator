#!/usr/bin/env python3
"""
CMMC Control Validator - Access Control Checks
Automated checks for AC (Access Control) family controls.

Author: Cameron Hopkin
License: MIT
"""
from typing import Dict
import json

from ..core.control_mapper import Control, Finding, ComplianceStatus


def check_access_control(
    control: Control,
    resource_type: str,
    config: Dict
) -> Finding:
    """
    Check Access Control family controls against resource configuration.

    Args:
        control: The control being checked
        resource_type: Terraform resource type
        config: Resource configuration

    Returns:
        Finding with compliance status
    """
    # Route to specific checks based on resource type
    if resource_type == "aws_iam_policy":
        return _check_iam_policy(control, config)
    elif resource_type in ("aws_iam_role", "aws_iam_user"):
        return _check_iam_principal(control, resource_type, config)
    elif resource_type == "aws_security_group":
        return _check_security_group(control, config)
    elif resource_type == "aws_s3_bucket":
        return _check_s3_access(control, config)
    else:
        return Finding(
            control=control,
            status=ComplianceStatus.UNKNOWN,
            resource_type=resource_type,
            resource_name=config.get("name", "unknown"),
            message="Manual review required for access control",
            remediation="Review access control configuration manually"
        )


def _check_iam_policy(control: Control, config: Dict) -> Finding:
    """Check IAM policy for least privilege violations."""
    resource_name = config.get("name", "unknown")

    # Parse policy document
    policy_doc = config.get("policy", {})
    if isinstance(policy_doc, str):
        try:
            policy_doc = json.loads(policy_doc)
        except json.JSONDecodeError:
            return Finding(
                control=control,
                status=ComplianceStatus.UNKNOWN,
                resource_type="aws_iam_policy",
                resource_name=resource_name,
                message="Could not parse IAM policy document",
                remediation="Ensure policy document is valid JSON"
            )

    statements = policy_doc.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    # Check for overly permissive policies
    issues = []

    for stmt in statements:
        effect = stmt.get("Effect", "")
        actions = stmt.get("Action", [])
        resources = stmt.get("Resource", [])

        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]

        # Check for wildcard actions
        if effect == "Allow":
            if "*" in actions or "iam:*" in actions:
                issues.append("Policy grants wildcard (*) IAM actions")

            # Check for admin access
            admin_actions = ["iam:CreateUser", "iam:CreateRole", "iam:AttachRolePolicy"]
            if any(a in actions for a in admin_actions) and "*" in resources:
                issues.append("Policy grants administrative IAM access on all resources")

            # Check for wildcard resources with sensitive actions
            sensitive_actions = [
                "s3:DeleteBucket", "s3:DeleteObject",
                "ec2:TerminateInstances",
                "rds:DeleteDBInstance",
                "kms:ScheduleKeyDeletion"
            ]
            if any(a in actions for a in sensitive_actions) and "*" in resources:
                issues.append("Policy grants destructive actions on all resources")

    if issues:
        return Finding(
            control=control,
            status=ComplianceStatus.NON_COMPLIANT,
            resource_type="aws_iam_policy",
            resource_name=resource_name,
            message="; ".join(issues),
            remediation="Restrict permissions to specific resources and actions following least privilege principle",
            severity="high",
            evidence={"policy_issues": issues}
        )

    return Finding(
        control=control,
        status=ComplianceStatus.COMPLIANT,
        resource_type="aws_iam_policy",
        resource_name=resource_name,
        message="IAM policy follows least privilege principles",
        remediation=""
    )


def _check_iam_principal(control: Control, resource_type: str, config: Dict) -> Finding:
    """Check IAM user or role configuration."""
    resource_name = config.get("name", "unknown")

    issues = []

    # Check for inline policies (prefer managed policies)
    if "inline_policy" in config:
        issues.append("Uses inline policies instead of managed policies")

    # Check for direct policy attachments (prefer role-based)
    if resource_type == "aws_iam_user" and "policy_arns" in config:
        issues.append("Policies attached directly to user instead of through roles/groups")

    # Check for assume role policy (for roles)
    if resource_type == "aws_iam_role":
        assume_policy = config.get("assume_role_policy", "")
        if "*" in str(assume_policy):
            issues.append("Assume role policy may be overly permissive")

    if issues:
        return Finding(
            control=control,
            status=ComplianceStatus.PARTIAL,
            resource_type=resource_type,
            resource_name=resource_name,
            message="; ".join(issues),
            remediation="Use managed policies attached to groups/roles instead of inline policies on users",
            severity="medium"
        )

    return Finding(
        control=control,
        status=ComplianceStatus.COMPLIANT,
        resource_type=resource_type,
        resource_name=resource_name,
        message="IAM principal configuration meets requirements",
        remediation=""
    )


def _check_security_group(control: Control, config: Dict) -> Finding:
    """Check security group for access control violations."""
    resource_name = config.get("name", config.get("tags", {}).get("Name", "unknown"))

    issues = []

    # Check ingress rules
    ingress_rules = config.get("ingress", [])
    if isinstance(ingress_rules, dict):
        ingress_rules = [ingress_rules]

    for rule in ingress_rules:
        cidr_blocks = rule.get("cidr_blocks", [])
        from_port = rule.get("from_port", 0)
        to_port = rule.get("to_port", 65535)

        # Check for open to world
        if "0.0.0.0/0" in cidr_blocks:
            # Administrative ports should not be open to world
            admin_ports = [22, 3389, 5432, 3306, 1433, 27017]
            if from_port in admin_ports or to_port in admin_ports:
                issues.append(f"Administrative port open to 0.0.0.0/0")
            elif from_port == 0 and to_port == 65535:
                issues.append("All ports open to 0.0.0.0/0")

    # Check egress rules
    egress_rules = config.get("egress", [])
    if isinstance(egress_rules, dict):
        egress_rules = [egress_rules]

    for rule in egress_rules:
        cidr_blocks = rule.get("cidr_blocks", [])
        if "0.0.0.0/0" in cidr_blocks:
            from_port = rule.get("from_port", 0)
            to_port = rule.get("to_port", 65535)
            if from_port == 0 and to_port == 65535:
                issues.append("All egress traffic allowed to 0.0.0.0/0")

    if issues:
        return Finding(
            control=control,
            status=ComplianceStatus.NON_COMPLIANT,
            resource_type="aws_security_group",
            resource_name=resource_name,
            message="; ".join(issues),
            remediation="Restrict security group rules to specific CIDR ranges and required ports only",
            severity="high",
            evidence={"security_group_issues": issues}
        )

    return Finding(
        control=control,
        status=ComplianceStatus.COMPLIANT,
        resource_type="aws_security_group",
        resource_name=resource_name,
        message="Security group follows access control best practices",
        remediation=""
    )


def _check_s3_access(control: Control, config: Dict) -> Finding:
    """Check S3 bucket access controls."""
    resource_name = config.get("bucket", "unknown")

    issues = []

    # Check for public access
    acl = config.get("acl", "private")
    if acl in ("public-read", "public-read-write"):
        issues.append(f"Bucket has public ACL: {acl}")

    # Check bucket policy
    policy = config.get("policy", "")
    if policy:
        if '"Principal": "*"' in str(policy) or '"Principal":"*"' in str(policy):
            issues.append("Bucket policy allows public access")

    # Check if public access block is configured
    if not config.get("public_access_block"):
        issues.append("Public access block not configured")

    if issues:
        return Finding(
            control=control,
            status=ComplianceStatus.NON_COMPLIANT,
            resource_type="aws_s3_bucket",
            resource_name=resource_name,
            message="; ".join(issues),
            remediation="Enable S3 public access block and restrict bucket policies",
            severity="high"
        )

    return Finding(
        control=control,
        status=ComplianceStatus.COMPLIANT,
        resource_type="aws_s3_bucket",
        resource_name=resource_name,
        message="S3 bucket access controls properly configured",
        remediation=""
    )

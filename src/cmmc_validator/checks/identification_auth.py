#!/usr/bin/env python3
"""
CMMC Control Validator - Identification and Authentication Checks
Automated checks for IA (Identification and Authentication) family controls.

Author: Cameron Hopkin
License: MIT
"""
from typing import Dict

from ..core.control_mapper import Control, Finding, ComplianceStatus


def check_identification_auth(
    control: Control,
    resource_type: str,
    config: Dict
) -> Finding:
    """
    Check Identification and Authentication controls.

    Args:
        control: The control being checked
        resource_type: Terraform resource type
        config: Resource configuration

    Returns:
        Finding with compliance status
    """
    if resource_type == "aws_iam_user":
        return _check_iam_user_auth(control, config)
    elif resource_type == "aws_iam_account_password_policy":
        return _check_password_policy(control, config)
    elif resource_type == "aws_iam_role":
        return _check_role_trust(control, config)
    elif resource_type in ("aws_cognito_user_pool", "aws_cognito_identity_pool"):
        return _check_cognito_auth(control, resource_type, config)
    else:
        return Finding(
            control=control,
            status=ComplianceStatus.UNKNOWN,
            resource_type=resource_type,
            resource_name=config.get("name", "unknown"),
            message="Manual review required for I&A controls",
            remediation="Verify MFA and authentication requirements"
        )


def _check_iam_user_auth(control: Control, config: Dict) -> Finding:
    """Check IAM user authentication configuration."""
    user_name = config.get("name", "unknown")

    # Note: MFA and console access are typically managed outside Terraform
    # or through aws_iam_user_login_profile and aws_iam_virtual_mfa_device

    # Check for programmatic access keys
    # (can't fully validate MFA requirement from Terraform alone)

    return Finding(
        control=control,
        status=ComplianceStatus.UNKNOWN,
        resource_type="aws_iam_user",
        resource_name=user_name,
        message="MFA status cannot be verified from Terraform configuration alone",
        remediation="Verify MFA is enabled for user through AWS Console or CLI",
        severity="medium"
    )


def _check_password_policy(control: Control, config: Dict) -> Finding:
    """Check IAM account password policy."""
    issues = []

    # Minimum password length
    min_length = config.get("minimum_password_length", 8)
    if min_length < 14:
        issues.append(f"Minimum password length is {min_length} (recommend 14+)")

    # Complexity requirements
    if not config.get("require_lowercase_characters", False):
        issues.append("Lowercase characters not required")
    if not config.get("require_uppercase_characters", False):
        issues.append("Uppercase characters not required")
    if not config.get("require_numbers", False):
        issues.append("Numbers not required")
    if not config.get("require_symbols", False):
        issues.append("Symbols not required")

    # Password reuse
    reuse_prevention = config.get("password_reuse_prevention", 0)
    if reuse_prevention < 24:
        issues.append(f"Password reuse prevention is {reuse_prevention} (recommend 24)")

    # Password expiration
    max_age = config.get("max_password_age", 0)
    if max_age == 0 or max_age > 90:
        issues.append("Password expiration not configured or exceeds 90 days")

    if len(issues) >= 3:
        return Finding(
            control=control,
            status=ComplianceStatus.NON_COMPLIANT,
            resource_type="aws_iam_account_password_policy",
            resource_name="account_password_policy",
            message="; ".join(issues),
            remediation="Strengthen password policy per NIST 800-63B guidelines",
            severity="high",
            evidence={"policy_issues": issues}
        )
    elif issues:
        return Finding(
            control=control,
            status=ComplianceStatus.PARTIAL,
            resource_type="aws_iam_account_password_policy",
            resource_name="account_password_policy",
            message="; ".join(issues),
            remediation="Consider strengthening password policy",
            severity="medium"
        )

    return Finding(
        control=control,
        status=ComplianceStatus.COMPLIANT,
        resource_type="aws_iam_account_password_policy",
        resource_name="account_password_policy",
        message="Password policy meets requirements",
        remediation=""
    )


def _check_role_trust(control: Control, config: Dict) -> Finding:
    """Check IAM role trust policy for proper authentication."""
    role_name = config.get("name", "unknown")

    assume_role_policy = config.get("assume_role_policy", "")

    issues = []

    # Check for overly permissive trust
    if '"Principal": "*"' in str(assume_role_policy):
        issues.append("Role trust policy allows any principal")

    if '"AWS": "*"' in str(assume_role_policy):
        issues.append("Role trust policy allows any AWS principal")

    # Check for missing conditions
    if "Condition" not in str(assume_role_policy):
        # Some roles legitimately don't need conditions
        if "sts:AssumeRoleWithSAML" not in str(assume_role_policy) and \
           "sts:AssumeRoleWithWebIdentity" not in str(assume_role_policy):
            issues.append("Role trust policy has no conditions (consider adding MFA requirement)")

    if issues:
        severity = "high" if "any principal" in str(issues) else "medium"
        return Finding(
            control=control,
            status=ComplianceStatus.PARTIAL if severity == "medium" else ComplianceStatus.NON_COMPLIANT,
            resource_type="aws_iam_role",
            resource_name=role_name,
            message="; ".join(issues),
            remediation="Restrict trust policy to specific principals and add conditions",
            severity=severity
        )

    return Finding(
        control=control,
        status=ComplianceStatus.COMPLIANT,
        resource_type="aws_iam_role",
        resource_name=role_name,
        message="Role trust policy properly configured",
        remediation=""
    )


def _check_cognito_auth(control: Control, resource_type: str, config: Dict) -> Finding:
    """Check Cognito authentication configuration."""
    resource_name = config.get("name", "unknown")

    if resource_type == "aws_cognito_user_pool":
        issues = []

        # Check MFA configuration
        mfa_config = config.get("mfa_configuration", "OFF")
        if mfa_config == "OFF":
            issues.append("MFA is disabled")
        elif mfa_config == "OPTIONAL":
            issues.append("MFA is optional (recommend ON for privileged users)")

        # Check password policy
        password_policy = config.get("password_policy", {})
        if password_policy:
            min_length = password_policy.get("minimum_length", 8)
            if min_length < 12:
                issues.append(f"Minimum password length is {min_length}")

            if not password_policy.get("require_lowercase", False):
                issues.append("Lowercase not required")
            if not password_policy.get("require_uppercase", False):
                issues.append("Uppercase not required")
            if not password_policy.get("require_numbers", False):
                issues.append("Numbers not required")
            if not password_policy.get("require_symbols", False):
                issues.append("Symbols not required")

        # Check for email/phone verification
        auto_verified = config.get("auto_verified_attributes", [])
        if not auto_verified:
            issues.append("No auto-verified attributes (email/phone)")

        if issues:
            severity = "high" if "MFA is disabled" in issues else "medium"
            return Finding(
                control=control,
                status=ComplianceStatus.PARTIAL if severity == "medium" else ComplianceStatus.NON_COMPLIANT,
                resource_type=resource_type,
                resource_name=resource_name,
                message="; ".join(issues),
                remediation="Enable MFA and strengthen password policy",
                severity=severity
            )

        return Finding(
            control=control,
            status=ComplianceStatus.COMPLIANT,
            resource_type=resource_type,
            resource_name=resource_name,
            message="Cognito user pool properly configured for authentication",
            remediation=""
        )

    # Identity pool
    return Finding(
        control=control,
        status=ComplianceStatus.UNKNOWN,
        resource_type=resource_type,
        resource_name=resource_name,
        message="Cognito identity pool requires manual review",
        remediation="Verify identity provider authentication settings"
    )

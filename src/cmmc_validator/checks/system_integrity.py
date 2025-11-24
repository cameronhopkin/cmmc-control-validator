#!/usr/bin/env python3
"""
CMMC Control Validator - System and Information Integrity Checks
Automated checks for SI (System and Information Integrity) family controls.

Author: Cameron Hopkin
License: MIT
"""
from typing import Dict

from ..core.control_mapper import Control, Finding, ComplianceStatus


def check_system_integrity(
    control: Control,
    resource_type: str,
    config: Dict
) -> Finding:
    """
    Check System and Information Integrity controls.

    Args:
        control: The control being checked
        resource_type: Terraform resource type
        config: Resource configuration

    Returns:
        Finding with compliance status
    """
    if resource_type == "aws_guardduty_detector":
        return _check_guardduty(control, config)
    elif resource_type == "aws_config_rule":
        return _check_config_rule(control, config)
    elif resource_type == "aws_inspector_assessment_target":
        return _check_inspector(control, config)
    elif resource_type == "aws_cloudwatch_metric_alarm":
        return _check_cloudwatch_alarm(control, config)
    elif resource_type == "aws_flow_log":
        return _check_flow_log(control, config)
    else:
        return Finding(
            control=control,
            status=ComplianceStatus.UNKNOWN,
            resource_type=resource_type,
            resource_name=config.get("name", "unknown"),
            message="Manual review required for system integrity controls",
            remediation="Verify logging and monitoring configuration"
        )


def _check_guardduty(control: Control, config: Dict) -> Finding:
    """Check GuardDuty detector configuration."""
    detector_id = config.get("id", "unknown")

    # Check if enabled
    enabled = config.get("enable", True)

    if not enabled:
        return Finding(
            control=control,
            status=ComplianceStatus.NON_COMPLIANT,
            resource_type="aws_guardduty_detector",
            resource_name=detector_id,
            message="GuardDuty detector is disabled",
            remediation="Enable GuardDuty for threat detection",
            severity="high"
        )

    # Check for S3 protection
    datasources = config.get("datasources", {})
    s3_logs = datasources.get("s3_logs", {})
    s3_enabled = s3_logs.get("enable", False)

    # Check for Kubernetes protection
    kubernetes = datasources.get("kubernetes", {})
    k8s_logs = kubernetes.get("audit_logs", {})
    k8s_enabled = k8s_logs.get("enable", False)

    # Check for Malware protection
    malware = datasources.get("malware_protection", {})
    malware_enabled = malware.get("scan_ec2_instance_with_findings", {}).get("ebs_volumes", {}).get("enable", False)

    features_disabled = []
    if not s3_enabled:
        features_disabled.append("S3 protection")
    if not k8s_enabled:
        features_disabled.append("Kubernetes audit logs")
    if not malware_enabled:
        features_disabled.append("Malware protection")

    if features_disabled:
        return Finding(
            control=control,
            status=ComplianceStatus.PARTIAL,
            resource_type="aws_guardduty_detector",
            resource_name=detector_id,
            message=f"GuardDuty enabled but missing: {', '.join(features_disabled)}",
            remediation="Enable all GuardDuty protection features",
            severity="medium"
        )

    return Finding(
        control=control,
        status=ComplianceStatus.COMPLIANT,
        resource_type="aws_guardduty_detector",
        resource_name=detector_id,
        message="GuardDuty fully configured for threat detection",
        remediation=""
    )


def _check_config_rule(control: Control, config: Dict) -> Finding:
    """Check AWS Config rule configuration."""
    rule_name = config.get("name", "unknown")

    # Check if rule is enabled
    # Config rules are typically enabled by default when created

    # Check for compliance-related rules
    source = config.get("source", {})
    source_id = source.get("source_identifier", "")

    # High-value security rules for CMMC
    important_rules = [
        "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
        "S3_BUCKET_PUBLIC_READ_PROHIBITED",
        "S3_BUCKET_PUBLIC_WRITE_PROHIBITED",
        "ENCRYPTED_VOLUMES",
        "RDS_STORAGE_ENCRYPTED",
        "CLOUDTRAIL_ENABLED",
        "IAM_PASSWORD_POLICY",
        "IAM_USER_MFA_ENABLED",
        "ROOT_ACCOUNT_MFA_ENABLED",
        "VPC_FLOW_LOGS_ENABLED",
    ]

    if source_id in important_rules:
        return Finding(
            control=control,
            status=ComplianceStatus.COMPLIANT,
            resource_type="aws_config_rule",
            resource_name=rule_name,
            message=f"Config rule {source_id} monitors security compliance",
            remediation=""
        )

    return Finding(
        control=control,
        status=ComplianceStatus.COMPLIANT,
        resource_type="aws_config_rule",
        resource_name=rule_name,
        message="Config rule contributes to configuration monitoring",
        remediation=""
    )


def _check_inspector(control: Control, config: Dict) -> Finding:
    """Check AWS Inspector configuration."""
    target_name = config.get("name", "unknown")

    # Check if assessment target is properly scoped
    resource_group_arn = config.get("resource_group_arn")

    if not resource_group_arn:
        return Finding(
            control=control,
            status=ComplianceStatus.PARTIAL,
            resource_type="aws_inspector_assessment_target",
            resource_name=target_name,
            message="Inspector assessment target has no resource group (scans all resources)",
            remediation="Consider scoping assessment to specific resource groups",
            severity="low"
        )

    return Finding(
        control=control,
        status=ComplianceStatus.COMPLIANT,
        resource_type="aws_inspector_assessment_target",
        resource_name=target_name,
        message="Inspector assessment target configured for vulnerability scanning",
        remediation=""
    )


def _check_cloudwatch_alarm(control: Control, config: Dict) -> Finding:
    """Check CloudWatch alarm configuration."""
    alarm_name = config.get("alarm_name", config.get("name", "unknown"))

    # Check for security-relevant metrics
    namespace = config.get("namespace", "")
    metric_name = config.get("metric_name", "")

    security_namespaces = ["AWS/GuardDuty", "AWS/SecurityHub", "AWS/WAF"]
    security_metrics = [
        "UnauthorizedAccessCount",
        "FailedLoginAttempts",
        "RootAccountUsage",
        "SecurityGroupChanges",
        "NACLChanges",
        "IAMPolicyChanges",
    ]

    is_security_alarm = (
        namespace in security_namespaces or
        metric_name in security_metrics or
        "security" in alarm_name.lower() or
        "unauthorized" in alarm_name.lower()
    )

    # Check alarm actions
    alarm_actions = config.get("alarm_actions", [])

    if not alarm_actions:
        return Finding(
            control=control,
            status=ComplianceStatus.PARTIAL,
            resource_type="aws_cloudwatch_metric_alarm",
            resource_name=alarm_name,
            message="CloudWatch alarm has no actions configured",
            remediation="Add SNS topic or other action for alert notification",
            severity="medium"
        )

    if is_security_alarm:
        return Finding(
            control=control,
            status=ComplianceStatus.COMPLIANT,
            resource_type="aws_cloudwatch_metric_alarm",
            resource_name=alarm_name,
            message="Security monitoring alarm properly configured",
            remediation=""
        )

    return Finding(
        control=control,
        status=ComplianceStatus.COMPLIANT,
        resource_type="aws_cloudwatch_metric_alarm",
        resource_name=alarm_name,
        message="CloudWatch alarm contributes to system monitoring",
        remediation=""
    )


def _check_flow_log(control: Control, config: Dict) -> Finding:
    """Check VPC flow log configuration."""
    flow_log_id = config.get("id", "unknown")

    # Check traffic type
    traffic_type = config.get("traffic_type", "ALL")

    if traffic_type == "REJECT":
        return Finding(
            control=control,
            status=ComplianceStatus.PARTIAL,
            resource_type="aws_flow_log",
            resource_name=flow_log_id,
            message="Flow log only captures rejected traffic",
            remediation="Consider capturing ALL traffic for complete visibility",
            severity="medium"
        )

    # Check log destination
    log_destination = config.get("log_destination")
    log_destination_type = config.get("log_destination_type", "cloud-watch-logs")

    if not log_destination:
        return Finding(
            control=control,
            status=ComplianceStatus.NON_COMPLIANT,
            resource_type="aws_flow_log",
            resource_name=flow_log_id,
            message="Flow log has no destination configured",
            remediation="Configure CloudWatch Logs or S3 destination",
            severity="high"
        )

    # Check log format (custom format provides more detail)
    log_format = config.get("log_format")

    if traffic_type == "ALL" and log_destination:
        return Finding(
            control=control,
            status=ComplianceStatus.COMPLIANT,
            resource_type="aws_flow_log",
            resource_name=flow_log_id,
            message=f"VPC flow log captures all traffic to {log_destination_type}",
            remediation=""
        )

    return Finding(
        control=control,
        status=ComplianceStatus.PARTIAL,
        resource_type="aws_flow_log",
        resource_name=flow_log_id,
        message="VPC flow log configured but review recommended",
        remediation="Verify flow log captures required traffic types",
        severity="low"
    )

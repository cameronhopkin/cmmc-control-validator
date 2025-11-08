#!/usr/bin/env python3
"""
CMMC Control Validator - CMMC Level 2 Practice Definitions
Core CMMC L2 practices mapped to NIST 800-171.

Author: Cameron Hopkin
License: MIT
"""
from typing import Dict, List

# CMMC Level 2 practices (subset - key controls)
CMMC_L2_PRACTICES: List[Dict] = [
    # Access Control (AC)
    {
        "id": "AC.L2-3.1.1",
        "family": "AC",
        "title": "Authorized Access Control",
        "description": "Limit system access to authorized users, processes acting on behalf of authorized users, and devices (including other systems).",
        "nist_mapping": "3.1.1",
        "cmmc_level": 2,
        "objectives": [
            "Authorized users are identified",
            "Processes acting on behalf of authorized users are identified",
            "Devices (and other systems) authorized to connect are identified",
            "System access is limited to authorized users",
            "System access is limited to processes acting on behalf of authorized users",
            "System access is limited to authorized devices"
        ],
        "aws_services": ["iam", "cognito", "sso"],
        "terraform_resources": ["aws_iam_user", "aws_iam_role", "aws_iam_policy", "aws_iam_group"]
    },
    {
        "id": "AC.L2-3.1.2",
        "family": "AC",
        "title": "Transaction & Function Control",
        "description": "Limit system access to the types of transactions and functions that authorized users are permitted to execute.",
        "nist_mapping": "3.1.2",
        "cmmc_level": 2,
        "objectives": [
            "Types of transactions and functions that authorized users are permitted to execute are defined",
            "System access is limited to defined transactions and functions"
        ],
        "aws_services": ["iam"],
        "terraform_resources": ["aws_iam_policy", "aws_iam_role_policy"]
    },
    {
        "id": "AC.L2-3.1.3",
        "family": "AC",
        "title": "Control CUI Flow",
        "description": "Control the flow of CUI in accordance with approved authorizations.",
        "nist_mapping": "3.1.3",
        "cmmc_level": 2,
        "objectives": [
            "Information flow control policies are defined",
            "Methods and enforcement mechanisms for controlling flow are defined",
            "Flow is controlled in accordance with approved authorizations"
        ],
        "aws_services": ["vpc", "network_firewall", "waf"],
        "terraform_resources": ["aws_security_group", "aws_network_acl", "aws_vpc"]
    },
    {
        "id": "AC.L2-3.1.5",
        "family": "AC",
        "title": "Least Privilege",
        "description": "Employ the principle of least privilege, including for specific security functions and privileged accounts.",
        "nist_mapping": "3.1.5",
        "cmmc_level": 2,
        "objectives": [
            "Privileged accounts are identified",
            "Access to privileged accounts is authorized in accordance with least privilege",
            "Security functions are identified",
            "Access to security functions is authorized in accordance with least privilege"
        ],
        "aws_services": ["iam"],
        "terraform_resources": ["aws_iam_policy", "aws_iam_role", "aws_iam_user"]
    },
    {
        "id": "AC.L2-3.1.7",
        "family": "AC",
        "title": "Privileged Functions",
        "description": "Prevent non-privileged users from executing privileged functions and capture the execution of such functions in audit logs.",
        "nist_mapping": "3.1.7",
        "cmmc_level": 2,
        "objectives": [
            "Privileged functions are defined",
            "Non-privileged users are defined",
            "Non-privileged users are prevented from executing privileged functions",
            "Execution of privileged functions is captured in audit logs"
        ],
        "aws_services": ["iam", "cloudtrail"],
        "terraform_resources": ["aws_iam_policy", "aws_cloudtrail"]
    },
    # Audit and Accountability (AU)
    {
        "id": "AU.L2-3.3.1",
        "family": "AU",
        "title": "System Auditing",
        "description": "Create and retain system audit logs and records to enable monitoring, analysis, investigation, and reporting.",
        "nist_mapping": "3.3.1",
        "cmmc_level": 2,
        "objectives": [
            "Audit logs needed to enable monitoring, analysis, investigation, and reporting are specified",
            "Audit logs are created",
            "Audit logs are retained",
            "Audit logs and records support monitoring",
            "Audit logs and records support analysis",
            "Audit logs and records support investigation",
            "Audit logs and records support reporting"
        ],
        "aws_services": ["cloudtrail", "cloudwatch", "s3"],
        "terraform_resources": ["aws_cloudtrail", "aws_cloudwatch_log_group", "aws_s3_bucket"]
    },
    {
        "id": "AU.L2-3.3.2",
        "family": "AU",
        "title": "User Accountability",
        "description": "Ensure that the actions of individual system users can be uniquely traced to those users.",
        "nist_mapping": "3.3.2",
        "cmmc_level": 2,
        "objectives": [
            "Content of audit records supports user accountability",
            "Audit records uniquely trace actions to users"
        ],
        "aws_services": ["cloudtrail", "iam"],
        "terraform_resources": ["aws_cloudtrail", "aws_iam_user"]
    },
    # Identification and Authentication (IA)
    {
        "id": "IA.L2-3.5.1",
        "family": "IA",
        "title": "Identification",
        "description": "Identify system users, processes acting on behalf of users, and devices.",
        "nist_mapping": "3.5.1",
        "cmmc_level": 2,
        "objectives": [
            "System users are identified",
            "Processes acting on behalf of users are identified",
            "Devices accessing the system are identified"
        ],
        "aws_services": ["iam", "cognito"],
        "terraform_resources": ["aws_iam_user", "aws_iam_role"]
    },
    {
        "id": "IA.L2-3.5.2",
        "family": "IA",
        "title": "Authentication",
        "description": "Authenticate (or verify) the identities of users, processes, or devices, as a prerequisite to allowing access.",
        "nist_mapping": "3.5.2",
        "cmmc_level": 2,
        "objectives": [
            "Identity of each user is authenticated or verified as a prerequisite to access",
            "Identity of each process acting on behalf of a user is authenticated or verified as a prerequisite to access",
            "Identity of each device is authenticated or verified as a prerequisite to access"
        ],
        "aws_services": ["iam", "cognito", "sso"],
        "terraform_resources": ["aws_iam_user", "aws_iam_role", "aws_iam_policy"]
    },
    {
        "id": "IA.L2-3.5.3",
        "family": "IA",
        "title": "Multi-Factor Authentication",
        "description": "Use multi-factor authentication for local and network access to privileged accounts and for network access to non-privileged accounts.",
        "nist_mapping": "3.5.3",
        "cmmc_level": 2,
        "objectives": [
            "Privileged accounts are identified",
            "MFA is implemented for local access to privileged accounts",
            "MFA is implemented for network access to privileged accounts",
            "MFA is implemented for network access to non-privileged accounts"
        ],
        "aws_services": ["iam", "cognito"],
        "terraform_resources": ["aws_iam_user", "aws_iam_account_password_policy"]
    },
    # System and Communications Protection (SC)
    {
        "id": "SC.L2-3.13.1",
        "family": "SC",
        "title": "Boundary Protection",
        "description": "Monitor, control, and protect communications at external boundaries and key internal boundaries.",
        "nist_mapping": "3.13.1",
        "cmmc_level": 2,
        "objectives": [
            "External system boundaries are identified",
            "Key internal system boundaries are identified",
            "Communications at external boundaries are monitored",
            "Communications at key internal boundaries are monitored",
            "Communications at external boundaries are controlled",
            "Communications at key internal boundaries are controlled",
            "Communications at external boundaries are protected",
            "Communications at key internal boundaries are protected"
        ],
        "aws_services": ["vpc", "network_firewall", "waf", "security_group"],
        "terraform_resources": ["aws_vpc", "aws_security_group", "aws_network_acl"]
    },
    {
        "id": "SC.L2-3.13.8",
        "family": "SC",
        "title": "Data in Transit",
        "description": "Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI during transmission.",
        "nist_mapping": "3.13.8",
        "cmmc_level": 2,
        "objectives": [
            "Cryptographic mechanisms to prevent unauthorized disclosure are identified",
            "Cryptographic mechanisms are implemented to prevent unauthorized disclosure during transmission"
        ],
        "aws_services": ["acm", "cloudfront", "elb", "api_gateway"],
        "terraform_resources": ["aws_acm_certificate", "aws_lb_listener", "aws_cloudfront_distribution"]
    },
    {
        "id": "SC.L2-3.13.11",
        "family": "SC",
        "title": "CUI Encryption",
        "description": "Employ FIPS-validated cryptography when used to protect the confidentiality of CUI.",
        "nist_mapping": "3.13.11",
        "cmmc_level": 2,
        "objectives": [
            "FIPS-validated cryptography is employed to protect CUI"
        ],
        "aws_services": ["kms", "s3", "ebs", "rds"],
        "terraform_resources": ["aws_kms_key", "aws_s3_bucket", "aws_ebs_volume", "aws_rds_instance"]
    },
    {
        "id": "SC.L2-3.13.16",
        "family": "SC",
        "title": "Data at Rest",
        "description": "Protect the confidentiality of CUI at rest.",
        "nist_mapping": "3.13.16",
        "cmmc_level": 2,
        "objectives": [
            "CUI at rest is identified",
            "Confidentiality of CUI at rest is protected"
        ],
        "aws_services": ["kms", "s3", "ebs", "rds"],
        "terraform_resources": ["aws_s3_bucket", "aws_ebs_volume", "aws_rds_instance", "aws_kms_key"]
    },
    # System and Information Integrity (SI)
    {
        "id": "SI.L2-3.14.1",
        "family": "SI",
        "title": "Flaw Remediation",
        "description": "Identify, report, and correct system flaws in a timely manner.",
        "nist_mapping": "3.14.1",
        "cmmc_level": 2,
        "objectives": [
            "Time within which to identify system flaws is specified",
            "System flaws are identified within specified time",
            "Time within which to report system flaws is specified",
            "System flaws are reported within specified time",
            "Time within which to correct system flaws is specified",
            "System flaws are corrected within specified time"
        ],
        "aws_services": ["inspector", "systems_manager", "config"],
        "terraform_resources": ["aws_inspector_assessment_target", "aws_config_rule"]
    },
    {
        "id": "SI.L2-3.14.2",
        "family": "SI",
        "title": "Malicious Code Protection",
        "description": "Provide protection from malicious code at designated locations.",
        "nist_mapping": "3.14.2",
        "cmmc_level": 2,
        "objectives": [
            "Designated locations for malicious code protection are identified",
            "Protection from malicious code at designated locations is provided"
        ],
        "aws_services": ["guardduty", "macie", "security_hub"],
        "terraform_resources": ["aws_guardduty_detector"]
    },
    {
        "id": "SI.L2-3.14.6",
        "family": "SI",
        "title": "Security Alerts",
        "description": "Monitor organizational systems, including inbound and outbound communications traffic, to detect attacks and indicators of potential attacks.",
        "nist_mapping": "3.14.6",
        "cmmc_level": 2,
        "objectives": [
            "The system is monitored to detect attacks and indicators of potential attacks",
            "Inbound communications traffic is monitored to detect attacks and indicators of potential attacks",
            "Outbound communications traffic is monitored to detect attacks and indicators of potential attacks"
        ],
        "aws_services": ["guardduty", "cloudwatch", "vpc_flow_logs"],
        "terraform_resources": ["aws_guardduty_detector", "aws_cloudwatch_metric_alarm", "aws_flow_log"]
    },
    # Configuration Management (CM)
    {
        "id": "CM.L2-3.4.1",
        "family": "CM",
        "title": "System Baselining",
        "description": "Establish and maintain baseline configurations and inventories of organizational systems.",
        "nist_mapping": "3.4.1",
        "cmmc_level": 2,
        "objectives": [
            "A baseline configuration is established",
            "A baseline configuration is maintained",
            "A system inventory is established",
            "A system inventory is maintained"
        ],
        "aws_services": ["config", "systems_manager", "service_catalog"],
        "terraform_resources": ["aws_config_configuration_recorder", "aws_ssm_document"]
    },
    {
        "id": "CM.L2-3.4.2",
        "family": "CM",
        "title": "Security Configuration Enforcement",
        "description": "Establish and enforce security configuration settings for information technology products.",
        "nist_mapping": "3.4.2",
        "cmmc_level": 2,
        "objectives": [
            "Security configuration settings are established and documented",
            "Security configuration settings are enforced"
        ],
        "aws_services": ["config", "systems_manager"],
        "terraform_resources": ["aws_config_rule", "aws_ssm_association"]
    },
]


def get_practices_by_family(family_code: str) -> List[Dict]:
    """Get all practices for a specific family."""
    return [p for p in CMMC_L2_PRACTICES if p["family"] == family_code.upper()]


def get_practice_by_id(practice_id: str) -> Dict:
    """Get a specific practice by ID."""
    for practice in CMMC_L2_PRACTICES:
        if practice["id"] == practice_id:
            return practice
    return None


def get_practices_for_terraform_resource(resource_type: str) -> List[Dict]:
    """Get practices relevant to a Terraform resource type."""
    return [
        p for p in CMMC_L2_PRACTICES
        if resource_type in p.get("terraform_resources", [])
    ]

#!/usr/bin/env python3
"""
CMMC Control Validator - Control Families
NIST 800-171 / CMMC control family definitions.

Author: Cameron Hopkin
License: MIT
"""
from typing import Dict, List
from dataclasses import dataclass


@dataclass
class FamilyInfo:
    """Information about a control family."""
    code: str
    name: str
    description: str
    nist_section: str
    control_count_l2: int


CONTROL_FAMILIES: Dict[str, FamilyInfo] = {
    "AC": FamilyInfo(
        code="AC",
        name="Access Control",
        description="Limit system access to authorized users, processes acting on behalf of authorized users, and devices.",
        nist_section="3.1",
        control_count_l2=22
    ),
    "AT": FamilyInfo(
        code="AT",
        name="Awareness and Training",
        description="Ensure that managers and users are aware of security risks and policies.",
        nist_section="3.2",
        control_count_l2=3
    ),
    "AU": FamilyInfo(
        code="AU",
        name="Audit and Accountability",
        description="Create, protect, and retain system audit records for monitoring, analysis, investigation, and reporting.",
        nist_section="3.3",
        control_count_l2=9
    ),
    "CM": FamilyInfo(
        code="CM",
        name="Configuration Management",
        description="Establish and maintain baseline configurations and inventories of systems.",
        nist_section="3.4",
        control_count_l2=9
    ),
    "IA": FamilyInfo(
        code="IA",
        name="Identification and Authentication",
        description="Identify and authenticate users, processes, or devices before allowing access.",
        nist_section="3.5",
        control_count_l2=11
    ),
    "IR": FamilyInfo(
        code="IR",
        name="Incident Response",
        description="Establish operational incident-handling capability including preparation, detection, analysis, containment, recovery, and user response.",
        nist_section="3.6",
        control_count_l2=3
    ),
    "MA": FamilyInfo(
        code="MA",
        name="Maintenance",
        description="Perform maintenance on organizational systems.",
        nist_section="3.7",
        control_count_l2=6
    ),
    "MP": FamilyInfo(
        code="MP",
        name="Media Protection",
        description="Protect system media containing CUI, both paper and digital.",
        nist_section="3.8",
        control_count_l2=9
    ),
    "PE": FamilyInfo(
        code="PE",
        name="Physical Protection",
        description="Limit physical access to systems, equipment, and operating environments.",
        nist_section="3.10",
        control_count_l2=6
    ),
    "PS": FamilyInfo(
        code="PS",
        name="Personnel Security",
        description="Screen individuals prior to authorizing access and ensure CUI is protected during personnel actions.",
        nist_section="3.9",
        control_count_l2=2
    ),
    "RA": FamilyInfo(
        code="RA",
        name="Risk Assessment",
        description="Periodically assess risk to organizational operations, assets, and individuals.",
        nist_section="3.11",
        control_count_l2=3
    ),
    "CA": FamilyInfo(
        code="CA",
        name="Security Assessment",
        description="Periodically assess security controls, develop and implement plans of action, and monitor security controls on an ongoing basis.",
        nist_section="3.12",
        control_count_l2=4
    ),
    "SC": FamilyInfo(
        code="SC",
        name="System and Communications Protection",
        description="Monitor, control, and protect communications at external and key internal boundaries.",
        nist_section="3.13",
        control_count_l2=16
    ),
    "SI": FamilyInfo(
        code="SI",
        name="System and Information Integrity",
        description="Identify, report, and correct system flaws in a timely manner.",
        nist_section="3.14",
        control_count_l2=7
    ),
}


def get_family_description(code: str) -> str:
    """Get description for a control family code."""
    family = CONTROL_FAMILIES.get(code.upper())
    return family.description if family else "Unknown control family"


def get_family_info(code: str) -> FamilyInfo:
    """Get full info for a control family."""
    return CONTROL_FAMILIES.get(code.upper())


def get_all_families() -> List[FamilyInfo]:
    """Get all control families."""
    return list(CONTROL_FAMILIES.values())


def get_total_l2_controls() -> int:
    """Get total number of CMMC L2 controls."""
    return sum(f.control_count_l2 for f in CONTROL_FAMILIES.values())


# AWS service relevance mapping by family
AWS_FAMILY_RELEVANCE: Dict[str, List[str]] = {
    "AC": ["iam", "cognito", "sso", "directory_service", "vpc", "security_group"],
    "AU": ["cloudtrail", "cloudwatch", "config", "s3", "kinesis"],
    "CM": ["config", "systems_manager", "cloudformation", "service_catalog"],
    "IA": ["iam", "cognito", "sso", "kms", "secrets_manager"],
    "IR": ["guardduty", "security_hub", "detective", "sns", "lambda"],
    "MA": ["systems_manager", "patch_manager"],
    "MP": ["s3", "ebs", "kms", "glacier", "macie"],
    "RA": ["inspector", "security_hub", "guardduty", "trusted_advisor"],
    "CA": ["security_hub", "config", "audit_manager"],
    "SC": ["vpc", "waf", "shield", "network_firewall", "acm", "kms", "cloudfront"],
    "SI": ["guardduty", "inspector", "macie", "config", "systems_manager"],
}


def get_aws_services_for_family(code: str) -> List[str]:
    """Get relevant AWS services for a control family."""
    return AWS_FAMILY_RELEVANCE.get(code.upper(), [])

#!/usr/bin/env python3
"""
CMMC Control Validator - Control Mapper
Maps infrastructure-as-code to CMMC/NIST 800-171 controls.

Author: Cameron Hopkin
License: MIT
"""
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import json


class ControlFamily(Enum):
    """NIST 800-171 / CMMC Control Families."""
    AC = "Access Control"
    AU = "Audit and Accountability"
    AT = "Awareness and Training"
    CM = "Configuration Management"
    IA = "Identification and Authentication"
    IR = "Incident Response"
    MA = "Maintenance"
    MP = "Media Protection"
    PE = "Physical Protection"
    PS = "Personnel Security"
    RA = "Risk Assessment"
    CA = "Security Assessment"
    SC = "System and Communications Protection"
    SI = "System and Information Integrity"


class ComplianceStatus(Enum):
    """Compliance status for a control."""
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    INHERITED = "inherited"
    UNKNOWN = "unknown"


@dataclass
class Control:
    """Represents a CMMC/NIST control."""
    id: str                          # e.g., "AC.L2-3.1.1"
    family: ControlFamily
    title: str
    description: str
    nist_mapping: str                # e.g., "3.1.1"
    cmmc_level: int                  # 1, 2, or 3
    assessment_objectives: List[str] = field(default_factory=list)
    aws_services: List[str] = field(default_factory=list)
    terraform_resources: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """A compliance finding/gap."""
    control: Control
    status: ComplianceStatus
    resource_type: str
    resource_name: str
    message: str
    remediation: str
    evidence: Dict = field(default_factory=dict)
    severity: str = "medium"

    def to_dict(self) -> Dict:
        """Convert finding to dictionary."""
        return {
            "control_id": self.control.id,
            "control_title": self.control.title,
            "family": self.control.family.value,
            "status": self.status.value,
            "resource_type": self.resource_type,
            "resource_name": self.resource_name,
            "message": self.message,
            "remediation": self.remediation,
            "severity": self.severity,
            "evidence": self.evidence,
        }


@dataclass
class ValidationResult:
    """Results of a validation run."""
    total_controls: int
    compliant: int
    partial: int
    non_compliant: int
    not_applicable: int
    findings: List[Finding] = field(default_factory=list)

    @property
    def compliance_score(self) -> float:
        """Calculate compliance percentage."""
        applicable = self.total_controls - self.not_applicable
        if applicable == 0:
            return 100.0
        return (self.compliant / applicable) * 100

    @property
    def findings_by_severity(self) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts

    def to_dict(self) -> Dict:
        """Convert result to dictionary."""
        return {
            "summary": {
                "total_controls": self.total_controls,
                "compliant": self.compliant,
                "partial": self.partial,
                "non_compliant": self.non_compliant,
                "not_applicable": self.not_applicable,
                "compliance_score": round(self.compliance_score, 1),
            },
            "findings_by_severity": self.findings_by_severity,
            "findings": [f.to_dict() for f in self.findings],
        }


class ControlMapper:
    """
    Maps infrastructure configurations to CMMC/NIST controls.

    Loads control definitions and AWS service mappings,
    then validates IaC against required controls.
    """

    def __init__(self, data_dir: Optional[Path] = None):
        self.data_dir = data_dir or Path(__file__).parent.parent.parent.parent / "data"
        self.controls: Dict[str, Control] = {}
        self.aws_mappings: Dict[str, List[str]] = {}
        self._load_controls()
        self._load_aws_mappings()

    def _load_controls(self):
        """Load CMMC L2 control definitions."""
        controls_file = self.data_dir / "cmmc_l2_practices.json"
        if controls_file.exists():
            with open(controls_file) as f:
                data = json.load(f)
                for ctrl in data.get("controls", []):
                    control = Control(
                        id=ctrl["id"],
                        family=ControlFamily[ctrl["family"]],
                        title=ctrl["title"],
                        description=ctrl["description"],
                        nist_mapping=ctrl["nist_mapping"],
                        cmmc_level=ctrl.get("cmmc_level", 2),
                        assessment_objectives=ctrl.get("objectives", []),
                        aws_services=ctrl.get("aws_services", []),
                        terraform_resources=ctrl.get("terraform_resources", [])
                    )
                    self.controls[control.id] = control

    def _load_aws_mappings(self):
        """Load AWS service to control mappings."""
        mapping_file = self.data_dir / "control_to_aws_mapping.json"
        if mapping_file.exists():
            with open(mapping_file) as f:
                self.aws_mappings = json.load(f)

    def get_controls_by_family(self, family: ControlFamily) -> List[Control]:
        """Get all controls for a specific family."""
        return [c for c in self.controls.values() if c.family == family]

    def get_controls_for_aws_service(self, service: str) -> List[Control]:
        """Get controls relevant to an AWS service."""
        control_ids = self.aws_mappings.get(service.lower(), [])
        return [self.controls[cid] for cid in control_ids if cid in self.controls]

    def get_all_controls(self) -> List[Control]:
        """Get all loaded controls."""
        return list(self.controls.values())

    def validate_terraform_resource(
        self,
        resource_type: str,
        resource_config: Dict
    ) -> List[Finding]:
        """
        Validate a Terraform resource against applicable controls.

        Args:
            resource_type: e.g., "aws_s3_bucket", "aws_iam_role"
            resource_config: The resource configuration dict

        Returns:
            List of findings (gaps or compliance confirmations)
        """
        findings = []

        # Map Terraform resource to AWS service
        service = self._terraform_to_aws_service(resource_type)
        applicable_controls = self.get_controls_for_aws_service(service)

        for control in applicable_controls:
            finding = self._check_control(control, resource_type, resource_config)
            findings.append(finding)

        return findings

    def _terraform_to_aws_service(self, resource_type: str) -> str:
        """Map Terraform resource type to AWS service name."""
        mappings = {
            "aws_s3_bucket": "s3",
            "aws_s3_bucket_versioning": "s3",
            "aws_s3_bucket_server_side_encryption_configuration": "s3",
            "aws_s3_bucket_public_access_block": "s3",
            "aws_iam_role": "iam",
            "aws_iam_policy": "iam",
            "aws_iam_user": "iam",
            "aws_iam_group": "iam",
            "aws_kms_key": "kms",
            "aws_kms_alias": "kms",
            "aws_cloudtrail": "cloudtrail",
            "aws_config_rule": "config",
            "aws_config_configuration_recorder": "config",
            "aws_guardduty_detector": "guardduty",
            "aws_security_group": "vpc",
            "aws_vpc": "vpc",
            "aws_subnet": "vpc",
            "aws_network_acl": "vpc",
            "aws_eks_cluster": "eks",
            "aws_lambda_function": "lambda",
            "aws_rds_instance": "rds",
            "aws_rds_cluster": "rds",
            "aws_secretsmanager_secret": "secretsmanager",
            "aws_ssm_parameter": "ssm",
        }
        return mappings.get(resource_type, resource_type.replace("aws_", ""))

    def _check_control(
        self,
        control: Control,
        resource_type: str,
        config: Dict
    ) -> Finding:
        """Check a specific control against resource configuration."""
        # Import checkers here to avoid circular imports
        from ..checks.access_control import check_access_control
        from ..checks.system_comm import check_system_comms
        from ..checks.system_integrity import check_system_integrity
        from ..checks.identification_auth import check_identification_auth

        # Delegate to specific family checkers
        checker_map = {
            ControlFamily.AC: check_access_control,
            ControlFamily.SC: check_system_comms,
            ControlFamily.SI: check_system_integrity,
            ControlFamily.IA: check_identification_auth,
        }

        checker = checker_map.get(control.family)
        if checker:
            return checker(control, resource_type, config)

        # Default: unknown status requiring manual review
        return Finding(
            control=control,
            status=ComplianceStatus.UNKNOWN,
            resource_type=resource_type,
            resource_name=config.get("name", config.get("bucket", "unknown")),
            message="Automated check not available - manual review required",
            remediation="Review control requirements and validate configuration"
        )

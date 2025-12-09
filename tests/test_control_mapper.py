#!/usr/bin/env python3
"""
CMMC Control Validator - Control Mapper Tests

Author: Cameron Hopkin
License: MIT
"""
import pytest

from cmmc_validator.core.control_mapper import ControlMapper, ValidationResult, ComplianceStatus
from cmmc_validator.controls.control_families import ControlFamily


class TestControlMapper:
    """Test suite for ControlMapper."""

    def test_mapper_initialization(self):
        """Test ControlMapper can be initialized."""
        mapper = ControlMapper()
        assert mapper is not None

    def test_get_all_controls(self):
        """Test getting all controls."""
        mapper = ControlMapper()
        controls = mapper.get_all_controls()

        assert len(controls) > 0

    def test_get_controls_by_family(self):
        """Test getting controls by family."""
        mapper = ControlMapper()
        ac_controls = mapper.get_controls_by_family(ControlFamily.ACCESS_CONTROL)

        assert len(ac_controls) > 0
        for control in ac_controls:
            assert control.family == ControlFamily.ACCESS_CONTROL

    def test_validate_s3_bucket_unencrypted(self, sample_s3_config):
        """Test validation of unencrypted S3 bucket."""
        mapper = ControlMapper()
        findings = mapper.validate_terraform_resource("aws_s3_bucket", sample_s3_config)

        # Should have findings related to encryption
        encryption_findings = [
            f for f in findings
            if "encrypt" in f.message.lower() or "SC" in f.control.id
        ]
        assert len(encryption_findings) > 0

    def test_validate_security_group_open_ssh(self, sample_security_group_config):
        """Test validation of security group with open SSH."""
        mapper = ControlMapper()
        findings = mapper.validate_terraform_resource(
            "aws_security_group",
            sample_security_group_config
        )

        # Should have findings about unrestricted access
        ssh_findings = [
            f for f in findings
            if "ssh" in f.message.lower() or "0.0.0.0" in f.message
        ]
        assert len(ssh_findings) > 0

    def test_validate_iam_policy_overly_permissive(self, sample_iam_policy_config):
        """Test validation of overly permissive IAM policy."""
        mapper = ControlMapper()
        findings = mapper.validate_terraform_resource(
            "aws_iam_policy",
            sample_iam_policy_config
        )

        # Should have findings about least privilege
        privilege_findings = [
            f for f in findings
            if "privilege" in f.message.lower() or "wildcard" in f.message.lower()
        ]
        assert len(privilege_findings) > 0


class TestValidationResult:
    """Test suite for ValidationResult."""

    def test_validation_result_creation(self):
        """Test creating ValidationResult."""
        mapper = ControlMapper()
        controls = mapper.get_all_controls()

        if controls:
            result = ValidationResult(
                control=controls[0],
                status=ComplianceStatus.COMPLIANT,
                message="Test message",
                resource_type="aws_s3_bucket",
                resource_name="test_bucket"
            )

            assert result.status == ComplianceStatus.COMPLIANT
            assert result.message == "Test message"


class TestComplianceStatus:
    """Test suite for ComplianceStatus enum."""

    def test_compliance_status_values(self):
        """Test ComplianceStatus enum values."""
        assert ComplianceStatus.COMPLIANT.value == "compliant"
        assert ComplianceStatus.NON_COMPLIANT.value == "non_compliant"
        assert ComplianceStatus.PARTIAL.value == "partial"
        assert ComplianceStatus.NOT_APPLICABLE.value == "not_applicable"


class TestControlFamily:
    """Test suite for ControlFamily enum."""

    def test_control_family_values(self):
        """Test ControlFamily enum contains expected families."""
        families = list(ControlFamily)

        family_names = [f.name for f in families]
        assert "ACCESS_CONTROL" in family_names
        assert "AUDIT_ACCOUNTABILITY" in family_names
        assert "SYSTEM_COMM_PROTECTION" in family_names
        assert "SYSTEM_INFO_INTEGRITY" in family_names

    def test_control_family_has_values(self):
        """Test ControlFamily enum has proper values."""
        assert ControlFamily.ACCESS_CONTROL.value == "Access Control"
        assert ControlFamily.AUDIT_ACCOUNTABILITY.value == "Audit and Accountability"

#!/usr/bin/env python3
"""
CMMC Control Validator - Findings Tests

Author: Cameron Hopkin
License: MIT
"""
import pytest
import json

from cmmc_validator.core.findings import FindingCollection, Finding
from cmmc_validator.core.control_mapper import ComplianceStatus, Control
from cmmc_validator.controls.control_families import ControlFamily


@pytest.fixture
def sample_control():
    """Create a sample control for testing."""
    return Control(
        id="AC.L2-3.1.1",
        family=ControlFamily.ACCESS_CONTROL,
        title="Authorized Access Control",
        description="Limit system access to authorized users."
    )


@pytest.fixture
def sample_finding(sample_control):
    """Create a sample finding for testing."""
    return Finding(
        control=sample_control,
        status=ComplianceStatus.NON_COMPLIANT,
        message="Test finding message",
        resource_type="aws_s3_bucket",
        resource_name="test_bucket",
        severity="high"
    )


@pytest.fixture
def sample_findings(sample_control):
    """Create multiple sample findings for testing."""
    findings = [
        Finding(
            control=sample_control,
            status=ComplianceStatus.COMPLIANT,
            message="Compliant finding",
            resource_type="aws_s3_bucket",
            resource_name="bucket1",
            severity="info"
        ),
        Finding(
            control=sample_control,
            status=ComplianceStatus.NON_COMPLIANT,
            message="Non-compliant finding 1",
            resource_type="aws_s3_bucket",
            resource_name="bucket2",
            severity="high"
        ),
        Finding(
            control=sample_control,
            status=ComplianceStatus.NON_COMPLIANT,
            message="Non-compliant finding 2",
            resource_type="aws_security_group",
            resource_name="sg1",
            severity="critical"
        ),
        Finding(
            control=sample_control,
            status=ComplianceStatus.PARTIAL,
            message="Partial finding",
            resource_type="aws_iam_policy",
            resource_name="policy1",
            severity="medium"
        ),
    ]
    return findings


class TestFindingCollection:
    """Test suite for FindingCollection."""

    def test_collection_initialization(self):
        """Test FindingCollection can be initialized."""
        collection = FindingCollection(scan_target="./terraform/")
        assert collection is not None
        assert collection.scan_target == "./terraform/"

    def test_add_finding(self, sample_finding):
        """Test adding a finding to collection."""
        collection = FindingCollection(scan_target="./test/")
        collection.add(sample_finding)

        assert len(collection) == 1

    def test_add_all_findings(self, sample_findings):
        """Test adding multiple findings."""
        collection = FindingCollection(scan_target="./test/")
        collection.add_all(sample_findings)

        assert len(collection) == len(sample_findings)

    def test_filter_by_status(self, sample_findings):
        """Test filtering findings by status."""
        collection = FindingCollection(scan_target="./test/")
        collection.add_all(sample_findings)

        compliant = collection.filter_by_status(ComplianceStatus.COMPLIANT)
        non_compliant = collection.filter_by_status(ComplianceStatus.NON_COMPLIANT)
        partial = collection.filter_by_status(ComplianceStatus.PARTIAL)

        assert len(compliant) == 1
        assert len(non_compliant) == 2
        assert len(partial) == 1

    def test_filter_by_severity(self, sample_findings):
        """Test filtering findings by severity."""
        collection = FindingCollection(scan_target="./test/")
        collection.add_all(sample_findings)

        high_severity = collection.filter_by_severity("high")
        critical_severity = collection.filter_by_severity("critical")

        assert len(high_severity) == 1
        assert len(critical_severity) == 1

    def test_status_counts(self, sample_findings):
        """Test getting status counts."""
        collection = FindingCollection(scan_target="./test/")
        collection.add_all(sample_findings)

        counts = collection.status_counts

        assert counts["compliant"] == 1
        assert counts["non_compliant"] == 2
        assert counts["partial"] == 1

    def test_compliance_rate(self, sample_findings):
        """Test calculating compliance rate."""
        collection = FindingCollection(scan_target="./test/")
        collection.add_all(sample_findings)

        rate = collection.compliance_rate

        # 1 compliant out of 4 total = 25%
        assert rate == 25.0

    def test_family_counts(self, sample_findings):
        """Test getting findings by family."""
        collection = FindingCollection(scan_target="./test/")
        collection.add_all(sample_findings)

        family_counts = collection.family_counts

        assert ControlFamily.ACCESS_CONTROL.value in family_counts

    def test_get_priority_findings(self, sample_findings):
        """Test getting priority findings."""
        collection = FindingCollection(scan_target="./test/")
        collection.add_all(sample_findings)

        priority = collection.get_priority_findings(2)

        # Should get critical and high severity first
        assert len(priority) == 2
        assert priority[0].severity == "critical"

    def test_to_json(self, sample_findings):
        """Test JSON serialization."""
        collection = FindingCollection(scan_target="./test/")
        collection.add_all(sample_findings)

        json_str = collection.to_json()
        data = json.loads(json_str)

        assert "findings" in data
        assert "summary" in data
        assert data["scan_target"] == "./test/"

    def test_empty_collection(self):
        """Test empty collection behavior."""
        collection = FindingCollection(scan_target="./test/")

        assert len(collection) == 0
        assert collection.compliance_rate == 100.0
        assert collection.status_counts["compliant"] == 0

    def test_iteration(self, sample_findings):
        """Test iterating over collection."""
        collection = FindingCollection(scan_target="./test/")
        collection.add_all(sample_findings)

        count = 0
        for finding in collection:
            count += 1
            assert isinstance(finding, Finding)

        assert count == len(sample_findings)


class TestFinding:
    """Test suite for Finding dataclass."""

    def test_finding_creation(self, sample_control):
        """Test creating a Finding."""
        finding = Finding(
            control=sample_control,
            status=ComplianceStatus.COMPLIANT,
            message="Test message",
            resource_type="aws_s3_bucket",
            resource_name="test_bucket",
            severity="low"
        )

        assert finding.control == sample_control
        assert finding.status == ComplianceStatus.COMPLIANT
        assert finding.severity == "low"

    def test_finding_to_dict(self, sample_finding):
        """Test Finding to_dict method."""
        data = sample_finding.to_dict()

        assert "control_id" in data
        assert "status" in data
        assert "message" in data
        assert "severity" in data

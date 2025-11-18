#!/usr/bin/env python3
"""
CMMC Control Validator - Findings Management
Data structures and utilities for managing compliance findings.

Author: Cameron Hopkin
License: MIT
"""
from typing import Dict, List, Optional, Iterator
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json

from .control_mapper import Finding, ComplianceStatus, ControlFamily


class FindingSeverity(Enum):
    """Severity levels for findings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class FindingCollection:
    """
    Collection of compliance findings with filtering and reporting capabilities.
    """
    findings: List[Finding] = field(default_factory=list)
    scan_timestamp: datetime = field(default_factory=datetime.utcnow)
    scan_target: str = ""
    metadata: Dict = field(default_factory=dict)

    def add(self, finding: Finding) -> None:
        """Add a finding to the collection."""
        self.findings.append(finding)

    def add_all(self, findings: List[Finding]) -> None:
        """Add multiple findings."""
        self.findings.extend(findings)

    def __len__(self) -> int:
        return len(self.findings)

    def __iter__(self) -> Iterator[Finding]:
        return iter(self.findings)

    # Filtering methods

    def filter_by_status(self, status: ComplianceStatus) -> "FindingCollection":
        """Get findings with specific status."""
        filtered = [f for f in self.findings if f.status == status]
        return FindingCollection(
            findings=filtered,
            scan_timestamp=self.scan_timestamp,
            scan_target=self.scan_target
        )

    def filter_by_family(self, family: ControlFamily) -> "FindingCollection":
        """Get findings for specific control family."""
        filtered = [f for f in self.findings if f.control.family == family]
        return FindingCollection(
            findings=filtered,
            scan_timestamp=self.scan_timestamp,
            scan_target=self.scan_target
        )

    def filter_by_severity(self, severity: str) -> "FindingCollection":
        """Get findings with specific severity."""
        filtered = [f for f in self.findings if f.severity == severity]
        return FindingCollection(
            findings=filtered,
            scan_timestamp=self.scan_timestamp,
            scan_target=self.scan_target
        )

    def filter_non_compliant(self) -> "FindingCollection":
        """Get only non-compliant findings."""
        non_compliant_statuses = {
            ComplianceStatus.NON_COMPLIANT,
            ComplianceStatus.PARTIAL
        }
        filtered = [f for f in self.findings if f.status in non_compliant_statuses]
        return FindingCollection(
            findings=filtered,
            scan_timestamp=self.scan_timestamp,
            scan_target=self.scan_target
        )

    def filter_by_resource_type(self, resource_type: str) -> "FindingCollection":
        """Get findings for specific resource type."""
        filtered = [f for f in self.findings if f.resource_type == resource_type]
        return FindingCollection(
            findings=filtered,
            scan_timestamp=self.scan_timestamp,
            scan_target=self.scan_target
        )

    # Statistics methods

    @property
    def status_counts(self) -> Dict[str, int]:
        """Count findings by status."""
        counts = {status.value: 0 for status in ComplianceStatus}
        for finding in self.findings:
            counts[finding.status.value] += 1
        return counts

    @property
    def severity_counts(self) -> Dict[str, int]:
        """Count findings by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.findings:
            if finding.severity in counts:
                counts[finding.severity] += 1
        return counts

    @property
    def family_counts(self) -> Dict[str, int]:
        """Count findings by control family."""
        counts = {family.name: 0 for family in ControlFamily}
        for finding in self.findings:
            counts[finding.control.family.name] += 1
        return counts

    @property
    def resource_type_counts(self) -> Dict[str, int]:
        """Count findings by resource type."""
        counts: Dict[str, int] = {}
        for finding in self.findings:
            rt = finding.resource_type
            counts[rt] = counts.get(rt, 0) + 1
        return counts

    @property
    def compliance_rate(self) -> float:
        """Calculate overall compliance rate."""
        if not self.findings:
            return 100.0

        compliant = sum(
            1 for f in self.findings
            if f.status == ComplianceStatus.COMPLIANT
        )
        applicable = sum(
            1 for f in self.findings
            if f.status != ComplianceStatus.NOT_APPLICABLE
        )

        if applicable == 0:
            return 100.0

        return (compliant / applicable) * 100

    # Grouping methods

    def group_by_family(self) -> Dict[ControlFamily, List[Finding]]:
        """Group findings by control family."""
        groups: Dict[ControlFamily, List[Finding]] = {}
        for finding in self.findings:
            family = finding.control.family
            if family not in groups:
                groups[family] = []
            groups[family].append(finding)
        return groups

    def group_by_resource(self) -> Dict[str, List[Finding]]:
        """Group findings by resource name."""
        groups: Dict[str, List[Finding]] = {}
        for finding in self.findings:
            key = f"{finding.resource_type}.{finding.resource_name}"
            if key not in groups:
                groups[key] = []
            groups[key].append(finding)
        return groups

    def group_by_status(self) -> Dict[ComplianceStatus, List[Finding]]:
        """Group findings by compliance status."""
        groups: Dict[ComplianceStatus, List[Finding]] = {}
        for finding in self.findings:
            if finding.status not in groups:
                groups[finding.status] = []
            groups[finding.status].append(finding)
        return groups

    # Export methods

    def to_dict(self) -> Dict:
        """Convert collection to dictionary."""
        return {
            "scan_info": {
                "timestamp": self.scan_timestamp.isoformat(),
                "target": self.scan_target,
                "total_findings": len(self.findings),
            },
            "summary": {
                "by_status": self.status_counts,
                "by_severity": self.severity_counts,
                "by_family": self.family_counts,
                "compliance_rate": round(self.compliance_rate, 1),
            },
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert collection to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save_json(self, filepath: str) -> None:
        """Save collection to JSON file."""
        with open(filepath, 'w') as f:
            f.write(self.to_json())

    # Priority sorting

    def get_priority_findings(self, limit: int = 10) -> List[Finding]:
        """
        Get highest priority findings for remediation.

        Priority is based on severity and compliance status.
        """
        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "info": 4
        }

        status_order = {
            ComplianceStatus.NON_COMPLIANT: 0,
            ComplianceStatus.PARTIAL: 1,
            ComplianceStatus.UNKNOWN: 2,
            ComplianceStatus.COMPLIANT: 3,
            ComplianceStatus.NOT_APPLICABLE: 4,
            ComplianceStatus.INHERITED: 5,
        }

        sorted_findings = sorted(
            self.findings,
            key=lambda f: (
                severity_order.get(f.severity, 99),
                status_order.get(f.status, 99)
            )
        )

        return sorted_findings[:limit]

    # Unique controls

    def get_unique_controls(self) -> List[str]:
        """Get list of unique control IDs."""
        return list(set(f.control.id for f in self.findings))

    def get_affected_resources(self) -> List[str]:
        """Get list of unique affected resources."""
        return list(set(
            f"{f.resource_type}.{f.resource_name}"
            for f in self.findings
        ))

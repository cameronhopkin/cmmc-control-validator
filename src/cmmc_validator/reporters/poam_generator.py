#!/usr/bin/env python3
"""
CMMC Control Validator - POA&M Generator
Generate Plan of Action and Milestones documents.

Author: Cameron Hopkin
License: MIT
"""
import csv
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional
from dataclasses import dataclass, field

from ..core.findings import FindingCollection
from ..core.control_mapper import Finding, ComplianceStatus


@dataclass
class POAMItem:
    """A single POA&M line item."""
    poam_id: str
    control_id: str
    weakness_description: str
    remediation_plan: str
    severity: str
    status: str = "Open"
    scheduled_completion: str = ""
    milestones: List[str] = field(default_factory=list)
    resource_required: str = ""
    responsible_party: str = ""
    comments: str = ""


class POAMGenerator:
    """
    Generate Plan of Action and Milestones (POA&M) documents.

    Creates POA&M in multiple formats (CSV, JSON, HTML) for
    tracking remediation of compliance gaps.
    """

    # Default remediation timeframes by severity
    DEFAULT_TIMEFRAMES = {
        "critical": 30,   # days
        "high": 60,
        "medium": 90,
        "low": 180,
        "info": 365,
    }

    def __init__(
        self,
        findings: FindingCollection,
        organization: str = "",
        system_name: str = "",
        start_date: Optional[datetime] = None
    ):
        self.findings = findings
        self.organization = organization
        self.system_name = system_name
        self.start_date = start_date or datetime.utcnow()
        self.poam_items: List[POAMItem] = []
        self._generate_items()

    def _generate_items(self):
        """Generate POA&M items from findings."""
        # Only include non-compliant findings
        gaps = self.findings.filter_non_compliant()

        for i, finding in enumerate(gaps, 1):
            days = self.DEFAULT_TIMEFRAMES.get(finding.severity, 90)
            completion_date = self.start_date + timedelta(days=days)

            item = POAMItem(
                poam_id=f"POAM-{i:04d}",
                control_id=finding.control.id,
                weakness_description=finding.message,
                remediation_plan=finding.remediation,
                severity=finding.severity,
                status="Open",
                scheduled_completion=completion_date.strftime("%Y-%m-%d"),
                milestones=self._generate_milestones(finding, days),
                resource_required=self._estimate_resources(finding),
                comments=f"Resource: {finding.resource_type}.{finding.resource_name}"
            )
            self.poam_items.append(item)

    def _generate_milestones(self, finding: Finding, total_days: int) -> List[str]:
        """Generate milestones for a finding."""
        milestones = []

        if total_days >= 30:
            milestones.append("Week 1: Assess current configuration and document baseline")

        if total_days >= 60:
            milestones.append("Week 2-3: Develop remediation approach and test in non-production")

        if total_days >= 90:
            milestones.append("Week 4-6: Implement changes in production with rollback plan")
            milestones.append("Week 7-8: Validate remediation and update documentation")

        milestones.append("Final: Verify compliance and close POA&M item")

        return milestones

    def _estimate_resources(self, finding: Finding) -> str:
        """Estimate resources needed for remediation."""
        resource_map = {
            "critical": "Security Engineer (2-4 hours), Change Advisory Board review",
            "high": "Security Engineer (1-2 hours)",
            "medium": "System Administrator (1 hour)",
            "low": "System Administrator (30 minutes)",
            "info": "Documentation update only",
        }
        return resource_map.get(finding.severity, "TBD")

    def generate_csv(self, filepath: str) -> None:
        """Generate POA&M in CSV format."""
        headers = [
            "POA&M ID",
            "Control ID",
            "Weakness Description",
            "Remediation Plan",
            "Severity",
            "Status",
            "Scheduled Completion",
            "Milestones",
            "Resources Required",
            "Responsible Party",
            "Comments"
        ]

        with open(filepath, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)
            writer.writerow(headers)

            for item in self.poam_items:
                writer.writerow([
                    item.poam_id,
                    item.control_id,
                    item.weakness_description,
                    item.remediation_plan,
                    item.severity,
                    item.status,
                    item.scheduled_completion,
                    "; ".join(item.milestones),
                    item.resource_required,
                    item.responsible_party,
                    item.comments
                ])

    def generate_json(self, filepath: Optional[str] = None) -> str:
        """Generate POA&M in JSON format."""
        data = {
            "poam_info": {
                "organization": self.organization,
                "system_name": self.system_name,
                "generated_at": datetime.utcnow().isoformat(),
                "total_items": len(self.poam_items),
            },
            "summary": {
                "by_severity": self._count_by_severity(),
                "by_status": self._count_by_status(),
            },
            "items": [
                {
                    "poam_id": item.poam_id,
                    "control_id": item.control_id,
                    "weakness_description": item.weakness_description,
                    "remediation_plan": item.remediation_plan,
                    "severity": item.severity,
                    "status": item.status,
                    "scheduled_completion": item.scheduled_completion,
                    "milestones": item.milestones,
                    "resources_required": item.resource_required,
                    "responsible_party": item.responsible_party,
                    "comments": item.comments,
                }
                for item in self.poam_items
            ]
        }

        json_str = json.dumps(data, indent=2)

        if filepath:
            Path(filepath).write_text(json_str)

        return json_str

    def generate_html(self, filepath: Optional[str] = None) -> str:
        """Generate POA&M in HTML format."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Plan of Action and Milestones (POA&M)</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 2rem; }}
        h1 {{ color: #1e3a5f; }}
        .meta {{ color: #666; margin-bottom: 2rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; vertical-align: top; }}
        th {{ background: #1e3a5f; color: white; }}
        tr:nth-child(even) {{ background: #f9f9f9; }}
        .severity-critical {{ background: #e74c3c; color: white; padding: 2px 8px; border-radius: 4px; }}
        .severity-high {{ background: #e67e22; color: white; padding: 2px 8px; border-radius: 4px; }}
        .severity-medium {{ background: #f1c40f; padding: 2px 8px; border-radius: 4px; }}
        .severity-low {{ background: #3498db; color: white; padding: 2px 8px; border-radius: 4px; }}
        .milestones {{ font-size: 0.9em; }}
        .milestones li {{ margin: 4px 0; }}
    </style>
</head>
<body>
    <h1>Plan of Action and Milestones (POA&M)</h1>
    <div class="meta">
        <p><strong>Organization:</strong> {self.organization or 'Not specified'}</p>
        <p><strong>System:</strong> {self.system_name or 'Not specified'}</p>
        <p><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d')}</p>
        <p><strong>Total Items:</strong> {len(self.poam_items)}</p>
    </div>

    <table>
        <thead>
            <tr>
                <th>POA&M ID</th>
                <th>Control</th>
                <th>Weakness</th>
                <th>Remediation</th>
                <th>Severity</th>
                <th>Due Date</th>
                <th>Milestones</th>
            </tr>
        </thead>
        <tbody>
"""

        for item in self.poam_items:
            milestones_html = "<ul class='milestones'>" + \
                "".join(f"<li>{m}</li>" for m in item.milestones) + "</ul>"

            html += f"""            <tr>
                <td>{item.poam_id}</td>
                <td>{item.control_id}</td>
                <td>{item.weakness_description[:100]}...</td>
                <td>{item.remediation_plan}</td>
                <td><span class="severity-{item.severity}">{item.severity.upper()}</span></td>
                <td>{item.scheduled_completion}</td>
                <td>{milestones_html}</td>
            </tr>
"""

        html += """        </tbody>
    </table>

    <footer style="margin-top: 2rem; color: #666; font-size: 0.9em;">
        <p>Generated by CMMC Control Validator</p>
    </footer>
</body>
</html>"""

        if filepath:
            Path(filepath).write_text(html)

        return html

    def _count_by_severity(self) -> Dict[str, int]:
        """Count POA&M items by severity."""
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for item in self.poam_items:
            if item.severity in counts:
                counts[item.severity] += 1
        return counts

    def _count_by_status(self) -> Dict[str, int]:
        """Count POA&M items by status."""
        counts: Dict[str, int] = {}
        for item in self.poam_items:
            counts[item.status] = counts.get(item.status, 0) + 1
        return counts

    def get_summary(self) -> Dict:
        """Get POA&M summary statistics."""
        return {
            "total_items": len(self.poam_items),
            "by_severity": self._count_by_severity(),
            "by_status": self._count_by_status(),
            "earliest_due": min(
                (item.scheduled_completion for item in self.poam_items),
                default=""
            ),
            "latest_due": max(
                (item.scheduled_completion for item in self.poam_items),
                default=""
            ),
        }

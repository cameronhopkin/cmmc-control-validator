#!/usr/bin/env python3
"""
CMMC Control Validator - Gap Report Generator
Generate compliance gap analysis reports.

Author: Cameron Hopkin
License: MIT
"""
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from ..core.findings import FindingCollection
from ..core.control_mapper import ComplianceStatus, ControlFamily


class GapReportGenerator:
    """
    Generate gap analysis reports from validation findings.

    Produces reports in JSON, HTML, and Markdown formats.
    """

    def __init__(
        self,
        findings: FindingCollection,
        organization: str = "",
        system_name: str = ""
    ):
        self.findings = findings
        self.organization = organization
        self.system_name = system_name
        self.generated_at = datetime.utcnow()

    def generate_json(self, filepath: Optional[str] = None) -> str:
        """Generate JSON gap report."""
        report = {
            "report_info": {
                "title": "CMMC Level 2 Gap Analysis Report",
                "organization": self.organization,
                "system_name": self.system_name,
                "generated_at": self.generated_at.isoformat(),
                "scan_target": self.findings.scan_target,
            },
            "executive_summary": self._generate_executive_summary(),
            "compliance_summary": {
                "by_status": self.findings.status_counts,
                "by_severity": self.findings.severity_counts,
                "by_family": self.findings.family_counts,
                "compliance_rate": round(self.findings.compliance_rate, 1),
            },
            "gaps_by_family": self._get_gaps_by_family(),
            "priority_remediation": [
                f.to_dict() for f in self.findings.get_priority_findings(10)
            ],
            "all_findings": [f.to_dict() for f in self.findings],
        }

        json_str = json.dumps(report, indent=2)

        if filepath:
            Path(filepath).write_text(json_str)

        return json_str

    def generate_html(self, filepath: Optional[str] = None) -> str:
        """Generate HTML gap report."""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CMMC Gap Analysis Report</title>
    <style>
        :root {{
            --primary: #1e3a5f;
            --secondary: #3498db;
            --success: #27ae60;
            --warning: #f39c12;
            --danger: #e74c3c;
            --light: #ecf0f1;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            line-height: 1.6;
            color: #333;
            background: var(--light);
        }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 2rem; }}
        header {{
            background: var(--primary);
            color: white;
            padding: 2rem;
            margin-bottom: 2rem;
        }}
        header h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
        .meta {{ opacity: 0.8; font-size: 0.9rem; }}
        .card {{
            background: white;
            border-radius: 8px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .card h2 {{ color: var(--primary); margin-bottom: 1rem; border-bottom: 2px solid var(--secondary); padding-bottom: 0.5rem; }}
        .stats {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 1rem;
            margin-bottom: 1rem;
        }}
        .stat {{
            text-align: center;
            padding: 1rem;
            background: var(--light);
            border-radius: 8px;
        }}
        .stat .value {{ font-size: 2rem; font-weight: bold; }}
        .stat.compliant .value {{ color: var(--success); }}
        .stat.non-compliant .value {{ color: var(--danger); }}
        .stat.partial .value {{ color: var(--warning); }}
        table {{ width: 100%; border-collapse: collapse; }}
        th, td {{ padding: 0.75rem; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background: var(--primary); color: white; }}
        tr:hover {{ background: #f5f5f5; }}
        .badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: bold;
        }}
        .badge-high {{ background: var(--danger); color: white; }}
        .badge-medium {{ background: var(--warning); color: white; }}
        .badge-low {{ background: var(--secondary); color: white; }}
        .badge-compliant {{ background: var(--success); color: white; }}
        .badge-non-compliant {{ background: var(--danger); color: white; }}
        .badge-partial {{ background: var(--warning); color: white; }}
        .progress-bar {{
            height: 20px;
            background: #ddd;
            border-radius: 10px;
            overflow: hidden;
        }}
        .progress-bar .fill {{
            height: 100%;
            background: var(--success);
            transition: width 0.3s;
        }}
    </style>
</head>
<body>
    <header>
        <div class="container">
            <h1>CMMC Level 2 Gap Analysis Report</h1>
            <div class="meta">
                <p>Organization: {self.organization or 'Not specified'}</p>
                <p>System: {self.system_name or 'Not specified'}</p>
                <p>Generated: {self.generated_at.strftime('%Y-%m-%d %H:%M UTC')}</p>
            </div>
        </div>
    </header>

    <div class="container">
        <div class="card">
            <h2>Executive Summary</h2>
            <p>{self._generate_executive_summary()}</p>
            <div style="margin-top: 1rem;">
                <strong>Compliance Score: {self.findings.compliance_rate:.1f}%</strong>
                <div class="progress-bar">
                    <div class="fill" style="width: {self.findings.compliance_rate}%"></div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Compliance Summary</h2>
            <div class="stats">
                <div class="stat compliant">
                    <div class="value">{self.findings.status_counts.get('compliant', 0)}</div>
                    <div>Compliant</div>
                </div>
                <div class="stat partial">
                    <div class="value">{self.findings.status_counts.get('partial', 0)}</div>
                    <div>Partial</div>
                </div>
                <div class="stat non-compliant">
                    <div class="value">{self.findings.status_counts.get('non_compliant', 0)}</div>
                    <div>Non-Compliant</div>
                </div>
                <div class="stat">
                    <div class="value">{self.findings.status_counts.get('unknown', 0)}</div>
                    <div>Unknown</div>
                </div>
            </div>
        </div>

        <div class="card">
            <h2>Priority Remediation Items</h2>
            <table>
                <thead>
                    <tr>
                        <th>Control</th>
                        <th>Resource</th>
                        <th>Status</th>
                        <th>Severity</th>
                        <th>Issue</th>
                    </tr>
                </thead>
                <tbody>
{self._generate_priority_table_rows()}
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Findings by Control Family</h2>
{self._generate_family_sections()}
        </div>
    </div>

    <footer style="text-align: center; padding: 2rem; color: #666;">
        <p>Generated by CMMC Control Validator v1.0.0</p>
    </footer>
</body>
</html>"""

        if filepath:
            Path(filepath).write_text(html)

        return html

    def generate_markdown(self, filepath: Optional[str] = None) -> str:
        """Generate Markdown gap report."""
        md = f"""# CMMC Level 2 Gap Analysis Report

**Organization:** {self.organization or 'Not specified'}
**System:** {self.system_name or 'Not specified'}
**Generated:** {self.generated_at.strftime('%Y-%m-%d %H:%M UTC')}

## Executive Summary

{self._generate_executive_summary()}

**Compliance Score:** {self.findings.compliance_rate:.1f}%

## Compliance Summary

| Status | Count |
|--------|-------|
| Compliant | {self.findings.status_counts.get('compliant', 0)} |
| Partial | {self.findings.status_counts.get('partial', 0)} |
| Non-Compliant | {self.findings.status_counts.get('non_compliant', 0)} |
| Unknown | {self.findings.status_counts.get('unknown', 0)} |
| Not Applicable | {self.findings.status_counts.get('not_applicable', 0)} |

## Priority Remediation Items

| Control | Resource | Severity | Issue |
|---------|----------|----------|-------|
{self._generate_priority_markdown_rows()}

## Findings by Control Family

{self._generate_family_markdown()}

---
*Generated by CMMC Control Validator v1.0.0*
"""

        if filepath:
            Path(filepath).write_text(md)

        return md

    def _generate_executive_summary(self) -> str:
        """Generate executive summary text."""
        total = len(self.findings)
        compliant = self.findings.status_counts.get('compliant', 0)
        non_compliant = self.findings.status_counts.get('non_compliant', 0)
        partial = self.findings.status_counts.get('partial', 0)

        high_severity = self.findings.severity_counts.get('high', 0)
        critical_severity = self.findings.severity_counts.get('critical', 0)

        summary = f"This assessment evaluated {total} control checks against CMMC Level 2 requirements. "

        if non_compliant + critical_severity + high_severity > 0:
            summary += f"The analysis identified {non_compliant} non-compliant and {partial} partially compliant findings. "
            summary += f"Of these, {critical_severity + high_severity} are high or critical severity requiring immediate attention. "
        else:
            summary += f"No high-severity gaps were identified. {partial} items require attention for full compliance. "

        summary += f"Overall compliance rate is {self.findings.compliance_rate:.1f}%."

        return summary

    def _get_gaps_by_family(self) -> Dict:
        """Get non-compliant findings grouped by family."""
        gaps = {}
        for family, findings in self.findings.group_by_family().items():
            non_compliant = [
                f.to_dict() for f in findings
                if f.status in (ComplianceStatus.NON_COMPLIANT, ComplianceStatus.PARTIAL)
            ]
            if non_compliant:
                gaps[family.name] = non_compliant
        return gaps

    def _generate_priority_table_rows(self) -> str:
        """Generate HTML table rows for priority findings."""
        rows = []
        for finding in self.findings.get_priority_findings(10):
            status_class = finding.status.value.replace('_', '-')
            rows.append(f"""                    <tr>
                        <td>{finding.control.id}</td>
                        <td>{finding.resource_type}.{finding.resource_name}</td>
                        <td><span class="badge badge-{status_class}">{finding.status.value}</span></td>
                        <td><span class="badge badge-{finding.severity}">{finding.severity}</span></td>
                        <td>{finding.message[:100]}...</td>
                    </tr>""")
        return "\n".join(rows)

    def _generate_priority_markdown_rows(self) -> str:
        """Generate Markdown table rows for priority findings."""
        rows = []
        for finding in self.findings.get_priority_findings(10):
            rows.append(
                f"| {finding.control.id} | {finding.resource_name} | "
                f"{finding.severity} | {finding.message[:50]}... |"
            )
        return "\n".join(rows)

    def _generate_family_sections(self) -> str:
        """Generate HTML sections for each control family."""
        sections = []
        for family, findings in self.findings.group_by_family().items():
            gaps = [f for f in findings if f.status != ComplianceStatus.COMPLIANT]
            if gaps:
                section = f"""            <h3>{family.value} ({family.name})</h3>
            <ul>"""
                for f in gaps[:5]:
                    section += f"\n                <li><strong>{f.control.id}</strong>: {f.message}</li>"
                if len(gaps) > 5:
                    section += f"\n                <li><em>... and {len(gaps) - 5} more</em></li>"
                section += "\n            </ul>"
                sections.append(section)
        return "\n".join(sections)

    def _generate_family_markdown(self) -> str:
        """Generate Markdown sections for each control family."""
        sections = []
        for family, findings in self.findings.group_by_family().items():
            gaps = [f for f in findings if f.status != ComplianceStatus.COMPLIANT]
            if gaps:
                section = f"### {family.value} ({family.name})\n\n"
                for f in gaps[:5]:
                    section += f"- **{f.control.id}**: {f.message}\n"
                if len(gaps) > 5:
                    section += f"- *... and {len(gaps) - 5} more*\n"
                sections.append(section)
        return "\n".join(sections)

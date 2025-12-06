#!/usr/bin/env python3
"""
CMMC Control Validator - Command Line Interface

Author: Cameron Hopkin
License: MIT
"""
import json
import sys
from pathlib import Path

import click

from .core.terraform_parser import TerraformParser
from .core.control_mapper import ControlMapper, ValidationResult, ComplianceStatus
from .core.findings import FindingCollection
from .reporters.gap_report import GapReportGenerator
from .reporters.poam_generator import POAMGenerator


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """CMMC Control Validator - Validate IaC against CMMC Level 2 controls."""
    pass


@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--output', '-o', help='Output file path')
@click.option('--format', '-f', type=click.Choice(['json', 'html', 'text']), default='text')
@click.option('--org', help='Organization name for report')
@click.option('--system', help='System name for report')
def validate(path: str, output: str, format: str, org: str, system: str):
    """Validate Terraform configuration against CMMC controls."""
    click.echo(f"Validating {path}...")

    # Parse Terraform
    parser = TerraformParser()
    parse_result = parser.parse_directory(path)

    if parse_result.errors:
        for error in parse_result.errors:
            click.secho(f"Warning: {error}", fg='yellow')

    click.echo(f"Found {parse_result.resource_count} resources")

    # Validate against controls
    mapper = ControlMapper()
    findings = FindingCollection(scan_target=path)

    for resource in parse_result.get_aws_resources():
        resource_findings = mapper.validate_terraform_resource(
            resource.resource_type,
            resource.config
        )
        findings.add_all(resource_findings)

    # Generate output
    if format == 'json':
        result = findings.to_json()
        if output:
            Path(output).write_text(result)
            click.echo(f"Results saved to {output}")
        else:
            click.echo(result)

    elif format == 'html':
        generator = GapReportGenerator(findings, organization=org, system_name=system)
        html = generator.generate_html(output)
        if output:
            click.echo(f"Report saved to {output}")
        else:
            click.echo(html)

    else:  # text
        _print_text_summary(findings)

    # Return exit code based on findings
    if findings.filter_by_status(ComplianceStatus.NON_COMPLIANT):
        sys.exit(1)


@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--output', '-o', required=True, help='Output file path')
@click.option('--format', '-f', type=click.Choice(['json', 'html', 'markdown']), default='html')
@click.option('--org', help='Organization name')
@click.option('--system', help='System name')
def gap_report(path: str, output: str, format: str, org: str, system: str):
    """Generate compliance gap analysis report."""
    click.echo(f"Generating gap report for {path}...")

    # Parse and validate
    parser = TerraformParser()
    parse_result = parser.parse_directory(path)
    mapper = ControlMapper()
    findings = FindingCollection(scan_target=path)

    for resource in parse_result.get_aws_resources():
        resource_findings = mapper.validate_terraform_resource(
            resource.resource_type,
            resource.config
        )
        findings.add_all(resource_findings)

    # Generate report
    generator = GapReportGenerator(findings, organization=org, system_name=system)

    if format == 'json':
        generator.generate_json(output)
    elif format == 'html':
        generator.generate_html(output)
    elif format == 'markdown':
        generator.generate_markdown(output)

    click.secho(f"Gap report saved to {output}", fg='green')


@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--output', '-o', required=True, help='Output file path')
@click.option('--format', '-f', type=click.Choice(['csv', 'json', 'html']), default='csv')
@click.option('--org', help='Organization name')
@click.option('--system', help='System name')
def poam(path: str, output: str, format: str, org: str, system: str):
    """Generate Plan of Action and Milestones (POA&M)."""
    click.echo(f"Generating POA&M for {path}...")

    # Parse and validate
    parser = TerraformParser()
    parse_result = parser.parse_directory(path)
    mapper = ControlMapper()
    findings = FindingCollection(scan_target=path)

    for resource in parse_result.get_aws_resources():
        resource_findings = mapper.validate_terraform_resource(
            resource.resource_type,
            resource.config
        )
        findings.add_all(resource_findings)

    # Generate POA&M
    generator = POAMGenerator(findings, organization=org, system_name=system)

    if format == 'csv':
        generator.generate_csv(output)
    elif format == 'json':
        generator.generate_json(output)
    elif format == 'html':
        generator.generate_html(output)

    summary = generator.get_summary()
    click.secho(f"POA&M saved to {output}", fg='green')
    click.echo(f"Total items: {summary['total_items']}")


@cli.command()
def list_controls():
    """List all CMMC Level 2 controls."""
    mapper = ControlMapper()
    controls = mapper.get_all_controls()

    if not controls:
        click.echo("No controls loaded. Ensure data files are present.")
        return

    click.echo(f"\nCMMC Level 2 Controls ({len(controls)} total)\n")
    click.echo("-" * 60)

    current_family = None
    for control in sorted(controls, key=lambda c: c.id):
        if control.family != current_family:
            current_family = control.family
            click.secho(f"\n{control.family.value} ({control.family.name})", fg='blue', bold=True)

        click.echo(f"  {control.id}: {control.title}")


@cli.command()
@click.argument('path', type=click.Path(exists=True))
def parse(path: str):
    """Parse Terraform files and show resources."""
    parser = TerraformParser()
    result = parser.parse_directory(path)

    click.echo(f"\nParsed {path}")
    click.echo(f"Resources: {result.resource_count}")
    click.echo(f"Modules: {len(result.modules)}")

    if result.errors:
        click.secho("\nErrors:", fg='red')
        for error in result.errors:
            click.echo(f"  - {error}")

    if result.resources:
        click.echo("\nResources found:")
        for resource in result.resources[:20]:
            click.echo(f"  - {resource.full_address}")

        if len(result.resources) > 20:
            click.echo(f"  ... and {len(result.resources) - 20} more")


def _print_text_summary(findings: FindingCollection):
    """Print text summary of findings."""
    click.echo("\n" + "=" * 60)
    click.echo("CMMC Level 2 Validation Summary")
    click.echo("=" * 60)

    # Status counts
    click.echo("\nCompliance Status:")
    for status, count in findings.status_counts.items():
        color = 'green' if status == 'compliant' else 'red' if status == 'non_compliant' else 'yellow'
        click.secho(f"  {status}: {count}", fg=color)

    click.echo(f"\nCompliance Rate: {findings.compliance_rate:.1f}%")

    # Priority findings
    priority = findings.get_priority_findings(5)
    if priority:
        click.echo("\nPriority Remediation Items:")
        for f in priority:
            if f.status != ComplianceStatus.COMPLIANT:
                click.secho(f"  [{f.severity.upper()}] {f.control.id}: {f.message[:60]}...", fg='red')

    # Family breakdown
    click.echo("\nFindings by Family:")
    for family, count in findings.family_counts.items():
        if count > 0:
            click.echo(f"  {family}: {count}")


if __name__ == "__main__":
    cli()

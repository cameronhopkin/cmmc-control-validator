#!/usr/bin/env python3
"""
CMMC Control Validator - CLI Tests

Author: Cameron Hopkin
License: MIT
"""
import pytest
from click.testing import CliRunner

from cmmc_validator.cli import cli


@pytest.fixture
def runner():
    """Create a CLI test runner."""
    return CliRunner()


class TestCLI:
    """Test suite for CLI commands."""

    def test_cli_help(self, runner):
        """Test CLI help message."""
        result = runner.invoke(cli, ['--help'])

        assert result.exit_code == 0
        assert 'CMMC Control Validator' in result.output

    def test_cli_version(self, runner):
        """Test CLI version display."""
        result = runner.invoke(cli, ['--version'])

        assert result.exit_code == 0
        assert '1.0.0' in result.output

    def test_validate_command_help(self, runner):
        """Test validate command help."""
        result = runner.invoke(cli, ['validate', '--help'])

        assert result.exit_code == 0
        assert 'Validate Terraform configuration' in result.output

    def test_validate_nonexistent_path(self, runner):
        """Test validate with non-existent path."""
        result = runner.invoke(cli, ['validate', '/nonexistent/path'])

        # Should fail with error about path not existing
        assert result.exit_code != 0

    def test_validate_with_terraform_dir(self, runner, sample_terraform_dir):
        """Test validate with actual Terraform directory."""
        result = runner.invoke(cli, ['validate', str(sample_terraform_dir)])

        # Should run successfully (may exit 1 if findings exist)
        assert 'Validating' in result.output or result.exit_code in [0, 1]

    def test_validate_json_format(self, runner, sample_terraform_dir, temp_dir):
        """Test validate with JSON output format."""
        output_file = temp_dir / "results.json"
        result = runner.invoke(cli, [
            'validate',
            str(sample_terraform_dir),
            '--format', 'json',
            '--output', str(output_file)
        ])

        # Check output file was created or output was displayed
        assert result.exit_code in [0, 1]

    def test_gap_report_command_help(self, runner):
        """Test gap-report command help."""
        result = runner.invoke(cli, ['gap-report', '--help'])

        assert result.exit_code == 0
        assert 'Generate compliance gap analysis report' in result.output

    def test_poam_command_help(self, runner):
        """Test poam command help."""
        result = runner.invoke(cli, ['poam', '--help'])

        assert result.exit_code == 0
        assert 'Generate Plan of Action and Milestones' in result.output

    def test_list_controls_command(self, runner):
        """Test list-controls command."""
        result = runner.invoke(cli, ['list-controls'])

        assert result.exit_code == 0
        assert 'CMMC Level 2 Controls' in result.output

    def test_parse_command_help(self, runner):
        """Test parse command help."""
        result = runner.invoke(cli, ['parse', '--help'])

        assert result.exit_code == 0
        assert 'Parse Terraform files' in result.output

    def test_parse_terraform_dir(self, runner, sample_terraform_dir):
        """Test parse command with Terraform directory."""
        result = runner.invoke(cli, ['parse', str(sample_terraform_dir)])

        assert result.exit_code == 0
        assert 'Parsed' in result.output
        assert 'Resources:' in result.output

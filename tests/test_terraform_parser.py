#!/usr/bin/env python3
"""
CMMC Control Validator - Terraform Parser Tests

Author: Cameron Hopkin
License: MIT
"""
import pytest
from pathlib import Path

from cmmc_validator.core.terraform_parser import TerraformParser, ParseResult, TerraformResource


class TestTerraformParser:
    """Test suite for TerraformParser."""

    def test_parser_initialization(self):
        """Test parser can be initialized."""
        parser = TerraformParser()
        assert parser is not None

    def test_parse_empty_directory(self, temp_dir):
        """Test parsing empty directory."""
        parser = TerraformParser()
        result = parser.parse_directory(str(temp_dir))

        assert isinstance(result, ParseResult)
        assert result.resource_count == 0
        assert len(result.resources) == 0

    def test_parse_directory_with_terraform(self, sample_terraform_dir):
        """Test parsing directory with Terraform files."""
        parser = TerraformParser()
        result = parser.parse_directory(str(sample_terraform_dir))

        assert result.resource_count > 0
        assert len(result.resources) > 0

    def test_parse_finds_s3_buckets(self, sample_terraform_dir):
        """Test parser finds S3 bucket resources."""
        parser = TerraformParser()
        result = parser.parse_directory(str(sample_terraform_dir))

        aws_resources = result.get_aws_resources()
        s3_buckets = [r for r in aws_resources if r.resource_type == "aws_s3_bucket"]

        assert len(s3_buckets) >= 2  # compliant and non-compliant

    def test_parse_finds_security_groups(self, sample_terraform_dir):
        """Test parser finds security group resources."""
        parser = TerraformParser()
        result = parser.parse_directory(str(sample_terraform_dir))

        aws_resources = result.get_aws_resources()
        security_groups = [r for r in aws_resources if r.resource_type == "aws_security_group"]

        assert len(security_groups) >= 2

    def test_parse_finds_iam_policies(self, sample_terraform_dir):
        """Test parser finds IAM policy resources."""
        parser = TerraformParser()
        result = parser.parse_directory(str(sample_terraform_dir))

        aws_resources = result.get_aws_resources()
        iam_policies = [r for r in aws_resources if r.resource_type == "aws_iam_policy"]

        assert len(iam_policies) >= 2

    def test_parse_nonexistent_directory(self):
        """Test parsing non-existent directory."""
        parser = TerraformParser()
        result = parser.parse_directory("/nonexistent/path")

        assert len(result.errors) > 0

    def test_resource_full_address(self, sample_terraform_dir):
        """Test resource full address formatting."""
        parser = TerraformParser()
        result = parser.parse_directory(str(sample_terraform_dir))

        for resource in result.resources:
            assert resource.full_address is not None
            assert "." in resource.full_address

    def test_get_aws_resources_filters_correctly(self, sample_terraform_dir):
        """Test that get_aws_resources only returns AWS resources."""
        parser = TerraformParser()
        result = parser.parse_directory(str(sample_terraform_dir))

        aws_resources = result.get_aws_resources()

        for resource in aws_resources:
            assert resource.resource_type.startswith("aws_")


class TestTerraformResource:
    """Test suite for TerraformResource dataclass."""

    def test_resource_creation(self):
        """Test creating a TerraformResource."""
        resource = TerraformResource(
            resource_type="aws_s3_bucket",
            name="test_bucket",
            config={"bucket": "my-bucket"},
            source_file="main.tf"
        )

        assert resource.resource_type == "aws_s3_bucket"
        assert resource.name == "test_bucket"
        assert resource.config["bucket"] == "my-bucket"

    def test_resource_full_address(self):
        """Test full_address property."""
        resource = TerraformResource(
            resource_type="aws_s3_bucket",
            name="test_bucket",
            config={},
            source_file="main.tf"
        )

        assert resource.full_address == "aws_s3_bucket.test_bucket"

    def test_resource_with_module(self):
        """Test resource with module path."""
        resource = TerraformResource(
            resource_type="aws_s3_bucket",
            name="test_bucket",
            config={},
            source_file="main.tf",
            module_path="module.storage"
        )

        assert "module.storage" in resource.full_address


class TestParseResult:
    """Test suite for ParseResult dataclass."""

    def test_empty_parse_result(self):
        """Test empty ParseResult."""
        result = ParseResult(resources=[], modules={}, errors=[])

        assert result.resource_count == 0
        assert len(result.get_aws_resources()) == 0

    def test_parse_result_with_resources(self):
        """Test ParseResult with resources."""
        resources = [
            TerraformResource("aws_s3_bucket", "bucket1", {}, "main.tf"),
            TerraformResource("aws_security_group", "sg1", {}, "main.tf"),
            TerraformResource("google_compute_instance", "vm1", {}, "main.tf"),
        ]
        result = ParseResult(resources=resources, modules={}, errors=[])

        assert result.resource_count == 3
        assert len(result.get_aws_resources()) == 2

#!/usr/bin/env python3
"""
CMMC Control Validator - Test Fixtures

Author: Cameron Hopkin
License: MIT
"""
import pytest
import tempfile
import os
from pathlib import Path


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_terraform_dir(temp_dir):
    """Create a temporary directory with sample Terraform files."""
    # Create main.tf with sample resources
    main_tf = temp_dir / "main.tf"
    main_tf.write_text('''
terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

# S3 bucket with encryption
resource "aws_s3_bucket" "compliant_bucket" {
  bucket = "my-compliant-bucket"

  tags = {
    Environment = "production"
    CMMCScope   = "true"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "compliant_bucket" {
  bucket = aws_s3_bucket.compliant_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.bucket_key.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "compliant_bucket" {
  bucket = aws_s3_bucket.compliant_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 bucket without encryption (non-compliant)
resource "aws_s3_bucket" "non_compliant_bucket" {
  bucket = "my-non-compliant-bucket"
}

# KMS key
resource "aws_kms_key" "bucket_key" {
  description             = "KMS key for S3 bucket encryption"
  deletion_window_in_days = 10
  enable_key_rotation     = true
}

# Security group with unrestricted SSH (non-compliant)
resource "aws_security_group" "non_compliant_sg" {
  name        = "non-compliant-sg"
  description = "Security group with open SSH"
  vpc_id      = "vpc-12345678"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Security group with restricted access (compliant)
resource "aws_security_group" "compliant_sg" {
  name        = "compliant-sg"
  description = "Properly restricted security group"
  vpc_id      = "vpc-12345678"

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }
}

# IAM policy with wildcards (non-compliant)
resource "aws_iam_policy" "overly_permissive" {
  name        = "overly-permissive-policy"
  description = "Policy with too many permissions"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"
        Resource = "*"
      }
    ]
  })
}

# IAM policy with least privilege (compliant)
resource "aws_iam_policy" "least_privilege" {
  name        = "least-privilege-policy"
  description = "Policy following least privilege"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["s3:GetObject", "s3:PutObject"]
        Resource = "arn:aws:s3:::my-bucket/*"
      }
    ]
  })
}

# CloudTrail (compliant)
resource "aws_cloudtrail" "main" {
  name                          = "main-trail"
  s3_bucket_name                = aws_s3_bucket.compliant_bucket.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.bucket_key.arn
}
''')

    return temp_dir


@pytest.fixture
def sample_s3_config():
    """Sample S3 bucket configuration."""
    return {
        "bucket": "test-bucket",
        "tags": {
            "Environment": "test"
        }
    }


@pytest.fixture
def sample_security_group_config():
    """Sample security group configuration."""
    return {
        "name": "test-sg",
        "vpc_id": "vpc-12345678",
        "ingress": [
            {
                "from_port": 22,
                "to_port": 22,
                "protocol": "tcp",
                "cidr_blocks": ["0.0.0.0/0"]
            }
        ]
    }


@pytest.fixture
def sample_iam_policy_config():
    """Sample IAM policy configuration."""
    return {
        "name": "test-policy",
        "policy": '''{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "*",
                    "Resource": "*"
                }
            ]
        }'''
    }

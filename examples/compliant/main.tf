# Example: CMMC-Compliant AWS Infrastructure
# This Terraform configuration demonstrates compliant patterns

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

# ============================================================
# KMS Key for Encryption (SC.L2-3.13.11, SC.L2-3.13.16)
# ============================================================
resource "aws_kms_key" "main" {
  description             = "KMS key for encrypting sensitive data"
  deletion_window_in_days = 10
  enable_key_rotation     = true  # Required for compliance

  tags = {
    Environment = "production"
    CMMCScope   = "true"
    Owner       = "security-team"
  }
}

resource "aws_kms_alias" "main" {
  name          = "alias/cmmc-main-key"
  target_key_id = aws_kms_key.main.key_id
}

# ============================================================
# S3 Bucket with Encryption (SC.L2-3.13.16, AU.L2-3.3.1)
# ============================================================
resource "aws_s3_bucket" "data" {
  bucket = "cmmc-compliant-data-bucket"

  tags = {
    Environment = "production"
    CMMCScope   = "true"
    DataClass   = "CUI"
  }
}

# Server-side encryption with KMS
resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
    bucket_key_enabled = true
  }
}

# Block all public access (AC.L2-3.1.1, AC.L2-3.1.3)
resource "aws_s3_bucket_public_access_block" "data" {
  bucket = aws_s3_bucket.data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Enable versioning for data protection
resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id

  versioning_configuration {
    status = "Enabled"
  }
}

# Enable access logging (AU.L2-3.3.1)
resource "aws_s3_bucket_logging" "data" {
  bucket = aws_s3_bucket.data.id

  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access-logs/"
}

# Logging bucket
resource "aws_s3_bucket" "logs" {
  bucket = "cmmc-compliant-logs-bucket"

  tags = {
    Environment = "production"
    Purpose     = "audit-logs"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.main.arn
    }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ============================================================
# VPC with Flow Logs (SC.L2-3.13.1, AU.L2-3.3.1, SI.L2-3.14.6)
# ============================================================
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "cmmc-compliant-vpc"
    Environment = "production"
    CMMCScope   = "true"
  }
}

# VPC Flow Logs for traffic monitoring
resource "aws_flow_log" "main" {
  vpc_id                   = aws_vpc.main.id
  traffic_type             = "ALL"
  log_destination_type     = "cloud-watch-logs"
  log_destination          = aws_cloudwatch_log_group.flow_logs.arn
  iam_role_arn             = aws_iam_role.flow_logs.arn
  max_aggregation_interval = 60

  tags = {
    Name = "vpc-flow-logs"
  }
}

resource "aws_cloudwatch_log_group" "flow_logs" {
  name              = "/aws/vpc/flow-logs"
  retention_in_days = 365  # Retain for compliance
  kms_key_id        = aws_kms_key.main.arn

  tags = {
    Purpose = "vpc-flow-logs"
  }
}

resource "aws_iam_role" "flow_logs" {
  name = "vpc-flow-logs-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "vpc-flow-logs.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "flow_logs" {
  name = "vpc-flow-logs-policy"
  role = aws_iam_role.flow_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "*"
      }
    ]
  })
}

# ============================================================
# Security Groups (AC.L2-3.1.1, SC.L2-3.13.1)
# ============================================================
resource "aws_security_group" "web" {
  name        = "web-tier-sg"
  description = "Security group for web tier - HTTPS only"
  vpc_id      = aws_vpc.main.id

  # Only allow HTTPS from specific CIDR
  ingress {
    description = "HTTPS from corporate network"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Internal network only
  }

  # Restricted egress
  egress {
    description = "HTTPS to internal services"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags = {
    Name        = "web-tier-sg"
    Environment = "production"
  }
}

resource "aws_security_group" "database" {
  name        = "database-tier-sg"
  description = "Security group for database tier"
  vpc_id      = aws_vpc.main.id

  # Only allow access from web tier
  ingress {
    description     = "PostgreSQL from web tier"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.web.id]
  }

  tags = {
    Name        = "database-tier-sg"
    Environment = "production"
  }
}

# ============================================================
# CloudTrail (AU.L2-3.3.1, AU.L2-3.3.2)
# ============================================================
resource "aws_cloudtrail" "main" {
  name                          = "cmmc-audit-trail"
  s3_bucket_name                = aws_s3_bucket.logs.id
  s3_key_prefix                 = "cloudtrail/"
  include_global_service_events = true
  is_multi_region_trail         = true  # Required for full coverage
  enable_log_file_validation    = true  # Required for integrity
  kms_key_id                    = aws_kms_key.main.arn

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.cloudtrail.arn

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = ["arn:aws:s3"]
    }
  }

  tags = {
    Environment = "production"
    Purpose     = "audit-compliance"
  }
}

resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "/aws/cloudtrail/cmmc-audit"
  retention_in_days = 365
  kms_key_id        = aws_kms_key.main.arn
}

resource "aws_iam_role" "cloudtrail" {
  name = "cloudtrail-cloudwatch-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy" "cloudtrail" {
  name = "cloudtrail-cloudwatch-policy"
  role = aws_iam_role.cloudtrail.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "logs:CreateLogStream",
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.cloudtrail.arn}:*"
      }
    ]
  })
}

# ============================================================
# GuardDuty (SI.L2-3.14.2, SI.L2-3.14.6)
# ============================================================
resource "aws_guardduty_detector" "main" {
  enable = true

  datasources {
    s3_logs {
      enable = true
    }
    kubernetes {
      audit_logs {
        enable = true
      }
    }
    malware_protection {
      scan_ec2_instance_with_findings {
        ebs_volumes {
          enable = true
        }
      }
    }
  }

  tags = {
    Environment = "production"
    Purpose     = "threat-detection"
  }
}

# ============================================================
# AWS Config (CM.L2-3.4.1, CM.L2-3.4.2)
# ============================================================
resource "aws_config_configuration_recorder" "main" {
  name     = "cmmc-config-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported = true
    include_global_resource_types = true
  }
}

resource "aws_iam_role" "config" {
  name = "aws-config-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "config" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# ============================================================
# IAM Policy with Least Privilege (AC.L2-3.1.5)
# ============================================================
resource "aws_iam_policy" "data_reader" {
  name        = "cmmc-data-reader"
  description = "Read-only access to specific S3 bucket"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.data.arn,
          "${aws_s3_bucket.data.arn}/*"
        ]
      }
    ]
  })
}

# ============================================================
# Outputs
# ============================================================
output "vpc_id" {
  description = "VPC ID"
  value       = aws_vpc.main.id
}

output "data_bucket_arn" {
  description = "Data bucket ARN"
  value       = aws_s3_bucket.data.arn
}

output "kms_key_arn" {
  description = "KMS key ARN"
  value       = aws_kms_key.main.arn
}

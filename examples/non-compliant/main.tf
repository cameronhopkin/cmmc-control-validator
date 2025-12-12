# Example: Non-Compliant AWS Infrastructure
# This Terraform configuration demonstrates common compliance violations
# Use cmmc-validator to identify these issues

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
# VIOLATION: S3 Bucket without Encryption (SC.L2-3.13.16)
# ============================================================
resource "aws_s3_bucket" "unencrypted" {
  bucket = "my-unencrypted-bucket"

  # Missing: server_side_encryption_configuration
  # Missing: public_access_block
  # Missing: versioning

  tags = {
    Environment = "development"
  }
}

# ============================================================
# VIOLATION: S3 Bucket with Public Access (AC.L2-3.1.1)
# ============================================================
resource "aws_s3_bucket" "public" {
  bucket = "my-public-bucket"
}

resource "aws_s3_bucket_public_access_block" "public" {
  bucket = aws_s3_bucket.public.id

  # VIOLATION: All should be true
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# ============================================================
# VIOLATION: KMS Key without Rotation (SC.L2-3.13.11)
# ============================================================
resource "aws_kms_key" "no_rotation" {
  description = "KMS key without rotation"

  # VIOLATION: enable_key_rotation should be true
  enable_key_rotation = false
}

# ============================================================
# VIOLATION: Security Group with Unrestricted SSH (AC.L2-3.1.1, SC.L2-3.13.1)
# ============================================================
resource "aws_security_group" "open_ssh" {
  name        = "open-ssh-sg"
  description = "Security group with unrestricted SSH"
  vpc_id      = "vpc-12345678"

  # VIOLATION: SSH open to the world
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Should be restricted
  }

  # VIOLATION: All traffic open to world
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ============================================================
# VIOLATION: Security Group with Unrestricted RDP (AC.L2-3.1.1)
# ============================================================
resource "aws_security_group" "open_rdp" {
  name        = "open-rdp-sg"
  description = "Security group with unrestricted RDP"
  vpc_id      = "vpc-12345678"

  # VIOLATION: RDP open to the world
  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ============================================================
# VIOLATION: IAM Policy with Wildcard Actions (AC.L2-3.1.5)
# ============================================================
resource "aws_iam_policy" "admin_access" {
  name        = "overly-permissive-policy"
  description = "Policy with excessive permissions"

  # VIOLATION: Wildcard actions and resources
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"        # Should be specific actions
        Resource = "*"        # Should be specific resources
      }
    ]
  })
}

# ============================================================
# VIOLATION: IAM Role with Public Trust (AC.L2-3.1.1)
# ============================================================
resource "aws_iam_role" "public_trust" {
  name = "publicly-assumable-role"

  # VIOLATION: Any AWS account can assume this role
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "*"  # Should be specific account/role
        }
      }
    ]
  })
}

# ============================================================
# VIOLATION: CloudTrail without Encryption (AU.L2-3.3.1)
# ============================================================
resource "aws_cloudtrail" "unencrypted" {
  name           = "unencrypted-trail"
  s3_bucket_name = aws_s3_bucket.unencrypted.id

  # VIOLATION: Missing encryption
  # kms_key_id = ... (should be set)

  # VIOLATION: Single region only
  is_multi_region_trail = false

  # VIOLATION: No log file validation
  enable_log_file_validation = false
}

# ============================================================
# VIOLATION: RDS without Encryption (SC.L2-3.13.16)
# ============================================================
resource "aws_db_instance" "unencrypted" {
  identifier        = "unencrypted-db"
  engine            = "mysql"
  engine_version    = "8.0"
  instance_class    = "db.t3.micro"
  allocated_storage = 20

  username = "admin"
  password = "insecure-password"  # VIOLATION: Hardcoded password

  # VIOLATION: No encryption at rest
  storage_encrypted = false

  # VIOLATION: No Multi-AZ
  multi_az = false

  # VIOLATION: Short backup retention
  backup_retention_period = 1  # Should be >= 7 days

  skip_final_snapshot = true
}

# ============================================================
# VIOLATION: EBS Volume without Encryption (SC.L2-3.13.16)
# ============================================================
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "us-east-1a"
  size              = 100

  # VIOLATION: No encryption
  encrypted = false
}

# ============================================================
# VIOLATION: VPC without Flow Logs (AU.L2-3.3.1, SI.L2-3.14.6)
# ============================================================
resource "aws_vpc" "no_flow_logs" {
  cidr_block = "10.0.0.0/16"

  # VIOLATION: No associated aws_flow_log resource
  # VPC Flow Logs are required for traffic monitoring

  tags = {
    Name = "vpc-without-flow-logs"
  }
}

# ============================================================
# VIOLATION: CloudWatch Log Group without Encryption (SC.L2-3.13.16)
# ============================================================
resource "aws_cloudwatch_log_group" "unencrypted" {
  name = "/application/logs"

  # VIOLATION: No KMS encryption
  # kms_key_id = ... (should be set)

  # VIOLATION: Short retention
  retention_in_days = 7  # Should be >= 90 days for compliance
}

# ============================================================
# VIOLATION: Load Balancer with HTTP (SC.L2-3.13.8)
# ============================================================
resource "aws_lb" "no_logging" {
  name               = "insecure-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.open_ssh.id]
  subnets            = ["subnet-1", "subnet-2"]

  # VIOLATION: No access logging
  # access_logs { enabled = true ... }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.no_logging.arn
  port              = 80
  protocol          = "HTTP"  # VIOLATION: Should use HTTPS

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "OK"
      status_code  = "200"
    }
  }
}

# ============================================================
# VIOLATION: EC2 Instance without IMDSv2 (CM.L2-3.4.2)
# ============================================================
resource "aws_instance" "insecure" {
  ami           = "ami-12345678"
  instance_type = "t3.micro"

  # VIOLATION: IMDSv1 allowed (insecure)
  metadata_options {
    http_tokens = "optional"  # Should be "required"
  }

  # VIOLATION: No detailed monitoring
  monitoring = false
}

# ============================================================
# VIOLATION: GuardDuty Disabled (SI.L2-3.14.2, SI.L2-3.14.6)
# ============================================================
resource "aws_guardduty_detector" "disabled" {
  enable = false  # VIOLATION: Should be enabled

  # VIOLATION: No data sources enabled
}

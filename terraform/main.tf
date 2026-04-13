# ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
#
# VULNERABILITIES DEMONSTRATED IN THIS FILE:
# ─────────────────────────────────────────────────────────────────────────────
#  [SECR-1]  Hardcoded AWS credentials in provider block
#  [STATE-1] Remote state stored without encryption
#  [STATE-2] State backend uses HTTP (not HTTPS)
#  [LOG-1]   CloudTrail disabled
#  [LOG-2]   VPC Flow Logs disabled
#  [NET-1]   Default VPC used (no custom network segmentation)
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.0.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # [STATE-1] VULNERABILITY: Remote state without encryption
  # [STATE-2] VULNERABILITY: HTTP backend (man-in-the-middle possible)
  backend "s3" {
    bucket  = "vulnerable-terraform-state"
    key     = "prod/terraform.tfstate"
    region  = "us-east-1"
    encrypt = false        # VULN: State file stored unencrypted (contains all secrets)
    # Missing: dynamodb_table for state locking
    # Missing: kms_key_id for encryption
  }
}

# [SECR-1] VULNERABILITY: Hardcoded AWS credentials in provider
# Credentials are committed to VCS and visible in terraform plan output
provider "aws" {
  region     = "us-east-1"
  access_key = "AKIAIOSFODNN7EXAMPLE"                        # Hardcoded AWS Access Key
  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # Hardcoded AWS Secret Key
  # Secure: use environment variables or IAM instance role — no keys in code
}

# [NET-1] VULNERABILITY: Using the default VPC
# Default VPC has permissive default security groups and no custom routing
data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

# [LOG-1] VULNERABILITY: CloudTrail disabled — no audit trail of API calls
# resource "aws_cloudtrail" "main" { ... }  ← intentionally absent

# [LOG-2] VULNERABILITY: VPC Flow Logs disabled — no network traffic visibility
# resource "aws_flow_log" "main" { ... }  ← intentionally absent

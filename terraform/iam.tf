# ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
#
# VULNERABILITIES DEMONSTRATED IN THIS FILE:
# ─────────────────────────────────────────────────────────────────────────────
#  [IAM-1]   Wildcard (*) Action in IAM policy — overly permissive
#  [IAM-2]   Wildcard (*) Resource in IAM policy — applies to all resources
#  [IAM-3]   IAM policy allows iam:PassRole to * — privilege escalation
#  [IAM-4]   IAM policy allows sts:AssumeRole from * — anyone can assume the role
#  [IAM-5]   No MFA condition on sensitive actions
#  [IAM-6]   No permission boundary on IAM role
#  [IAM-7]   Inline policy used instead of managed policy
#  [IAM-8]   Root account access keys (conceptual — shown in policy comment)
#  [IAM-9]   AdministratorAccess attached to application role (see ec2.tf)
#  [IAM-10]  No IAM password policy enforced
#
# Triggers: Checkov (CKV_AWS_1, CKV_AWS_2, CKV_AWS_40, CKV_AWS_107,
#           CKV_AWS_108, CKV_AWS_109, CKV_AWS_110, CKV_AWS_111)
# ─────────────────────────────────────────────────────────────────────────────

# [IAM-1][IAM-2] VULNERABILITY: Wildcard action + wildcard resource
# This policy grants full AWS account access — same as AdministratorAccess
resource "aws_iam_policy" "app_policy" {
  name        = "vulnerable-app-policy"
  description = "Overly permissive policy for vulnerable app"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "AllowEverything"
        Effect   = "Allow"
        Action   = "*"      # [IAM-1] VULN: All AWS actions permitted
        Resource = "*"      # [IAM-2] VULN: On all resources in the account
      },
      # [IAM-3] VULNERABILITY: PassRole to any role → privilege escalation
      # Attacker can pass an admin role to a service they control
      {
        Sid      = "AllowPassRole"
        Effect   = "Allow"
        Action   = ["iam:PassRole", "iam:CreateRole", "iam:AttachRolePolicy"]
        Resource = "*"
      }
    ]
  })
}

# [IAM-4] VULNERABILITY: Any AWS principal can assume this role
resource "aws_iam_role" "open_role" {
  name = "vulnerable-open-role"

  # Trust policy allows ANYONE to assume this role (no Principal restriction)
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { AWS = "*" }   # VULN: Any AWS account/user/role
      Action    = "sts:AssumeRole"
      # Missing Condition: { StringEquals: { "aws:MultiFactorAuthPresent": "true" } }
    }]
  })
}

# [IAM-7] VULNERABILITY: Inline policy (harder to audit, can't be reused or centrally managed)
resource "aws_iam_role_policy" "inline_admin" {
  name = "inline-admin-policy"
  role = aws_iam_role.open_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:*", "ec2:*", "rds:*", "iam:*", "lambda:*"]
      Resource = "*"
    }]
  })
}

# [IAM-10] VULNERABILITY: No account password policy
# Without this, IAM users can have weak/short passwords with no rotation
# resource "aws_iam_account_password_policy" "strict" { ... }
# ← intentionally absent

# ── CI/CD User ────────────────────────────────────────────────────────────────
# [IAM-1][IAM-2] VULNERABILITY: CI/CD user has wildcard access
resource "aws_iam_user" "cicd_user" {
  name = "vulnerable-cicd-user"
  path = "/"
  # [IAM-8] Note: Access keys for this user would be root-equivalent
}

resource "aws_iam_user_policy" "cicd_policy" {
  name = "cicd-admin-policy"
  user = aws_iam_user.cicd_user.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"    # [IAM-1] VULN: Full account access for CI/CD
      Resource = "*"    # [IAM-2]
    }]
  })
}

# [IAM-8] VULNERABILITY: Creating programmatic access keys for the user
# Access keys are long-lived credentials — no rotation, no MFA
resource "aws_iam_access_key" "cicd_key" {
  user = aws_iam_user.cicd_user.name
  # Secret stored in Terraform state (which is also unencrypted — see s3.tf)
}

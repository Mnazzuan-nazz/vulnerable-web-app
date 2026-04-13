# ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
#
# VULNERABILITIES DEMONSTRATED IN THIS FILE:
# ─────────────────────────────────────────────────────────────────────────────
#  [S3-1]   Bucket ACL set to public-read — any file uploaded is publicly readable
#  [S3-2]   Bucket ACL set to public-read-write on a second bucket — world writable
#  [S3-3]   Block public access settings all disabled
#  [S3-4]   No server-side encryption (SSE) enabled
#  [S3-5]   No versioning enabled — no recovery from accidental deletion
#  [S3-6]   No access logging on buckets
#  [S3-7]   Bucket policy allows s3:* from any principal ("*")
#  [S3-8]   No lifecycle rules — data accumulates indefinitely
#  [S3-9]   MFA delete not enabled
#
# Triggers: Checkov (CKV_AWS_18, CKV_AWS_19, CKV_AWS_20, CKV_AWS_21,
#           CKV_AWS_52, CKV_AWS_53, CKV_AWS_54, CKV_AWS_55, CKV_AWS_56)
# ─────────────────────────────────────────────────────────────────────────────

# ── Public Readable Bucket ────────────────────────────────────────────────────
resource "aws_s3_bucket" "app_assets" {
  bucket = "vulnerable-app-assets-${var.environment}"

  # [S3-8] VULNERABILITY: No lifecycle rules
  tags = {
    Name        = "vulnerable-app-assets"
    Environment = var.environment
  }
}

# [S3-1] VULNERABILITY: Public read ACL — any file is accessible to the internet
resource "aws_s3_bucket_acl" "app_assets_acl" {
  bucket = aws_s3_bucket.app_assets.id
  acl    = "public-read"   # Every object is readable by anyone
}

# [S3-3] VULNERABILITY: All public access blocks disabled
# These settings exist specifically to prevent accidental public exposure
resource "aws_s3_bucket_public_access_block" "app_assets" {
  bucket = aws_s3_bucket.app_assets.id

  block_public_acls       = false   # VULN: Public ACLs allowed
  block_public_policy     = false   # VULN: Public bucket policies allowed
  ignore_public_acls      = false   # VULN: Public ACLs not ignored
  restrict_public_buckets = false   # VULN: Public bucket access not restricted
}

# [S3-4] VULNERABILITY: No server-side encryption
# Sensitive data (uploads, DB backups) stored in plaintext on S3
# resource "aws_s3_bucket_server_side_encryption_configuration" "app_assets" { }
# ← intentionally absent

# [S3-5] VULNERABILITY: No versioning — overwrites and deletes are unrecoverable
# resource "aws_s3_bucket_versioning" "app_assets" { }
# ← intentionally absent

# [S3-6] VULNERABILITY: No access logging — no audit trail of who accessed what
# resource "aws_s3_bucket_logging" "app_assets" { }
# ← intentionally absent

# [S3-7] VULNERABILITY: Bucket policy grants s3:* to any principal
# Allows anonymous reads, writes, ACL changes, object deletions
resource "aws_s3_bucket_policy" "app_assets_policy" {
  bucket = aws_s3_bucket.app_assets.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadWriteAccess"
        Effect    = "Allow"
        Principal = "*"           # VULN: Any AWS account or anonymous user
        Action    = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject",      # VULN: Anyone can delete objects
          "s3:ListBucket",        # VULN: Anyone can list bucket contents
          "s3:GetBucketAcl",
          "s3:PutBucketAcl"       # VULN: Anyone can change the bucket ACL
        ]
        Resource  = [
          aws_s3_bucket.app_assets.arn,
          "${aws_s3_bucket.app_assets.arn}/*"
        ]
      }
    ]
  })
}

# ── World-Writable Backup Bucket ──────────────────────────────────────────────
resource "aws_s3_bucket" "backups" {
  bucket = "vulnerable-app-backups-${var.environment}"

  tags = {
    Name        = "vulnerable-app-backups"
    Environment = var.environment
  }
}

# [S3-2] VULNERABILITY: public-read-write — anyone can upload/overwrite backups
resource "aws_s3_bucket_acl" "backups_acl" {
  bucket = aws_s3_bucket.backups.id
  acl    = "public-read-write"   # World-writable bucket — attackers can plant files
}

resource "aws_s3_bucket_public_access_block" "backups" {
  bucket = aws_s3_bucket.backups.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# ── Terraform State Bucket ────────────────────────────────────────────────────
# [STATE-1] VULNERABILITY: State bucket has no encryption, versioning, or logging
# Terraform state contains all resource details including passwords and secrets
resource "aws_s3_bucket" "tf_state" {
  bucket = "vulnerable-terraform-state"

  tags = {
    Name = "terraform-state"
  }
}

resource "aws_s3_bucket_public_access_block" "tf_state" {
  bucket = aws_s3_bucket.tf_state.id

  # [S3-3] VULNERABILITY: State bucket also publicly accessible
  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

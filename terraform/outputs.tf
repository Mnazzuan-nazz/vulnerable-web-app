# ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
#
# VULNERABILITIES DEMONSTRATED IN THIS FILE:
# ─────────────────────────────────────────────────────────────────────────────
#  [SECR-1]  Sensitive values (DB password, access keys) output without sensitive=true
#  [SECR-2]  IAM access key secret output in plaintext — visible in terraform apply
#  [DISC-1]  Internal IP addresses, DB endpoints, private DNS exposed as outputs
# ─────────────────────────────────────────────────────────────────────────────

output "app_public_ip" {
  description = "Public IP of the application server"
  value       = aws_instance.app_server.public_ip
}

output "app_public_dns" {
  description = "Public DNS of the application server"
  value       = aws_instance.app_server.public_dns
}

# [DISC-1] VULNERABILITY: DB endpoint exposed (useful for attackers who read state/output)
output "rds_endpoint" {
  description = "RDS database endpoint"
  value       = aws_db_instance.app_db.endpoint
}

# [SECR-1] VULNERABILITY: DB password output without sensitive = true
# Will be printed to console during `terraform apply` and stored in state
output "db_password" {
  description = "RDS master password"
  value       = var.db_password
  sensitive   = false   # VULN: Should be sensitive = true
}

# [SECR-2] VULNERABILITY: IAM access key ID and secret output in plaintext
output "cicd_access_key_id" {
  description = "CI/CD IAM user access key ID"
  value       = aws_iam_access_key.cicd_key.id
  sensitive   = false   # VULN: Key ID visible in output and state
}

output "cicd_secret_access_key" {
  description = "CI/CD IAM user secret access key"
  value       = aws_iam_access_key.cicd_key.secret
  sensitive   = false   # VULN: Secret key printed to console in plaintext
}

output "s3_assets_bucket" {
  description = "S3 assets bucket name"
  value       = aws_s3_bucket.app_assets.bucket
}

output "s3_assets_bucket_arn" {
  description = "S3 assets bucket ARN"
  value       = aws_s3_bucket.app_assets.arn
}

# [SECR-1] VULNERABILITY: JWT secret output in plaintext
output "jwt_secret" {
  description = "JWT signing secret"
  value       = var.jwt_secret
  sensitive   = false   # VULN
}

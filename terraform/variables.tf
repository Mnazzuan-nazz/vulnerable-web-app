# ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
#
# VULNERABILITIES DEMONSTRATED IN THIS FILE:
# ─────────────────────────────────────────────────────────────────────────────
#  [SECR-1]  Hardcoded default values for secrets (db password, api keys)
#  [SECR-2]  Sensitive variables without sensitive = true flag
#  [SECR-3]  Secrets stored as plain strings, not using Secrets Manager refs
# ─────────────────────────────────────────────────────────────────────────────

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment"
  type        = string
  default     = "production"
}

# [SECR-1] VULNERABILITY: Hardcoded default password in variable definition
# [SECR-2] VULNERABILITY: sensitive = true is NOT set — value printed in plan output
variable "db_password" {
  description = "RDS master password"
  type        = string
  default     = "SuperSecretDBPassword123!"  # Hardcoded default — committed to VCS
  # sensitive = true  ← intentionally absent
}

variable "db_username" {
  description = "RDS master username"
  type        = string
  default     = "admin"
}

variable "db_name" {
  description = "RDS database name"
  type        = string
  default     = "vulnerable_app"
}

# [SECR-1] VULNERABILITY: JWT secret with hardcoded default
variable "jwt_secret" {
  description = "JWT signing secret"
  type        = string
  default     = "secret"   # Extremely weak, hardcoded
  # sensitive = true  ← intentionally absent
}

# [SECR-1] VULNERABILITY: Stripe secret key hardcoded as variable default
variable "stripe_secret_key" {
  description = "Stripe secret API key"
  type        = string
  default     = "sk_live_51H2QwertyuiopASDFGHJKLzxcvbnmQWERTYUIOP1234"
  # sensitive = true  ← intentionally absent
}

variable "ec2_instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "ec2_key_name" {
  description = "EC2 SSH key pair name"
  type        = string
  default     = "vulnerable-app-key"
}

# [SECR-3] VULNERABILITY: Hardcoded SSH public key (matching private key in secrets.js)
variable "ssh_public_key" {
  description = "SSH public key for EC2 access"
  type        = string
  default     = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDA2a2rwplBQLzHPZe5RJ vulnerable-demo-key"
}

variable "app_port" {
  description = "Application port"
  type        = number
  default     = 3000
}

variable "allowed_cidr_blocks" {
  description = "CIDR blocks allowed to access the application"
  type        = list(string)
  # [NET-1] VULNERABILITY: Default allows access from the entire internet
  default     = ["0.0.0.0/0"]
}

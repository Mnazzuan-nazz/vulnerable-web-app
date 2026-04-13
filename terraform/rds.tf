# ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
#
# VULNERABILITIES DEMONSTRATED IN THIS FILE:
# ─────────────────────────────────────────────────────────────────────────────
#  [RDS-1]   RDS instance publicly accessible (publicly_accessible = true)
#  [RDS-2]   Storage encryption disabled
#  [RDS-3]   Deletion protection disabled — DB can be deleted with one API call
#  [RDS-4]   Backup retention set to 0 — no automated backups
#  [RDS-5]   Multi-AZ disabled — single point of failure
#  [RDS-6]   Minor version auto-upgrade disabled
#  [RDS-7]   Enhanced monitoring disabled
#  [RDS-8]   Performance insights disabled
#  [RDS-9]   Hardcoded master password (from variable default)
#  [SG-5]    RDS security group allows 5432 from 0.0.0.0/0
#  [LOG-3]   RDS audit/error/slow query logs disabled
#
# Triggers: Checkov (CKV_AWS_16, CKV_AWS_17, CKV_AWS_118, CKV_AWS_129,
#           CKV_AWS_133, CKV_AWS_157, CKV_AWS_161, CKV_AWS_162)
# ─────────────────────────────────────────────────────────────────────────────

resource "aws_db_subnet_group" "app_db" {
  name       = "vulnerable-app-db-subnet"
  subnet_ids = data.aws_subnets.default.ids

  tags = {
    Name = "vulnerable-app-db-subnet"
  }
}

# [SG-5] VULNERABILITY: DB security group allows all internet traffic on port 5432
resource "aws_security_group" "rds_sg" {
  name        = "vulnerable-rds-sg"
  description = "RDS security group"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "PostgreSQL from anywhere"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # VULN: DB open to the entire internet
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "app_db" {
  identifier        = "vulnerable-app-db"
  engine            = "postgres"
  engine_version    = "14"
  instance_class    = "db.t3.micro"
  allocated_storage = 20
  storage_type      = "gp2"
  db_name           = var.db_name
  username          = var.db_username

  # [RDS-9] VULNERABILITY: Password from variable with hardcoded default
  password = var.db_password   # default = "SuperSecretDBPassword123!"

  db_subnet_group_name   = aws_db_subnet_group.app_db.name
  vpc_security_group_ids = [aws_security_group.rds_sg.id]

  # [RDS-1] VULNERABILITY: Database directly reachable from the internet
  publicly_accessible = true   # Should always be false

  # [RDS-2] VULNERABILITY: Data at rest not encrypted
  storage_encrypted = false    # Should be true, with a KMS key

  # [RDS-3] VULNERABILITY: Deletion protection off — accidental/malicious deletion possible
  deletion_protection = false  # Should be true in production

  # [RDS-4] VULNERABILITY: No automated backups
  # If the database is corrupted or deleted, there is no recovery point
  backup_retention_period = 0   # Should be >= 7 days

  # [RDS-5] VULNERABILITY: Single-AZ — one AZ failure takes down the DB
  multi_az = false

  # [RDS-6] VULNERABILITY: Auto minor version upgrades disabled
  # Known CVEs in older PostgreSQL minor versions won't be patched automatically
  auto_minor_version_upgrade = false

  # [RDS-7] VULNERABILITY: Enhanced monitoring disabled
  monitoring_interval = 0   # Should be 60 (seconds)

  # [RDS-8] VULNERABILITY: Performance Insights disabled
  performance_insights_enabled = false

  # [LOG-3] VULNERABILITY: No database logs exported to CloudWatch
  # Without logs, there is no visibility into slow queries, errors, or auth failures
  enabled_cloudwatch_logs_exports = []
  # Should include: ["postgresql", "upgrade"] for PostgreSQL

  skip_final_snapshot = true   # VULN: No final snapshot on destroy

  tags = {
    Name        = "vulnerable-app-db"
    Environment = var.environment
  }
}

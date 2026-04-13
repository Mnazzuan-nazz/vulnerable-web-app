# ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
#
# VULNERABILITIES DEMONSTRATED IN THIS FILE:
# ─────────────────────────────────────────────────────────────────────────────
#  [EC2-1]   IMDSv2 not enforced — metadata service v1 accessible without token
#  [EC2-2]   Associate public IP on launch (direct internet exposure)
#  [EC2-3]   No EBS encryption on root volume
#  [EC2-4]   Hardcoded secrets injected via user_data (visible in EC2 console)
#  [EC2-5]   Overly permissive IAM instance profile (AdministratorAccess)
#  [SG-1]    Security group allows SSH (22) from 0.0.0.0/0
#  [SG-2]    Security group allows all outbound traffic
#  [SG-3]    Security group allows Node debugger port (9229) from 0.0.0.0/0
#  [SG-4]    Security group uses 0.0.0.0/0 for all inbound rules
#  [KEY-1]   Hardcoded SSH key pair material
#
# Triggers: Checkov, tfsec, Terrascan, Snyk IaC
# ─────────────────────────────────────────────────────────────────────────────

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# [KEY-1] VULNERABILITY: SSH key pair created from hardcoded public key in variables
resource "aws_key_pair" "app_key" {
  key_name   = var.ec2_key_name
  public_key = var.ssh_public_key
}

# ── Security Group ────────────────────────────────────────────────────────────
resource "aws_security_group" "app_sg" {
  name        = "vulnerable-app-sg"
  description = "Security group for vulnerable web application"
  vpc_id      = data.aws_vpc.default.id

  # [SG-1] VULNERABILITY: SSH open to the entire internet
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # Should be restricted to specific IPs
    ipv6_cidr_blocks = ["::/0"]   # IPv6 also open
  }

  # [SG-3] VULNERABILITY: Node.js debugger port open to internet
  # Anyone reaching this port gets a full Node.js REPL (arbitrary code execution)
  ingress {
    description = "Node.js debugger"
    from_port   = 9229
    to_port     = 9229
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Application port
  ingress {
    description = "App HTTP"
    from_port   = var.app_port
    to_port     = var.app_port
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # [SG-4] VULNERABILITY: HTTP open to all — no WAF, no CDN
  ingress {
    description = "HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # [SG-2] VULNERABILITY: All outbound traffic allowed
  # No egress restrictions → easy data exfiltration / C2 beaconing
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "vulnerable-app-sg"
    Environment = var.environment
  }
}

# ── IAM Role ──────────────────────────────────────────────────────────────────
# [EC2-5] VULNERABILITY: EC2 instance gets AdministratorAccess
# If the instance is compromised, the attacker inherits full AWS account control
resource "aws_iam_role" "app_role" {
  name = "vulnerable-app-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
      Action    = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "admin_access" {
  role       = aws_iam_role.app_role.name
  # [EC2-5] VULNERABILITY: AdministratorAccess = full AWS account control
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  # Principle of least privilege requires a custom policy scoped to what the app needs
}

resource "aws_iam_instance_profile" "app_profile" {
  name = "vulnerable-app-profile"
  role = aws_iam_role.app_role.name
}

# ── EC2 Instance ──────────────────────────────────────────────────────────────
resource "aws_instance" "app_server" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.ec2_instance_type
  key_name               = aws_key_pair.app_key.key_name
  vpc_security_group_ids = [aws_security_group.app_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.app_profile.name

  # [EC2-2] VULNERABILITY: Public IP assigned — instance directly reachable from internet
  associate_public_ip_address = true

  # [EC2-1] VULNERABILITY: IMDSv2 not enforced
  # IMDSv1 allows: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name
  # An SSRF vulnerability in the app can steal the IAM role credentials via IMDSv1
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "optional"   # VULN: Should be "required" (IMDSv2)
    http_put_response_hop_limit = 2            # VULN: Should be 1 for containers
  }

  # [EC2-3] VULNERABILITY: Root EBS volume not encrypted
  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    encrypted             = false   # VULN: Data at rest unencrypted
    delete_on_termination = true
    # kms_key_id = ...  ← intentionally absent
  }

  # [EC2-4] VULNERABILITY: Secrets injected via user_data
  # user_data is visible in the AWS console and stored unencrypted in the EC2 metadata
  # Retrieve with: curl http://169.254.169.254/latest/user-data
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="${var.db_password}"
    export JWT_SECRET="${var.jwt_secret}"
    export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
    export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    export STRIPE_SECRET_KEY="${var.stripe_secret_key}"
    export GITHUB_TOKEN="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AB"

    # Install Node.js and start app
    curl -fsSL https://rpm.nodesource.com/setup_18.x | bash -
    yum install -y nodejs git
    git clone https://github.com/example/vulnerable-app /opt/app
    cd /opt/app && npm install
    node server.js &
  EOF

  tags = {
    Name        = "vulnerable-web-app"
    Environment = var.environment
  }
}

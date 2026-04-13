# ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
#
# VULNERABILITIES DEMONSTRATED IN THIS DOCKERFILE:
# ─────────────────────────────────────────────────────────────────────────────
#  [IMG-1]   Using latest tag — non-deterministic, no pinned digest
#  [IMG-2]   Running as root (no USER directive)
#  [IMG-3]   Base image: node:latest (bloated, includes unnecessary packages/attack surface)
#  [SECR-1]  Hardcoded secrets via ARG/ENV (visible in image layers & docker inspect)
#  [SECR-2]  AWS credentials baked into image
#  [SECR-3]  Database password in ENV
#  [SECR-4]  JWT secret in ENV
#  [PERM-1]  chmod 777 on application directory
#  [PERM-2]  sudo installed inside container
#  [PERM-3]  curl, wget, netcat installed (useful for attackers post-exploit)
#  [MISC-1]  SSH server running inside container
#  [MISC-2]  .env file copied into image
#  [MISC-3]  No HEALTHCHECK defined
#  [MISC-4]  No .dockerignore limiting what gets copied
#  [MISC-5]  ADD used instead of COPY (ADD can auto-extract and fetch URLs)
#  [MISC-6]  Multiple RUN layers not squashed — secrets in intermediate layers
#  [MISC-7]  npm install runs as root, no --ignore-scripts flag
#  [NET-1]   Exposes unnecessary ports (22/SSH, 9229/Node debugger)
#  [NET-2]   Node.js debugger port exposed (--inspect=0.0.0.0:9229)
#
# Triggers: Trivy, Hadolint, Checkov, Snyk Container, Docker Scout
# ─────────────────────────────────────────────────────────────────────────────

# [IMG-1] VULNERABILITY: Unpinned 'latest' tag — image content changes silently
# [IMG-3] VULNERABILITY: Full node image (~1GB), should use node:20-alpine
FROM node:latest

# [SECR-1] VULNERABILITY: Secrets passed as build ARGs are cached in image layer history
# docker history <image> reveals these in plaintext
ARG DB_PASSWORD=SuperSecretDBPassword123!
ARG JWT_SECRET=secret
ARG AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ARG AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ARG STRIPE_SECRET_KEY=sk_live_51H2QwertyuiopASDFGHJKLzxcvbnmQWERTYUIOP1234
ARG GITHUB_TOKEN=ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AB

# [SECR-2] VULNERABILITY: Promoting build ARGs to ENV bakes them permanently into
# the image filesystem. Visible via: docker inspect <container> or docker history
ENV NODE_ENV=production \
    PORT=3000 \
    DB_HOST=localhost \
    DB_PORT=5432 \
    DB_NAME=vulnerable_app \
    DB_USER=admin \
    DB_PASSWORD=${DB_PASSWORD} \
    JWT_SECRET=${JWT_SECRET} \
    AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID} \
    AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY} \
    AWS_REGION=us-east-1 \
    STRIPE_SECRET_KEY=${STRIPE_SECRET_KEY} \
    GITHUB_TOKEN=${GITHUB_TOKEN} \
    SENDGRID_API_KEY=SG.aBcDeFgHiJkLmNoPq.RsTuVwXyZ0123456789ABCDEFGHIJKLM \
    SLACK_BOT_TOKEN=xoxb-1234567890-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwXy \
    # [NET-2] VULNERABILITY: Node.js inspector bound to all interfaces
    NODE_OPTIONS=--inspect=0.0.0.0:9229

# [PERM-1] VULNERABILITY: World-writable app directory
RUN mkdir -p /app && chmod 777 /app

WORKDIR /app

# [PERM-2] VULNERABILITY: Installing sudo, ssh, netcat, curl, wget into the image
# These tools massively aid lateral movement after a container breakout
RUN apt-get update && apt-get install -y \
    sudo \
    openssh-server \
    netcat-openbsd \
    curl \
    wget \
    vim \
    net-tools \
    iputils-ping \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# [MISC-1] VULNERABILITY: SSH server configured and started in container
# Containers should be ephemeral — SSH is an antipattern and an attack surface
RUN mkdir /var/run/sshd \
    && echo 'root:toor' | chpasswd \
    && sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config

# [MISC-5] VULNERABILITY: ADD instead of COPY
# ADD can fetch from URLs and auto-extract archives — broader attack surface
ADD package*.json ./

# [MISC-7] VULNERABILITY: npm install as root with no --ignore-scripts
# postinstall scripts in malicious packages execute as root
RUN npm install --unsafe-perm

# [MISC-4] VULNERABILITY: Copies entire project including .env, config/secrets.js
# No .dockerignore restricts what lands in the image
COPY . .

# [MISC-2] VULNERABILITY: .env file (with all secrets) explicitly copied in
COPY .env .env

# [SECR-3] VULNERABILITY: Writing credentials to a file inside the image layer
# Even if deleted later, the file remains in the previous layer
RUN echo "DB_PASSWORD=${DB_PASSWORD}" >> /app/.secrets \
    && echo "JWT_SECRET=${JWT_SECRET}" >> /app/.secrets \
    && echo "AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}" >> /app/.secrets \
    && echo "AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}" >> /app/.secrets

# [PERM-1] VULNERABILITY: World-writable permissions on source files
RUN chmod -R 777 /app

# Initialize database
RUN node db/init.js || true

# [NET-1] VULNERABILITY: Exposing SSH (22) and Node debugger (9229) ports
# Port 22 → SSH brute force
# Port 9229 → Full Node.js REPL access (arbitrary code execution)
EXPOSE 3000 22 9229

# [MISC-3] VULNERABILITY: No HEALTHCHECK — orchestrators can't detect unhealthy containers
# Correct: HEALTHCHECK --interval=30s --timeout=3s CMD curl -f http://localhost:3000/ || exit 1

# [IMG-2] VULNERABILITY: No USER directive — process runs as root (UID 0)
# If app is compromised, attacker has root inside container
# Correct: RUN addgroup -S appgroup && adduser -S appuser -G appgroup
#          USER appuser

# [MISC-1] Start SSH daemon alongside the app (two processes in one container)
CMD service ssh start && node server.js

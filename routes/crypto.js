/**
 * ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
 *
 * VULNERABILITIES DEMONSTRATED IN THIS FILE:
 * ─────────────────────────────────────────────────────────────────────────────
 *  [CRYPT-1]  Weak password hashing — unsalted MD5 (no bcrypt/argon2)
 *  [CRYPT-2]  Weak password hashing — unsalted SHA-1
 *  [CRYPT-3]  Weak password hashing — unsalted SHA-256 (rainbow table vulnerable)
 *  [CRYPT-4]  AES-ECB mode — identical plaintext blocks produce identical ciphertext
 *  [CRYPT-5]  Hardcoded AES key (from secrets.js)
 *  [CRYPT-6]  Hardcoded IV (should be random per encryption operation)
 *  [CRYPT-7]  Encryption key returned in API response
 *  [RAND-1]   Insecure PRNG — Math.random() used for security tokens
 *  [RAND-2]   Short / predictable token length
 *  [RAND-3]   Predictable password-reset token (md5(username + timestamp))
 *  [RAND-4]   Timestamp seed disclosed in response
 *  [HMAC-1]   Weak HMAC — uses MD5 + hardcoded secret
 *  [DISC-1]   Plaintext password echoed in hash response
 *  [DISC-2]   Encryption key returned in response
 */

'use strict';

const express = require('express');
const router  = express.Router();
const crypto  = require('crypto');
const md5     = require('md5');

const secrets = require('../config/secrets');

// ─────────────────────────────────────────────────────────────────────────────
// POST /crypto/hash-password
// VULNERABILITIES: MD5, SHA-1, SHA-256 without salt — all inappropriate for passwords
// ─────────────────────────────────────────────────────────────────────────────
router.post('/hash-password', (req, res) => {
  const { password } = req.body;

  if (!password) return res.status(400).json({ error: 'password required' });

  // [CRYPT-1] VULNERABILITY: MD5 — broken, fast, no salt → rainbow table trivial
  const md5Hash = md5(password);

  // [CRYPT-2] VULNERABILITY: SHA-1 — deprecated for cryptographic use, no salt
  const sha1Hash = crypto.createHash('sha1').update(password).digest('hex');

  // [CRYPT-3] VULNERABILITY: SHA-256 without salt — still vulnerable to rainbow tables
  //           Use bcrypt/scrypt/argon2 with a random salt and appropriate work factor
  const sha256Hash = crypto.createHash('sha256').update(password).digest('hex');

  res.json({
    password,            // [DISC-1] VULNERABILITY: Echoes plaintext password
    hashes: {
      md5:           md5Hash,
      sha1:          sha1Hash,
      sha256_nosalt: sha256Hash
    },
    note: 'All of the above are INSECURE for password storage. Use bcrypt or argon2.'
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /crypto/encrypt
// VULNERABILITIES: ECB mode, hardcoded key, key returned in response
// ─────────────────────────────────────────────────────────────────────────────
router.post('/encrypt', (req, res) => {
  const { plaintext } = req.body;

  if (!plaintext) return res.status(400).json({ error: 'plaintext required' });

  // [CRYPT-5] VULNERABILITY: AES key is hardcoded in config/secrets.js
  const key = Buffer.from(secrets.encryption.key, 'utf8').slice(0, 16);

  // [CRYPT-4] VULNERABILITY: ECB mode — electronic codebook
  //   Identical 16-byte blocks of plaintext produce identical ciphertext blocks
  //   Makes patterns visible — see the "ECB penguin" demonstration
  //   Fix: use AES-CBC or AES-GCM with a random IV
  const cipher    = crypto.createCipheriv('aes-128-ecb', key, null);
  let   encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted      += cipher.final('hex');

  res.json({
    plaintext,
    encrypted,
    algorithm: 'aes-128-ecb',
    key:       secrets.encryption.key    // [DISC-2] VULNERABILITY: Returns the AES key
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /crypto/decrypt
// VULNERABILITY: Hardcoded decryption key returned in response
// ─────────────────────────────────────────────────────────────────────────────
router.post('/decrypt', (req, res) => {
  const { ciphertext } = req.body;

  if (!ciphertext) return res.status(400).json({ error: 'ciphertext required' });

  try {
    // [CRYPT-5] VULNERABILITY: Same hardcoded key used for all encrypt/decrypt
    const key      = Buffer.from(secrets.encryption.key, 'utf8').slice(0, 16);
    const decipher = crypto.createDecipheriv('aes-128-ecb', key, null);
    let   decrypted = decipher.update(ciphertext, 'hex', 'utf8');
    decrypted      += decipher.final('utf8');

    res.json({
      ciphertext,
      decrypted,
      key: secrets.encryption.key    // [DISC-2] VULNERABILITY: Decryption key in response
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /crypto/random-token
// VULNERABILITY: Math.random() — not cryptographically secure
// ─────────────────────────────────────────────────────────────────────────────
router.get('/random-token', (req, res) => {
  // [RAND-1] VULNERABILITY: Math.random() is a PRNG seeded with system time
  //   Output is predictable if seed is known or if attacker can observe outputs
  //   Never use for session tokens, CSRF tokens, reset links, API keys, etc.
  const insecureToken  = Math.random().toString(36).substring(2);  // ~11 chars

  // [RAND-2] VULNERABILITY: Very short token — tiny search space
  const shortToken     = Math.random().toString(16).substring(2, 10); // 8 hex chars

  // [RAND-1] Another insecure approach — using timestamp as randomness
  const timestampToken = Date.now().toString(36) + Math.random().toString(36).substring(2);

  // The CORRECT approach (included for contrast)
  const secureToken    = crypto.randomBytes(32).toString('hex');  // 256-bit secure random

  res.json({
    insecureToken,        // Predictable — DO NOT USE for security
    shortToken,           // Too short   — DO NOT USE for security
    timestampToken,       // Predictable — DO NOT USE for security
    secureToken           // Correct: crypto.randomBytes(32)
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /crypto/generate-reset-token
// VULNERABILITY: Predictable password-reset token (md5 of username + timestamp)
// ─────────────────────────────────────────────────────────────────────────────
router.post('/generate-reset-token', (req, res) => {
  const { username } = req.body;

  if (!username) return res.status(400).json({ error: 'username required' });

  // [RAND-3] VULNERABILITY: Token is deterministic — predictable if attacker knows
  //   the username and approximate timestamp (often leakable via HTTP headers/emails)
  const timestamp = Date.now();
  const token     = md5(`${username}${timestamp}`);  // md5(username + ms timestamp)

  // [RAND-4] VULNERABILITY: Seed values disclosed in response
  res.json({
    username,
    token,
    timestamp,            // Disclosing the seed — makes brute-force trivial
    algorithm: 'md5(username + timestamp)',  // Disclosing the formula
    resetLink: `http://localhost:3000/auth/reset?token=${token}&user=${username}`
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /crypto/sign
// VULNERABILITY: HMAC-MD5 with hardcoded weak secret
// ─────────────────────────────────────────────────────────────────────────────
router.post('/sign', (req, res) => {
  const { data } = req.body;

  if (!data) return res.status(400).json({ error: 'data required' });

  // [HMAC-1] VULNERABILITY:
  //   - MD5 is cryptographically broken (collision attacks feasible)
  //   - Secret is hardcoded ('weak-secret') — attackers who find the code know it
  //   - Fix: use HMAC-SHA256 with a secret from environment variables
  const signature = crypto
    .createHmac('md5', 'weak-secret')   // VULN: MD5 + hardcoded secret
    .update(data)
    .digest('hex');

  res.json({
    data,
    signature,
    algorithm: 'hmac-md5',
    secret:    'weak-secret'   // [DISC-2] VULNERABILITY: Returns the HMAC secret
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /crypto/weak-iv
// VULNERABILITY: Hardcoded IV reused across all encryption operations
// ─────────────────────────────────────────────────────────────────────────────
router.post('/weak-iv', (req, res) => {
  const { plaintext } = req.body;

  // [CRYPT-6] VULNERABILITY: IV is hardcoded and constant
  //   Using the same IV with the same key makes the cipher deterministic
  //   An attacker who observes two ciphertexts encrypted with the same key+IV
  //   can XOR them to cancel out the keystream → plaintext relationship leaked
  const key    = Buffer.from(secrets.encryption.key,  'utf8').slice(0, 16);
  const iv     = Buffer.from(secrets.encryption.iv,   'utf8').slice(0, 16); // Same IV always

  const cipher    = crypto.createCipheriv('aes-128-cbc', key, iv);
  let   encrypted = cipher.update(plaintext || '', 'utf8', 'hex');
  encrypted      += cipher.final('hex');

  res.json({
    plaintext,
    encrypted,
    algorithm: 'aes-128-cbc',
    key:       secrets.encryption.key,  // [DISC-2] Key returned
    iv:        secrets.encryption.iv    // [CRYPT-6] Hardcoded IV returned
  });
});

module.exports = router;

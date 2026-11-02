/**
 * ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
 *
 * VULNERABILITIES DEMONSTRATED IN THIS FILE:
 * ─────────────────────────────────────────────────────────────────────────────
 *  [SQLI-1]   SQL Injection in login (string concatenation in query)
 *  [SQLI-2]   SQL Injection in password reset
 *  [SQLI-3]   SQL Injection in registration
 *  [HASH-1]   Weak password hashing — unsalted MD5
 *  [JWT-1]    Insecure JWT — weak secret ('secret')
 *  [JWT-2]    Insecure JWT — sensitive PII (SSN, credit card) in payload
 *  [JWT-3]    Insecure JWT — 'none' algorithm accepted
 *  [JWT-4]    Insecure JWT — 365-day expiry
 *  [SESS-1]   Storing plaintext password in session
 *  [SESS-2]   Storing PII (credit card) in session
 *  [DISC-1]   Exposing raw SQL query on error
 *  [DISC-2]   Returning password hash in registration response
 *  [DISC-3]   Returning SSN / credit card in login response
 *  [AUTHZ-1]  Password reset with no token / email verification
 *  [AUTHZ-2]  User can self-assign any role during registration (mass assignment)
 *  [BRUTE-1]  No brute-force / rate-limit protection on login
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * SQL Injection Payloads to try:
 *   Login bypass:        username = admin' --
 *   Union dump:          username = ' UNION SELECT 1,2,3,4,5,6,7,8,9,10 --
 *   Boolean blind:       username = admin' AND 1=1 --
 *
 * JWT 'none' algorithm bypass:
 *   1. Base64-decode header, change "alg":"HS256" → "alg":"none"
 *   2. Strip the signature
 *   3. Token = header.payload.
 */

'use strict';

const express = require('express');
const router  = express.Router();
const md5     = require('md5');
const jwt     = require('jsonwebtoken');

const { getDb }  = require('../db/init');
const secrets    = require('../config/secrets');

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/login
// VULNERABILITIES: SQL Injection, Weak Hashing, Insecure JWT, Info Disclosure
// ─────────────────────────────────────────────────────────────────────────────
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const db = getDb();

  // [HASH-1] Password hashed with unsalted MD5 before comparison
  const hashedPassword = md5(password);

  // [SQLI-1] VULNERABILITY: Raw string concatenation → SQL Injection
  // Payload: username = admin' --      (bypasses password check entirely)
  // Payload: username = ' OR '1'='1   (returns first user in table)
  const query = `
  SELECT *
  FROM   users
  WHERE  username = ?
  AND    password = ?
`;

  // [DISC-1] VULNERABILITY: Query string logged to console
  console.log('[LOGIN] Executing query:', query);

  db.get(query, [username, hashedPassword], (err, user) => {
    if (err) {
      // [DISC-1] VULNERABILITY: Raw database error + full query returned to client
      return res.status(500).json({
        error: err.message,
        query,                  // Full SQL query exposed
        database: 'sqlite3'
      });
    }

    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // [JWT-1] VULNERABILITY: Signing with weak secret 'secret'
    // [JWT-2] VULNERABILITY: PII embedded in JWT payload (visible without the secret)
    // [JWT-4] VULNERABILITY: 365-day token lifetime
    const token = jwt.sign(
      {
        id:          user.id,
        username:    user.username,
        role:        user.role,
        email:       user.email,
        credit_card: user.credit_card,   // PII in JWT payload
        ssn:         user.ssn,           // PII in JWT payload
        api_key:     user.api_key
      },
      secrets.jwt.secret,               // Weak secret: 'secret'
      { expiresIn: '365d', algorithm: 'HS256' }
    );

    // [SESS-1] VULNERABILITY: Plaintext password stored in session
    // [SESS-2] VULNERABILITY: Credit card stored in session
    req.session.userId      = user.id;
    req.session.username    = user.username;
    req.session.role        = user.role;
    req.session.password    = password;           // Plaintext password in session
    req.session.credit_card = user.credit_card;   // PII in session

    // [DISC-3] VULNERABILITY: Full user object including SSN / credit card returned
    res.json({
      message: 'Login successful',
      token,
      user: {
        id:          user.id,
        username:    user.username,
        email:       user.email,
        role:        user.role,
        credit_card: user.credit_card,   // Should NEVER be returned to client
        ssn:         user.ssn,           // Should NEVER be returned to client
        api_key:     user.api_key
      }
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /auth/verify
// VULNERABILITIES: JWT 'none' algorithm accepted, error disclosure
// ─────────────────────────────────────────────────────────────────────────────
router.get('/verify', (req, res) => {
  const token = req.headers.authorization?.split(' ')[1] || req.query.token;

  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    // [JWT-3] VULNERABILITY: algorithms array includes 'none'
    // An attacker can forge a token by setting alg: "none" and removing the signature
    const decoded = jwt.verify(token, secrets.jwt.secret, {
      algorithms: ['HS256', 'none']   // 'none' allows signature bypass
    });
    res.json({ valid: true, decoded });
  } catch (err) {
    // [DISC-1] VULNERABILITY: JWT error details exposed
    res.status(401).json({ error: err.message, type: err.name, expiredAt: err.expiredAt });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/reset-password
// VULNERABILITIES: SQL Injection, no identity verification, no token
// ─────────────────────────────────────────────────────────────────────────────
router.post('/reset-password', (req, res) => {
  const { username, newPassword } = req.body;
  const db = getDb();

  // [AUTHZ-1] VULNERABILITY: No email token / OTP / authentication required
  // Anyone can reset anyone's password simply by knowing (or guessing) a username

  // [SQLI-2] VULNERABILITY: SQL Injection in UPDATE statement
  // Payload: username = admin' --
  const query = `
    UPDATE users
    SET    password = '${md5(newPassword)}'
    WHERE  username = '${username}'
  `;

  db.run(query, function (err) {
    if (err) {
      return res.status(500).json({ error: err.message, query });
    }
    res.json({
      message:      `Password reset for user: ${username}`,
      rowsAffected: this.changes,
      newHash:      md5(newPassword)    // [DISC-2] Returns new password hash
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/register
// VULNERABILITIES: SQL Injection, Mass Assignment (self-assign role), weak hash
// ─────────────────────────────────────────────────────────────────────────────
router.post('/register', (req, res) => {
  const { username, password, email, role } = req.body;
  const db = getDb();

  // [AUTHZ-2] VULNERABILITY: Role comes directly from user-supplied request body
  // Payload: { "username": "hacker", "password": "pass", "role": "admin" }
  const userRole = role || 'user';

  // [SQLI-3] VULNERABILITY: SQL Injection in INSERT
  // [HASH-1] VULNERABILITY: Unsalted MD5
  const query = `
    INSERT INTO users (username, password, email, role)
    VALUES ('${username}', '${md5(password)}', '${email}', '${userRole}')
  `;

  db.run(query, function (err) {
    if (err) {
      return res.status(500).json({ error: err.message, query });
    }

    res.status(201).json({
      message:       'User registered successfully',
      id:            this.lastID,
      username,
      role:          userRole,
      password_hash: md5(password)   // [DISC-2] VULNERABILITY: Returns MD5 hash
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /auth/logout
// VULNERABILITY: Session not properly invalidated server-side
// ─────────────────────────────────────────────────────────────────────────────
router.post('/logout', (req, res) => {
  // VULNERABILITY: Only destroys client session object, does not invalidate
  // the session token server-side — old tokens remain valid
  req.session = null;
  res.json({ message: 'Logged out' });
});

module.exports = router;

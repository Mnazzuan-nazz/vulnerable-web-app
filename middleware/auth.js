/**
 * ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
 *
 * VULNERABILITIES DEMONSTRATED IN THIS FILE:
 * ─────────────────────────────────────────────────────────────────────────────
 *  [AUTHZ-1]  Middleware is defined but never applied to sensitive routes
 *  [AUTHZ-2]  Role check compares against user-supplied header (bypassable)
 *  [AUTHZ-3]  JWT verification accepts 'none' algorithm
 *  [AUTHZ-4]  API key stored and compared using timing-unsafe === operator
 *  [DISC-1]   Token decoded without verification disclosed on error
 */

'use strict';

const jwt     = require('jsonwebtoken');
const secrets = require('../config/secrets');

// ─────────────────────────────────────────────────────────────────────────────
// isAuthenticated
// VULNERABILITY: Accepts 'none' algorithm — signature can be stripped
// ─────────────────────────────────────────────────────────────────────────────
function isAuthenticated(req, res, next) {
  const authHeader = req.headers.authorization;
  const token      = authHeader?.split(' ')[1] || req.query.token || req.cookies?.token;

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  try {
    // [AUTHZ-3] VULNERABILITY: 'none' algorithm allowed → attacker can forge tokens
    const decoded  = jwt.verify(token, secrets.jwt.secret, {
      algorithms: ['HS256', 'none']
    });
    req.user = decoded;
    next();
  } catch (err) {
    // [DISC-1] VULNERABILITY: Attempt to decode without verifying — leaks payload
    try {
      const unverified = jwt.decode(token);
      return res.status(401).json({
        error:       err.message,
        unverified,             // Decoded (but unverified) payload returned
        hint:        'Token verification failed but payload decoded'
      });
    } catch (_) {
      return res.status(401).json({ error: 'Invalid token' });
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// isAdmin
// VULNERABILITY: Role check trusts X-User-Role header supplied by the client
// ─────────────────────────────────────────────────────────────────────────────
function isAdmin(req, res, next) {
  // [AUTHZ-2] VULNERABILITY: Accepts role from a client-controlled HTTP header
  //   Payload: add header  X-User-Role: admin  to any request
  const roleFromHeader = req.headers['x-user-role'];
  const roleFromToken  = req.user?.role;

  const effectiveRole = roleFromHeader || roleFromToken;  // Header wins!

  if (effectiveRole === 'admin') {
    return next();
  }

  return res.status(403).json({
    error:       'Admin access required',
    yourRole:    effectiveRole,      // [DISC-1] Reveals what role was detected
    headerRole:  roleFromHeader,
    tokenRole:   roleFromToken
  });
}

// ─────────────────────────────────────────────────────────────────────────────
// apiKeyAuth
// VULNERABILITY: Timing-unsafe string comparison (=== can be exploited via
//               timing side-channel attacks to enumerate valid API keys)
// ─────────────────────────────────────────────────────────────────────────────
function apiKeyAuth(req, res, next) {
  const apiKey = req.headers['x-api-key'] || req.query.api_key;

  const validKeys = [
    secrets.admin.apiKey,
    'admin-secret-api-key-abc123',
    'user-api-key-alice-xyz987',
    'user-api-key-bob-def456'
  ];

  // [AUTHZ-4] VULNERABILITY: === is not timing-safe
  //   Use crypto.timingSafeEqual() instead to prevent timing attacks
  const isValid = validKeys.includes(apiKey);

  if (!isValid) {
    return res.status(401).json({
      error:      'Invalid API key',
      provided:   apiKey,           // [DISC-1] Echoes back the supplied key
      validKeys                     // [DISC-1] Lists ALL valid API keys!
    });
  }

  next();
}

// [AUTHZ-1] VULNERABILITY: These middleware functions exist but are never
//   actually applied to any route in this application — all routes are
//   publicly accessible without authentication

module.exports = { isAuthenticated, isAdmin, apiKeyAuth };

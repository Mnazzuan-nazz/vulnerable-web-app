/**
 * ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
 *
 * VULNERABILITIES DEMONSTRATED IN THIS FILE:
 * ─────────────────────────────────────────────────────────────────────────────
 *  [PATH-1]  Path Traversal (read) — arbitrary file read via ../
 *  [PATH-2]  Path Traversal (write) — arbitrary file write via ../
 *  [PATH-3]  Path Traversal (logs) — arbitrary log file access
 *  [UPLD-1]  Unrestricted File Upload — no MIME type validation
 *  [UPLD-2]  Unrestricted File Upload — user controls final filename (path traversal)
 *  [UPLD-3]  No file size limit on upload
 *  [DIR-1]   Directory Listing — any directory on the server
 *  [DISC-1]  Server path disclosed in responses
 *  [DISC-2]  Detailed filesystem error (errno, syscall, path) returned to client
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * Example attack payloads:
 *
 *  Read /etc/passwd:
 *    GET /files/read?filename=../../../../etc/passwd
 *    GET /files/read?filename=..%2F..%2F..%2Fetc%2Fpasswd
 *    GET /files/read?filename=....//....//etc/passwd
 *
 *  Read Windows files:
 *    GET /files/read?filename=..\..\..\..\Windows\System32\drivers\etc\hosts
 *
 *  Overwrite server.js:
 *    POST /files/write  body: { "filename": "../../server.js", "content": "evil code" }
 *
 *  Upload a web shell (if server executes uploads):
 *    POST /files/upload  multipart: file=shell.php (Content-Type: application/octet-stream)
 *
 *  List root directory:
 *    GET /files/list?dir=/
 *    GET /files/list?dir=C:\
 */

'use strict';

const express = require('express');
const router  = express.Router();
const fs      = require('fs');
const path    = require('path');
const multer  = require('multer');

// ─────────────────────────────────────────────────────────────────────────────
// Multer configuration — INTENTIONALLY INSECURE
// ─────────────────────────────────────────────────────────────────────────────
// [UPLD-1] VULNERABILITY: No file type restriction (fileFilter absent)
// [UPLD-3] VULNERABILITY: No file size limit
// Accepts .php, .sh, .exe, .js — anything
const upload = multer({
  dest: path.join(__dirname, '../uploads/')
  // No limits:      { } — accepts arbitrarily large files
  // No fileFilter:  accepts any MIME type
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /files/read
// VULNERABILITY: Path Traversal — reads any file on the server
// ─────────────────────────────────────────────────────────────────────────────
router.get('/read', (req, res) => {
  const filename = req.query.filename;

  if (!filename) {
    return res.status(400).json({ error: 'filename parameter required' });
  }

  // [PATH-1] VULNERABILITY: path.join does NOT prevent traversal sequences
  // An attacker supplies: filename=../../../../etc/passwd
  // Resulting path escapes the intended directory entirely
  const filePath = path.join(__dirname, '../files/', filename);

  // No check: filePath.startsWith(allowedDir)  ← the fix that's missing

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      // [DISC-2] VULNERABILITY: Detailed filesystem error reveals server internals
      return res.status(500).json({
        error:   err.message,
        code:    err.code,         // e.g. ENOENT, EACCES
        syscall: err.syscall,
        path:    filePath,         // Full server-side absolute path disclosed
        errno:   err.errno
      });
    }

    // [DISC-1] VULNERABILITY: Returns resolved path in response headers
    res.setHeader('X-File-Path', filePath);
    res.send(data);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /files/write
// VULNERABILITY: Path Traversal — writes arbitrary content to any path
// ─────────────────────────────────────────────────────────────────────────────
router.post('/write', (req, res) => {
  const { filename, content } = req.body;

  // [PATH-2] VULNERABILITY: User controls both the path and content of the file
  // No directory restriction, no content validation
  // Payload: filename=../../server.js  → overwrites the main application file
  // Payload: filename=../../.env       → overwrites environment config
  const filePath = path.join(__dirname, '../files/', filename);

  fs.writeFile(filePath, content || '', 'utf8', (err) => {
    if (err) {
      return res.status(500).json({
        error:   err.message,
        path:    filePath,         // [DISC-1] Path disclosed
        syscall: err.syscall
      });
    }
    res.json({
      message: 'File written successfully',
      path:    filePath,           // [DISC-1] Absolute server path returned
      size:    (content || '').length
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /files/upload
// VULNERABILITY: Unrestricted file upload + path traversal via filename
// ─────────────────────────────────────────────────────────────────────────────
router.post('/upload', upload.single('file'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  // [UPLD-2] VULNERABILITY: Final filename comes from original upload name
  // Attacker supplies filename: ../../../../etc/cron.d/backdoor
  // Or: ../views/malicious.ejs  → server-side template injection
  const originalName = req.file.originalname;
  const destPath     = path.join(__dirname, '../uploads/', originalName);

  // Move temp upload to attacker-controlled filename
  fs.rename(req.file.path, destPath, (err) => {
    if (err) {
      return res.status(500).json({ error: err.message, path: destPath });
    }

    res.json({
      message:      'File uploaded successfully',
      originalName,
      savedPath:    destPath,        // [DISC-1] Server path returned
      size:         req.file.size,
      mimetype:     req.file.mimetype,
      // Note: mimetype comes from client — trivially spoofed
    });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /files/list
// VULNERABILITY: Directory listing — no restrictions on which directory
// ─────────────────────────────────────────────────────────────────────────────
router.get('/list', (req, res) => {
  // [DIR-1] VULNERABILITY: User controls the directory to list
  // Default falls back to project root, but attacker can point to /
  // Payload: dir=/  or  dir=C:\
  const dir = req.query.dir || path.join(__dirname, '../');

  fs.readdir(dir, { withFileTypes: true }, (err, entries) => {
    if (err) {
      return res.status(500).json({ error: err.message, path: dir });
    }

    const files = entries.map(e => ({
      name:  e.name,
      type:  e.isDirectory() ? 'directory' : 'file',
      path:  path.join(dir, e.name)   // [DISC-1] Full paths returned
    }));

    res.json({ directory: dir, count: files.length, files });
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /files/logs
// VULNERABILITY: Path Traversal — read arbitrary log / config files
// ─────────────────────────────────────────────────────────────────────────────
router.get('/logs', (req, res) => {
  // [PATH-3] VULNERABILITY: User-supplied filename used without sanitization
  // Payload: file=../../config/secrets.js   → leaks all hardcoded credentials
  // Payload: file=../../.env               → leaks environment secrets
  const logFile = req.query.file || 'app.log';
  const logPath = path.join(__dirname, '../logs/', logFile);

  fs.readFile(logPath, 'utf8', (err, data) => {
    if (err) {
      return res.status(500).json({ error: err.message, path: logPath });
    }
    res.type('text/plain').send(data);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// GET /files/delete
// VULNERABILITY: Arbitrary file deletion via path traversal
// ─────────────────────────────────────────────────────────────────────────────
router.delete('/delete', (req, res) => {
  const filename = req.query.filename;

  // No authentication, no path restriction
  // Payload: filename=../../package.json  → deletes application files
  const filePath = path.join(__dirname, '../files/', filename);

  fs.unlink(filePath, (err) => {
    if (err) return res.status(500).json({ error: err.message, path: filePath });
    res.json({ message: 'File deleted', path: filePath });
  });
});

module.exports = router;

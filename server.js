/**
 * ╔══════════════════════════════════════════════════════════════════════╗
 * ║          ⚠️  INTENTIONALLY VULNERABLE WEB APPLICATION ⚠️            ║
 * ╠══════════════════════════════════════════════════════════════════════╣
 * ║  This application contains numerous security vulnerabilities and is  ║
 * ║  intended SOLELY for security training and demonstration purposes.   ║
 * ║                                                                      ║
 * ║  DO NOT deploy in any production or internet-facing environment.     ║
 * ║  DO NOT use any of this code as a template for real applications.    ║
 * ╚══════════════════════════════════════════════════════════════════════╝
 *
 * VULNERABILITIES IN THIS FILE:
 *  - Insecure session configuration (no secure flag, httpOnly=false, weak secret)
 *  - No rate limiting on any route
 *  - No CSRF protection
 *  - No security headers (Helmet.js absent)
 *  - Server listens on all interfaces (0.0.0.0)
 *  - Full error details (stack traces) exposed to clients
 *  - Environment variables exposed via root endpoint
 *  - Credentials printed to console on startup
 *  - No input validation middleware
 */

'use strict';

const express       = require('express');
const session       = require('express-session');
const bodyParser    = require('body-parser');
const cookieParser  = require('cookie-parser');
const morgan        = require('morgan');
const path          = require('path');

const secrets = require('./config/secrets');

// ── Route handlers ────────────────────────────────────────────────────────────
const authRoutes    = require('./routes/auth');
const userRoutes    = require('./routes/users');
const fileRoutes    = require('./routes/files');
const commandRoutes = require('./routes/commands');
const cryptoRoutes  = require('./routes/crypto');
const apiRoutes     = require('./routes/api');

const { initDatabase } = require('./db/init');

const app  = express();
const PORT = process.env.PORT || 3000;

// ── VULNERABILITY: Verbose request logging exposes sensitive query params ─────
app.use(morgan('combined'));

// ── VULNERABILITY: No request body size limits → DoS via large payloads ──────
app.use(bodyParser.json({ limit: '100mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '100mb' }));
app.use(cookieParser());

// ── Static files & templating ─────────────────────────────────────────────────
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ── VULNERABILITY: Insecure session configuration ─────────────────────────────
app.use(session({
  secret: 'secret123',              // VULN: Weak, hardcoded session secret
  resave: true,                     // VULN: Re-saves unchanged sessions
  saveUninitialized: true,          // VULN: Saves uninitialized sessions
  name: 'sessionId',                // VULN: Default/predictable cookie name
  cookie: {
    secure: false,                  // VULN: Cookie transmitted over HTTP (no TLS required)
    httpOnly: false,                // VULN: Cookie accessible via JavaScript → XSS theft
    maxAge: 365 * 24 * 60 * 60 * 1000, // VULN: 1-year session lifetime
    sameSite: false                 // VULN: No SameSite → CSRF attacks possible
  }
}));

// ── INTENTIONAL ABSENCES ─────────────────────────────────────────────────────
//  - No Helmet.js        → Missing: CSP, HSTS, X-Frame-Options, X-XSS-Protection, etc.
//  - No rate limiting    → Brute force / credential stuffing attacks possible
//  - No CSRF tokens      → Cross-site request forgery attacks possible
//  - No input validation → All input passed raw to DB / shell / filesystem

// ── Routes ────────────────────────────────────────────────────────────────────
app.use('/auth',    authRoutes);
app.use('/users',   userRoutes);
app.use('/files',   fileRoutes);
app.use('/cmd',     commandRoutes);
app.use('/crypto',  cryptoRoutes);
app.use('/api',     apiRoutes);

// ── VULNERABILITY: Root endpoint exposes all process environment variables ────
app.get('/', (req, res) => {
  res.json({
    app:     'Vulnerable Web App v1.0.0',
    status:  'running',
    node:    process.version,
    env:     process.env,           // VULN: Full env dump (may contain cloud credentials)
    uptime:  process.uptime(),
    cwd:     process.cwd(),
    pid:     process.pid,
    secrets: {                      // VULN: Hardcoded secrets exposed on root endpoint
      dbPassword:   secrets.database.password,
      jwtSecret:    secrets.jwt.secret,
      awsKey:       secrets.aws.accessKeyId,
      stripeSecret: secrets.stripe.secretKey
    }
  });
});

// ── VULNERABILITY: Global error handler leaks stack traces to clients ─────────
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('[ERROR]', err);
  res.status(500).json({
    error:   err.message,           // VULN: Raw error message
    stack:   err.stack,             // VULN: Full stack trace exposed
    type:    err.constructor.name,
    code:    err.code,
    syscall: err.syscall,
    path:    err.path,
    errno:   err.errno
  });
});

// ── Start server ──────────────────────────────────────────────────────────────
initDatabase(() => {
  // VULNERABILITY: Binds to all network interfaces
  app.listen(PORT, '0.0.0.0', () => {
    // VULNERABILITY: Prints credentials to console/logs on startup
    console.log(`
╔══════════════════════════════════════════════════════════╗
║         ⚠️  VULNERABLE WEB APP RUNNING ⚠️                ║
╠══════════════════════════════════════════════════════════╣
║  URL          : http://0.0.0.0:${PORT}                      ║
║  DB Password  : ${secrets.database.password.padEnd(41)}║
║  Admin Creds  : ${(secrets.admin.username + ':' + secrets.admin.password).padEnd(41)}║
║  JWT Secret   : ${secrets.jwt.secret.padEnd(41)}║
║  AWS Key ID   : ${secrets.aws.accessKeyId.padEnd(41)}║
║  Stripe Key   : ${secrets.stripe.secretKey.substring(0, 30).padEnd(41)}║
╚══════════════════════════════════════════════════════════╝
    `);
  });
});

module.exports = app;

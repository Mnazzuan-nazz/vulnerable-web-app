/**
 * ⚠️  WARNING: INTENTIONALLY VULNERABLE - FOR EDUCATIONAL PURPOSES ONLY ⚠️
 *
 * VULNERABILITIES DEMONSTRATED:
 *  - Storing passwords as MD5 hashes (no salt, broken algorithm)
 *  - Storing plaintext sensitive data (credit cards, SSNs)
 *  - No data encryption at rest
 *  - Hardcoded seed credentials
 *  - Database accessible outside web root
 */

'use strict';

const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const md5 = require('md5');

// VULNERABILITY: Database stored in accessible directory
const DB_PATH = path.join(__dirname, 'vulnerable.db');

let db;

function getDb() {
  if (!db) {
    db = new sqlite3.Database(DB_PATH, (err) => {
      if (err) {
        // VULNERABILITY: Logs full DB path and error details
        console.error('Database connection error:', err.message, 'Path:', DB_PATH);
      } else {
        console.log(`Connected to SQLite database at: ${DB_PATH}`);
      }
    });
    db.run('PRAGMA journal_mode = WAL');
  }
  return db;
}

function initDatabase(callback) {
  const database = getDb();

  database.serialize(() => {
    // ─── Users table: stores sensitive data in plaintext ───────────────
    database.run(`
      CREATE TABLE IF NOT EXISTS users (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        username    TEXT    NOT NULL UNIQUE,
        password    TEXT    NOT NULL,
        email       TEXT,
        role        TEXT    DEFAULT 'user',
        credit_card TEXT,
        ssn         TEXT,
        api_key     TEXT,
        address     TEXT,
        phone       TEXT,
        created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // ─── Products table ─────────────────────────────────────────────────
    database.run(`
      CREATE TABLE IF NOT EXISTS products (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        name         TEXT    NOT NULL,
        description  TEXT,
        price        REAL,
        secret_field TEXT
      )
    `);

    // ─── Orders table ───────────────────────────────────────────────────
    database.run(`
      CREATE TABLE IF NOT EXISTS orders (
        id         INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id    INTEGER,
        product_id INTEGER,
        quantity   INTEGER,
        total      REAL,
        status     TEXT DEFAULT 'pending'
      )
    `);

    // ─── Sessions table (insecure) ───────────────────────────────────────
    database.run(`
      CREATE TABLE IF NOT EXISTS sessions (
        id         TEXT PRIMARY KEY,
        user_id    INTEGER,
        token      TEXT,
        data       TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // VULNERABILITY: Passwords stored as unsalted MD5 hashes
    // VULNERABILITY: Sensitive PII (SSN, credit card) stored in plaintext
    // VULNERABILITY: Hardcoded seed data with real-looking sensitive data
    database.run(`
      INSERT OR IGNORE INTO users
        (id, username, password, email, role, credit_card, ssn, api_key, address, phone)
      VALUES
        (1, 'admin',  '${md5('admin123')}',   'admin@corp.local',  'admin',
         '4111111111111111', '123-45-6789', 'admin-secret-api-key-abc123',
         '1 Admin St, Corp City, CA 90001', '+1-555-000-0001'),

        (2, 'alice',  '${md5('password')}',   'alice@example.com', 'user',
         '4012888888881881', '987-65-4321', 'user-api-key-alice-xyz987',
         '42 Wallaby Way, Sydney, NSW 2000', '+1-555-000-0002'),

        (3, 'bob',    '${md5('bob123')}',     'bob@example.com',   'user',
         '5500005555555559', '456-78-9012', 'user-api-key-bob-def456',
         '221B Baker Street, London, UK',   '+1-555-000-0003'),

        (4, 'charlie','${md5('charlie')}',    'charlie@test.com',  'manager',
         '370000000000002',  '789-01-2345', 'mgr-api-key-charlie-ghi789',
         '10 Downing Street, London, UK',   '+1-555-000-0004')
    `);

    database.run(`
      INSERT OR IGNORE INTO products (id, name, description, price, secret_field)
      VALUES
        (1, 'Basic Widget',    'A simple widget',       9.99,  'cost:2.50;margin:7.49'),
        (2, 'Premium Widget',  'An enhanced widget',   19.99,  'cost:5.00;margin:14.99'),
        (3, 'Enterprise Pack', 'Bundle of features',   99.99,  'cost:20.00;margin:79.99')
    `);

    console.log('[DB] Tables created and seed data inserted.');
    if (callback) callback();
  });
}

module.exports = { getDb, initDatabase };

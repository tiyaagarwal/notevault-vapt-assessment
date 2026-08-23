const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');
const crypto = require('node:crypto');

const DB_PATH = path.join(__dirname, 'notevault.db');
const db = new DatabaseSync(DB_PATH);

db.exec(`
  DROP TABLE IF EXISTS comments;
  DROP TABLE IF EXISTS notes;
  DROP TABLE IF EXISTS users;

  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    salt TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'user'
  );

  CREATE TABLE notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    body TEXT NOT NULL
  );

  CREATE TABLE comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    note_id INTEGER NOT NULL,
    author TEXT NOT NULL,
    body TEXT NOT NULL
  );
`);

// Remediates VULN-04: salted scrypt hash instead of plaintext storage.
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { hash, salt };
}

const insertUser = db.prepare('INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)');
for (const [username, password, role] of [
  ['alice', 'alice123', 'user'],
  ['bob', 'bobpassword', 'user'],
  ['admin', 'admin123', 'admin'],
]) {
  const { hash, salt } = hashPassword(password);
  insertUser.run(username, hash, salt, role);
}

const insertNote = db.prepare('INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)');
insertNote.run(1, "Alice's private note", 'Server root password rotation is scheduled for the 1st. -A');
insertNote.run(2, "Bob's meeting notes", 'Q3 budget figures: revenue $482,000, payroll $210,000.');
insertNote.run(3, 'Admin runbook', 'Incident escalation contact: admin@notevault.local, PagerDuty key ends 8841.');

module.exports = { db, hashPassword };

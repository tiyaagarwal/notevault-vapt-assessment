const { DatabaseSync } = require('node:sqlite');
const path = require('node:path');

const DB_PATH = path.join(__dirname, 'notevault.db');
const db = new DatabaseSync(DB_PATH);

db.exec(`
  DROP TABLE IF EXISTS comments;
  DROP TABLE IF EXISTS notes;
  DROP TABLE IF EXISTS users;

  CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
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

// VULN-04 (Broken Authentication): passwords stored and compared in plaintext, no hashing.
const insertUser = db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)');
insertUser.run('alice', 'alice123', 'user');
insertUser.run('bob', 'bobpassword', 'user');
insertUser.run('admin', 'admin123', 'admin');

const insertNote = db.prepare('INSERT INTO notes (owner_id, title, body) VALUES (?, ?, ?)');
insertNote.run(1, "Alice's private note", 'Server root password rotation is scheduled for the 1st. -A');
insertNote.run(2, "Bob's meeting notes", 'Q3 budget figures: revenue $482,000, payroll $210,000.');
insertNote.run(3, 'Admin runbook', 'Incident escalation contact: admin@notevault.local, PagerDuty key ends 8841.');

module.exports = { db };

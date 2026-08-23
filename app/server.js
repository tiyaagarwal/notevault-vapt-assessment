const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { db } = require('./db');

const app = express();
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// VULN-04 (Broken Authentication): hardcoded, weak, guessable JWT signing secret
// committed to source control. No expiry, no rotation, same secret across envs.
const JWT_SECRET = 'notevault_secret_123';

function authOptional(req, res, next) {
  const token = req.cookies.token;
  if (token) {
    try {
      req.user = jwt.verify(token, JWT_SECRET);
    } catch {
      req.user = null;
    }
  }
  next();
}
app.use(authOptional);

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'authentication required' });
  next();
}

// --- Auth ---
app.post('/api/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  try {
    // VULN-04: plaintext password storage
    db.prepare('INSERT INTO users (username, password, role) VALUES (?, ?, ?)').run(username, password, 'user');
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: 'username already exists' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  // VULN-04: plaintext comparison, no rate limiting / lockout on this endpoint
  if (!user || user.password !== password) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET);
  res.cookie('token', token, { httpOnly: true });
  res.json({ ok: true, token });
});

app.post('/api/logout', (req, res) => {
  res.clearCookie('token');
  res.json({ ok: true });
});

// --- Notes ---
app.get('/api/notes', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT id, owner_id, title FROM notes WHERE owner_id = ?').all(req.user.id);
  res.json(rows);
});

// VULN-03 (Broken Access Control / IDOR): any authenticated user can fetch any
// note by guessing/incrementing the numeric id — no ownership check.
app.get('/api/notes/:id', requireAuth, (req, res) => {
  const note = db.prepare(`SELECT * FROM notes WHERE id = ${req.params.id}`).get();
  // (this line is also VULN-01, see below — kept identical to the deployed build)
  if (!note) return res.status(404).json({ error: 'not found' });
  const comments = db.prepare('SELECT * FROM comments WHERE note_id = ?').all(note.id);
  res.json({ ...note, comments });
});

// VULN-01 (SQL Injection): user-controlled `q` is concatenated directly into
// the SQL string instead of using a parameterized query.
app.get('/api/search', requireAuth, (req, res) => {
  const q = req.query.q || '';
  const sql = `SELECT id, owner_id, title FROM notes WHERE title LIKE '%${q}%'`;
  try {
    const rows = db.prepare(sql).all();
    res.json(rows);
  } catch (e) {
    // VULN-05: verbose error leaks raw SQL + stack trace to the client
    res.status(500).json({ error: e.message, sql, stack: e.stack });
  }
});

// VULN-02 (Stored XSS): comment body is stored and later rendered without
// escaping in note.ejs (`<%- %>` instead of `<%= %>`).
app.post('/api/notes/:id/comments', requireAuth, (req, res) => {
  const { body } = req.body;
  db.prepare('INSERT INTO comments (note_id, author, body) VALUES (?, ?, ?)').run(req.params.id, req.user.username, body);
  res.json({ ok: true });
});

app.get('/notes/:id', requireAuth, (req, res) => {
  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id);
  if (!note) return res.status(404).send('not found');
  const comments = db.prepare('SELECT * FROM comments WHERE note_id = ?').all(note.id);
  res.render('note', { note, comments });
});

// VULN-05 (Security Misconfiguration): unauthenticated debug endpoint leaks
// environment variables, the JWT signing secret, and internal paths.
app.get('/api/debug/config', (req, res) => {
  res.json({
    env: process.env,
    jwtSecret: JWT_SECRET,
    dbPath: require('node:path').join(__dirname, 'notevault.db'),
    nodeVersion: process.version,
  });
});

app.get('/', (req, res) => res.render('login', { user: req.user }));

const PORT = process.env.PORT || 4001;
app.listen(PORT, () => console.log(`NoteVault (VULNERABLE build) listening on http://localhost:${PORT}`));

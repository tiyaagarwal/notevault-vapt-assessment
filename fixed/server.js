const crypto = require('node:crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');
const { db, hashPassword } = require('./db');

// Remediates VULN-04: no hardcoded fallback secret. The app refuses to start
// without a properly configured, environment-provided signing key.
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error('FATAL: JWT_SECRET env var must be set to a random string of at least 32 characters.');
  process.exit(1);
}

const app = express();
app.set('view engine', 'ejs');
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

// Remediates VULN-06: baseline security headers (in production, prefer `helmet`).
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  res.removeHeader('X-Powered-By');
  next();
});

// Remediates VULN-06: basic in-memory rate limit / lockout on login attempts.
const loginAttempts = new Map();
function isRateLimited(key) {
  const now = Date.now();
  const record = loginAttempts.get(key) || { count: 0, windowStart: now };
  if (now - record.windowStart > 60_000) {
    record.count = 0;
    record.windowStart = now;
  }
  record.count += 1;
  loginAttempts.set(key, record);
  return record.count > 5;
}

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
  if (!username || !password || password.length < 8) {
    return res.status(400).json({ error: 'username and a password of at least 8 characters are required' });
  }
  try {
    const { hash, salt } = hashPassword(password);
    db.prepare('INSERT INTO users (username, password_hash, salt, role) VALUES (?, ?, ?, ?)').run(username, hash, salt, 'user');
    res.json({ ok: true });
  } catch (e) {
    res.status(400).json({ error: 'username already exists' });
  }
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  if (isRateLimited(`${req.ip}:${username}`)) {
    return res.status(429).json({ error: 'too many attempts, try again later' });
  }
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  const { hash } = user ? hashPassword(password, user.salt) : { hash: null };
  // Remediates VULN-04: constant-time hash comparison, no plaintext password storage.
  const valid = user && hash && crypto.timingSafeEqual(Buffer.from(hash), Buffer.from(user.password_hash));
  if (!valid) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  const token = jwt.sign({ id: user.id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '1h' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production' });
  res.json({ ok: true });
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

// Remediates VULN-03: explicit ownership check (admins may access any note).
app.get('/api/notes/:id', requireAuth, (req, res) => {
  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id);
  if (!note) return res.status(404).json({ error: 'not found' });
  if (note.owner_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  const comments = db.prepare('SELECT * FROM comments WHERE note_id = ?').all(note.id);
  res.json({ ...note, comments });
});

// Remediates VULN-01: fully parameterized query, no string concatenation.
// Also scoped to the caller's own notes to avoid re-introducing VULN-03.
app.get('/api/search', requireAuth, (req, res) => {
  const q = req.query.q || '';
  const rows = db
    .prepare('SELECT id, owner_id, title FROM notes WHERE owner_id = ? AND title LIKE ?')
    .all(req.user.id, `%${q}%`);
  res.json(rows);
});

app.post('/api/notes/:id/comments', requireAuth, (req, res) => {
  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id);
  if (!note) return res.status(404).json({ error: 'not found' });
  if (note.owner_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'forbidden' });
  }
  const { body } = req.body;
  if (typeof body !== 'string' || body.length === 0 || body.length > 2000) {
    return res.status(400).json({ error: 'invalid comment body' });
  }
  db.prepare('INSERT INTO comments (note_id, author, body) VALUES (?, ?, ?)').run(req.params.id, req.user.username, body);
  res.json({ ok: true });
});

app.get('/notes/:id', requireAuth, (req, res) => {
  const note = db.prepare('SELECT * FROM notes WHERE id = ?').get(req.params.id);
  if (!note) return res.status(404).send('not found');
  if (note.owner_id !== req.user.id && req.user.role !== 'admin') {
    return res.status(403).send('forbidden');
  }
  const comments = db.prepare('SELECT * FROM comments WHERE note_id = ?').all(note.id);
  res.render('note', { note, comments });
});

// Remediates VULN-05: debug/config endpoint removed entirely (no equivalent route exists).

app.get('/', (req, res) => res.render('login', { user: req.user }));

// Remediates VULN-05: generic error responses, no stack traces or internals sent to clients.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'internal server error' });
});

const PORT = process.env.PORT || 4002;
app.listen(PORT, () => console.log(`NoteVault (REMEDIATED build) listening on http://localhost:${PORT}`));

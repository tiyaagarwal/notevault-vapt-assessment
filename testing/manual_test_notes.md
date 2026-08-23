# Manual Testing Notes & Tool Workflow

This assessment used a standard black-box workflow. The exact requests are captured in [`postman_collection.json`](postman_collection.json) and reproduced with real responses in [`report/VAPT_Report.md`](../report/VAPT_Report.md); this file documents *how* each tool was used.

## Burp Suite

1. **Proxy** — browser/`curl` traffic to `localhost:4001` routed through Burp's intercepting proxy to build the site map (`/`, `/api/login`, `/api/register`, `/api/notes`, `/api/notes/:id`, `/api/search`, `/api/notes/:id/comments`, `/api/debug/config`).
2. **Repeater** — each parameter (`q` on `/api/search`, `id` on `/api/notes/:id`, `body` on comments) was sent to Repeater and manually mutated: SQL metacharacters (`'`, `--`, `UNION SELECT`) on `q`; sequential integers on `id`; HTML/JS payloads on `body`.
3. **Intruder** — used in *sniper* mode against `/api/notes/:id` with a numeric payload set (`1`–`20`) to confirm the IDOR was consistent across every note ID, not a one-off.
4. **Decoder** — used to inspect the JWT (`token` cookie) structure (header/payload/signature) before attempting to forge one with a guessed secret.

## Postman

The full request set (grouped by finding) is in [`postman_collection.json`](postman_collection.json), importable directly into Postman. A `base_url` collection variable lets you re-point every request at the vulnerable build (`:4001`) or the remediated build (`:4002`) to compare behavior side by side, which is how the retest evidence in the report was produced.

## Manual / scripted testing

For endpoints where scripting was faster than the UI (bulk retesting, exact PoC reproduction for the report), `curl` and small Node.js snippets were used directly — see the exact commands referenced throughout `report/VAPT_Report.md`. Every response quoted in the report is real output captured from a locally running instance, not a mockup.

## Recon checklist used

- [x] Map all routes (unauthenticated crawl + authenticated crawl as `alice`)
- [x] Identify all user-controlled input points (query params, JSON bodies, path params, cookies)
- [x] Test authorization boundaries: same user across resources (IDOR), user vs admin (privilege escalation)
- [x] Test input handling: SQL metacharacters, HTML/JS payloads, oversized/malformed input
- [x] Inspect session token structure and signing
- [x] Check for debug/admin endpoints not linked from the UI
- [x] Check response headers for information disclosure and missing hardening headers
- [x] Trigger error conditions and inspect verbosity of the response

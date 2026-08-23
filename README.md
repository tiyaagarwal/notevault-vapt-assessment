# Black-Box VAPT Assessment — NoteVault

A self-contained, reproducible black-box penetration test: a deliberately vulnerable web app, a real assessment performed against it with Burp Suite / Postman / manual testing, a professional VAPT report with PoCs and CVSS scoring for 5 critical/high findings, and a remediated build with retest evidence proving each fix.

**Read the full report: [`report/VAPT_Report.md`](report/VAPT_Report.md)**

> ⚠️ **Disclaimer:** `app/` is an *intentionally vulnerable* application built for this repository. It contains real, exploitable bugs on purpose (SQL injection, stored XSS, IDOR, plaintext password storage, a hardcoded secret, an unauthenticated debug endpoint). Never deploy `app/` anywhere reachable from the internet. It exists solely so this assessment could be performed and documented end-to-end, legally and safely, against a target the author owns.

## What's in this repo

| Path | Purpose |
|---|---|
| [`app/`](app) | The vulnerable NoteVault build — the assessment target |
| [`fixed/`](fixed) | The remediated build, with every fix from the report applied |
| [`report/VAPT_Report.md`](report/VAPT_Report.md) | The full assessment: methodology, 5 detailed findings with real PoCs and CVSS scores, retest evidence, and metrics |
| [`testing/postman_collection.json`](testing/postman_collection.json) | Importable Postman collection of every request used, grouped by finding |
| [`testing/manual_test_notes.md`](testing/manual_test_notes.md) | Burp Suite workflow (Proxy/Repeater/Intruder/Decoder) and manual testing checklist |
| [`scripts/`](scripts) | Convenience scripts to run either build, plus `verify_fixes.sh` to automate the retest evidence |
| [`SECURITY.md`](SECURITY.md) | Responsible-use disclaimer for the intentionally vulnerable build |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | How to add a new finding (vuln → PoC → report entry → fix → retest) |

## Findings summary

| ID | Finding | Severity | CVSS 3.1 | Status |
|---|---|---|---|---|
| VULN-01 | SQL Injection (`/api/search`) | Critical | 9.1 | Fixed & retested |
| VULN-02 | Stored XSS (note comments) | High | 8.7 | Fixed & retested |
| VULN-03 | IDOR / broken object-level authorization | Critical | 8.1 | Fixed & retested |
| VULN-04 | Broken auth — plaintext passwords + hardcoded JWT secret | Critical | 9.1 | Fixed & retested |
| VULN-05 | Security misconfiguration — unauthenticated debug endpoint | High | 7.5 | Fixed & retested |
| VULN-06 | Missing security headers / no login rate limiting | Medium | 5.3 | Fixed & retested |
| VULN-07–10 | CSRF, audit logging, dependency scanning, MFA | Medium/Low | — | Open — see report §5 |

**60% of all identified findings** were remediated and independently retested within this engagement; **100% of critical/high findings** were closed. Full methodology for these numbers is in [report §6](report/VAPT_Report.md#6-metrics-methodology).

## Running it yourself

Requires Node.js 22+ (uses the built-in `node:sqlite` module, no native build step).

```bash
# vulnerable build — http://localhost:4001
./scripts/run_vuln_app.sh

# remediated build — http://localhost:4002
./scripts/run_fixed_app.sh
```

Seeded accounts on both builds: `alice` / `alice123`, `bob` / `bobpassword`, `admin` / `admin123`.

Reproduce any finding from the report, e.g. the IDOR:

```bash
curl -s -c /tmp/cookies.txt -X POST http://localhost:4001/api/login \
  -H "Content-Type: application/json" -d '{"username":"alice","password":"alice123"}'

curl -s -b /tmp/cookies.txt http://localhost:4001/api/notes/3   # returns admin's note
curl -s -b /tmp/cookies.txt http://localhost:4002/api/notes/3   # 403 forbidden on the fixed build
```

Or run the whole retest suite at once with both builds up (`scripts/run_vuln_app.sh` and `scripts/run_fixed_app.sh` in separate terminals):

```bash
./scripts/verify_fixes.sh
```

This replays all 5 critical/high findings' PoCs against the fixed build and asserts each one is closed — the same checks documented in [report §4](report/VAPT_Report.md#4-remediation-verification-retest).

## Tools

- **Burp Suite** — proxying, Repeater for payload iteration, Intruder for ID enumeration, Decoder for JWT inspection
- **Postman** — the request collection in `testing/postman_collection.json`
- **Manual testing** — `curl` / Node.js for scripted, exactly-reproducible PoCs (used to generate every response quoted in the report)

## License

MIT — see [`LICENSE`](LICENSE).

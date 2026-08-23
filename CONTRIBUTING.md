# Contributing

This repo is primarily a portfolio artifact, but improvements are welcome — especially additional findings, better remediation patterns, or corrections to the report.

## Adding a new finding

1. Introduce the vulnerability in `app/` only (never `fixed/` directly).
2. Confirm it's exploitable with a real request — `curl`, Postman, or Burp — and capture the actual response.
3. Add a numbered `VULN-NN` entry to `report/VAPT_Report.md` following the existing structure: endpoint, CVSS 3.1 vector/score, root cause, PoC with real captured output, impact, remediation.
4. Implement the fix in `fixed/`, then retest the same PoC against it and record the before/after in report §4.
5. Add the corresponding request(s) to `testing/postman_collection.json` and, if practical, an automated check in `scripts/verify_fixes.sh`.
6. Update the findings table in `README.md`.

## Style

- Every claim in the report should be backed by a request/response you actually ran locally — no fabricated output.
- Keep `app/` and `fixed/` structurally close so the diff between them stays readable as "here's the fix."

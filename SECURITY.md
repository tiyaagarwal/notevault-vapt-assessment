# Security Policy

## Responsible use

`app/` in this repository is **intentionally vulnerable**, built specifically as the target for the assessment documented in [`report/VAPT_Report.md`](report/VAPT_Report.md). It contains real, working exploits (SQL injection, stored XSS, IDOR, plaintext password storage, a hardcoded JWT secret, and an unauthenticated debug endpoint) on purpose.

- Run `app/` only on `localhost` / an isolated environment you control.
- Never deploy `app/` to a shared host, a cloud VM with a public IP, or anywhere reachable from the internet.
- `fixed/` is the build to use as a reference for how each finding was remediated — it is not vulnerable by design, but it is a demo app and has not been hardened for production use beyond what the report covers.

## Reporting an issue with this repository itself

This repo has no production deployment and isn't used to protect real user data, so there's no formal disclosure program. If you spot a mistake in the report, the remediation code, or the methodology, please open a GitHub issue.

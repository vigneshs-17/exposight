# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities **privately** through GitHub private vulnerability reporting:

https://github.com/vigneshs-17/exposight/security/advisories/new

Do not open a public issue, pull request or discussion for a security problem.

Include what you found, the steps to reproduce it, and the impact you expect. Test only against
your own deployment or domains you own; do not scan or attack the hosted service or anyone
else's systems.

## Scope

- The Exposight application in this repository (API, dashboard, worker, scanner).
- The deployment configuration in this repository (`compose.prod.yml`, `Caddyfile`,
  `deploy/`).

## Supported versions

Only the latest commit on `main` receives security fixes.

## Automated security checks

Every push and pull request to `main`, and a weekly run, go through `.github/workflows/security.yml`:

- **bandit** on `src/`: any finding fails. An accepted finding is suppressed only on its own line
  with `# nosec B###` and a written reason (inline, or a `Bandit B### accepted:` comment just
  above); `tests/test_security_tooling.py` fails on a suppression without both.
- **pip-audit** on the installed runtime and dev dependencies: any known vulnerability fails.
- **gitleaks** over the full git history: any finding fails. False positives are listed one
  fingerprint at a time, each with a reason, in `.gitleaksignore`; no rule or path is disabled.
- **trivy** on the app image and the egress firewall image: fails on HIGH or CRITICAL
  vulnerabilities that have a fixed version. Unfixed ones are shown in the job log.

The CI `db-test` job also enforces a test coverage floor (line and branch, `fail_under` in
`pyproject.toml`). The current list of accepted findings and their reasons is in `STATUS.md`
("Phase G plan").


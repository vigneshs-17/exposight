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

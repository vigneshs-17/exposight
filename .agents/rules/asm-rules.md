# Exposight - Project Rules

## Project
- Exposight: Attack Surface Management tool. Discovers a domain's subdomains,
  live hosts, open ports, TLS and header issues, risk-scores them, and later
  monitors changes.
- Build in phases. Only build what the current prompt asks. Never start the
  next phase on your own.

## Stack
- v1: Python 3.11+, httpx, dnspython, argparse, pytest, ruff
- Later phases, only when a prompt says so: FastAPI, PostgreSQL, Next.js
- Never add a dependency without asking me first and explaining why

## Code quality
- Clear, simple, commented code a student can explain. No clever one-liners.
- Type hints and docstrings on every function; small functions, one job each
- Use logging, not print (except CLI output)
- Tests for all logic; tests never touch the network (use mocks and fixtures)
- Before saying "done": run pytest and ruff check . and show the results
- When adding or editing CI/Docker config, reuse the exact action and image
  versions already pinned in the repo. Never introduce an older version.

## Security (non-negotiable)
- Validate all user input
- Every network call has a timeout and error handling
- No secrets or API keys in code or git; use env vars, keep .env in .gitignore
- Only scan targets the user owns or has written permission to test
- Respect rate limits; never evade bot protection, WAFs or rate limiting
- Active scanning (ports, HTTP probing) only in steps that explicitly allow it

## Workflow
- Always produce an implementation plan first and wait for my approval
- If something is unclear, ask instead of guessing
- After each step, update docs/LEARNING_NOTES.md: plain-English explanation
  of new files plus 5 interview questions with answers
- End every task with: file tree, commands run, test results, open questions

## Architecture constraints (full text: docs/ARCHITECTURE_TARGET.md)
- Phase order is fixed: verify v2.1 -> v2.2 scan jobs -> v2.3 change
  detection -> v2.4 scheduling + alerts -> v3 SaaS. Never skip ahead,
  restart or redesign.
- Preserve the v1 scanner core and its safety controls (auth gate, SSRF
  guard, redirect scope, bounded scanning, banner safety, TLS behavior,
  untrusted-report validation, evidence-based scoring). Change them only
  with a demonstrated technical reason.
- Add the minimum architecture each phase needs, designed so later phases
  fit. No new infrastructure (Redis, Celery, Kafka, graph databases, cloud
  services) without a measurable limitation that justifies it.
- Never overwrite historical scan state. Keep the evidence and its source
  (crt.sh, DNS, redirect, ...) with every derived fact; never reduce
  evidence to an unexplained boolean.
- Risk scoring stays explainable: every score lists its contributors, is
  never called CVSS, and many weak findings never outweigh one strong,
  evidenced exposure.
- Long-running work never runs inside an API request; it goes through the
  job queue. Scheduled scans create ordinary jobs on the same queue.
- Create normalized tables only when a current feature needs them; JSONB
  reports are acceptable until then.
- Every new subsystem gets tests for its failure modes.
- Log with structured context where it exists: scan_id, job_id, domain_id,
  stage, duration, status, error.

## Reporting rules (mandatory)
- Never claim tests passed, lint is clean, Docker or migrations worked,
  files exist, or CI is green unless you ran the command in this session
  and show its unedited output.
- Label every item in a summary IMPLEMENTED, VERIFIED (proven by a command
  you ran, output shown) or PLANNED.
- List files from disk (git status), never from memory.
- Each step ends verified and committed before the next step starts.


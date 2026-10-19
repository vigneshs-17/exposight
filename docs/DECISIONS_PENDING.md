# Decisions pending (owner)

## P-1: Cert Spotter terms of use

**State of the code.** Discovery uses crt.sh first and falls back to Cert Spotter (`src/asm/discovery.py`). Cert Spotter requests are unauthenticated unless `CERTSPOTTER_API_KEY` is set; then each request carries `Authorization: Bearer <key>` (`tests/test_discovery.py::test_certspotter_api_key_sent_as_bearer_and_not_leaked`). `compose.prod.yml` already passes the variable to the worker. No code change is needed for any option below.

**The question.** SSLMate's Cert Spotter API has a free unauthenticated tier with a low rate limit. Whether that tier, or the free account tier, may be used by a hosted service that scans for other people (even an invite-only, non-commercial beta) depends on SSLMate's current terms, which have not been checked against this use.

**Options (owner decides):**

1. **Buy an API key.** Set `CERTSPOTTER_API_KEY` in the VM `.env` and recreate the worker. Clear terms and higher limits; costs money.
2. **Ask SSLMate for permission** to use the free tier for a non-commercial student project, and keep the written answer with the project records.
3. **Drop Cert Spotter as a source.** Discovery then depends on crt.sh only; when crt.sh is down, scans fail at the discovery stage instead of falling back. This needs a small code change (remove the fallback) with tests.

Until decided, production uses the unauthenticated tier as today.

## P-2: Pin images by digest and actions by commit SHA (independent check F6, deferred)

**State.** Container images are pinned by patch tag (`postgres:18.6-alpine`, `caddy:2.11.7-alpine`, `python:3.12.15-slim-trixie`, `alpine:3.24.2`) and GitHub Actions by major tag (`actions/checkout@v7`, ...). A tag can be re-pointed by its publisher; a digest or commit SHA cannot.

**Why deferred (2026-10-19, IC-1).** Python dependencies, the larger supply-chain gap, are now locked with hashes (F1). Digest/SHA pinning needs Dependabot configured to update digests so pins do not go stale, and it touches every workflow and compose file; it is a separate change.

**When to do it.** Before the beta opens beyond invited users, or together with the next Dependabot configuration change: pin images as `tag@sha256:...` and actions by full SHA with the tag in a comment.

## P-3: HSTS includeSubDomains / preload (independent check F12, deferred)

**State.** Caddy sends `Strict-Transport-Security: max-age=31536000` without `includeSubDomains` or `preload` (Caddyfile comment).

**Why deferred (2026-10-19, IC-1).** `includeSubDomains` makes browsers refuse plain HTTP on every subdomain of `exposight.dev` (for example the email subdomain `notify.exposight.dev`, see `docs/DNS_RECORDS.md`), and preload is hard to undo. It needs an inventory of every subdomain and confirmation that each serves HTTPS or nothing.

**When to do it.** After that inventory: add `includeSubDomains` first, wait a full `max-age`, and only then consider `preload`.

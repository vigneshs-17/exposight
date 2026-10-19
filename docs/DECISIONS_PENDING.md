# Decisions pending (owner)

## P-1: Cert Spotter terms of use

**State of the code.** Discovery uses crt.sh first and falls back to Cert Spotter (`src/asm/discovery.py`). Cert Spotter requests are unauthenticated unless `CERTSPOTTER_API_KEY` is set; then each request carries `Authorization: Bearer <key>` (`tests/test_discovery.py::test_certspotter_api_key_sent_as_bearer_and_not_leaked`). `compose.prod.yml` already passes the variable to the worker. No code change is needed for any option below.

**The question.** SSLMate's Cert Spotter API has a free unauthenticated tier with a low rate limit. Whether that tier, or the free account tier, may be used by a hosted service that scans for other people (even an invite-only, non-commercial beta) depends on SSLMate's current terms, which have not been checked against this use.

**Options (owner decides):**

1. **Buy an API key.** Set `CERTSPOTTER_API_KEY` in the VM `.env` and recreate the worker. Clear terms and higher limits; costs money.
2. **Ask SSLMate for permission** to use the free tier for a non-commercial student project, and keep the written answer with the project records.
3. **Drop Cert Spotter as a source.** Discovery then depends on crt.sh only; when crt.sh is down, scans fail at the discovery stage instead of falling back. This needs a small code change (remove the fallback) with tests.

Until decided, production uses the unauthenticated tier as today.

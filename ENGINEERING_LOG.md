# Engineering Log

## Entries

### Entry A: Operator-Verified Domain Transition on DNS Match
- **What happened:** Code review identified that an operator-verified domain could match a DNS TXT check and remain verified indefinitely without undergoing continuous background re-verification.
- **Root cause:** Verification state transition logic was duplicated across API endpoints and worker routines, leading to inconsistent state assignment (`verification_method`, `next_reverification_at`, `verification_expires_at`).
- **Fix:** Consolidated all verification state transitions into a single authoritative pure function: `apply_check_outcome(domain, outcome, now) -> bool` in `src/asm/verification.py`.
- **How to prevent it:** Maintain a single state transition function for all verification outcomes and enforce full broken-path integration tests covering state transitions end-to-end.

### Entry B: Fail-Open Default in Alert Trigger Rules
- **What happened:** `should_trigger_alerts` had a fail-open default argument `verified=True`.
- **Root cause:** Parameter defaulted to `True` during helper refactoring, allowing unverified domains to trigger alerts if callers omitted the argument.
- **Fix:** Removed default values and made `verified: bool` a required argument without default; removed deprecated `authorized` parameter.
- **How to prevent it:** Security gates must never use permissive or fail-open default arguments; required arguments ensure explicit verification checks.

### Entry C: Database Integration Tests Hung on Unreachable PostgreSQL
- **What happened:** On 2026-10-02, database integration tests hung indefinitely instead of failing fast when the test PostgreSQL service was unreachable (most likely Docker Desktop was not yet running; root cause not confirmed).
- **Root cause:** Database connection pool lacked an explicit client-side connection timeout, so a connection attempt could wait without a bound.
- **Fix:** Configured `connect_args={"connect_timeout": 5}` on the test SQLAlchemy engine in `tests/conftest.py`.
- **How to prevent it:** Explicitly configure bounded connect timeouts on database drivers in both test and application harnesses.

### Entry D: DNS Lookup Under Row Lock
- **What happened:** Known trade-off: DNS lookup runs while holding the domain database row lock (`SELECT ... FOR UPDATE`) during manual verification checks.
- **Root cause:** Atomic enforcement of the 30-second verification cooldown across distributed API processes required acquiring the row lock before updating `last_checked_at` and resolving DNS.
- **Fix:** Not fixed; trade-off accepted for current scale. DNS lookup timeout is short and bounded (about 5s), and cooldown prevents concurrent requests on the same domain. Revisit if measured contention occurs.
- **How to prevent it:** If database lock contention is measured under load, decouple cooldown checks and DNS resolution into a two-phase check.

### Entry E: Metadata Checker Exception on Pattern Match Risked Aborting Business Transactions
- **What happened:** The initial v3.3 plan proposed rejecting audit events if metadata contained values matching email or IP patterns, which would raise an exception inside the caller's database transaction.
- **Root cause:** Raising exceptions on pattern matching within audit metadata validation risked aborting critical business operations (e.g. background verification lapses or domain creation with unconventional names).
- **Fix:** Switched to strict per-action allowlists of allowed keys and types; free-text inputs (`org.created` name, operator override reason) are truncated to 500 characters and emails/IP addresses are masked as `[redacted]` instead of rejecting or raising errors.
- **How to prevent it:** Never fail an operational or background transaction due to secondary audit trail formatting; sanitize and mask rather than reject.

### Entry F: Model `index=True` on `AuditEvent.org_id` Caused Schema Drift Against Migration 0009
- **What happened:** `src/asm/db/models.py` had `index=True` on `AuditEvent.org_id`, but migration 0009 only created composite indexes `ix_audit_events_org_id_id` and `ix_audit_events_org_target`. `alembic check` would report schema drift.
- **Root cause:** Declaring `index=True` on a single column in SQLAlchemy creates an implicit single-column index (`ix_audit_events_org_id`) in model metadata that was never defined in the Alembic migration script.
- **Fix:** Removed `index=True` from `AuditEvent.org_id` in `src/asm/db/models.py`. The composite index `(org_id, id)` already covers queries filtering by `org_id`.
- **How to prevent it:** Always run `alembic check` to detect discrepancies between SQLAlchemy model definitions and migration scripts; avoid redundant single-column indexes when a composite index with that column as the leading prefix exists.

### Entry G: Missing Behavioural Tests for 7 of 15 Audit Actions
- **What happened:** Code review found that while route tables and schema maps listed all 15 audit actions, 7 actions lacked behavioural tests verifying that calling the API endpoint actually wrote an audit event to the database.
- **Root cause:** Initial tests asserted the existence of route-to-action mappings rather than exercising the actual HTTP endpoints against the database.
- **Fix:** Added dedicated DB integration tests for all untested actions (`membership.added`, `membership.role_changed`, `membership.removed`, `domain.alerts_changed`, `verification.checked`, `verification.rotated`, `scan.queued`), verifying exact action, actor type, actor user ID, target, and metadata. Added a test confirming idempotent replay of `POST /scans` writes no duplicate `scan.queued` event.
- **How to prevent it:** Test end-to-end event generation through API calls rather than asserting on static lookup tables.

### Entry H: Progress Line Mismatch from Retyped Builder Output
- **What happened:** Discrepancies between builder output text and test progress summaries previously occurred when test outputs or progress counts were manually retyped.
- **Root cause:** Manual retyping and copy-pasting across conversation turns led to drift and unverified claims.
- **Fix / Prevention:** The repo owner runs tests directly in his terminal before every commit, avoiding synthetic or misaligned test count reporting.

### Entry I: Plan Used Unscoped Write Paths for Domain Verification Endpoints
- **What happened:** The initial v3.4a implementation plan proposed writing to `/domains/{domain_id}/verification/check` and `/domains/{domain_id}/verification/rotate`.
- **Root cause:** Author referenced pre-v3.1b unscoped endpoints from memory instead of verifying the current tenant-isolated route signatures introduced in v3.1b.
- **Fix:** Caught in design review. Updated client fetch calls and plan to use the exact tenant-isolated write paths: `/orgs/{org_id}/domains/{domain_id}/verification/check` and `/orgs/{org_id}/domains/{domain_id}/verification/rotate`.
- **How to prevent it:** Always inspect the actual OpenAPI route table or router definitions before specifying client API URLs.

### Entry J: Synchronous `htmx:configRequest` vs Asynchronous `supabase.auth.getSession()`
- **What happened:** Attempting to inject the Bearer auth token into HTMX requests dynamically using `supabase.auth.getSession()` failed because HTMX's `htmx:configRequest` event is strictly synchronous.
- **Root cause:** Awaiting a promise inside `htmx:configRequest` does not pause the dispatch; the request was dispatched immediately without the `Authorization` header.
- **Fix:** Stored the current JWT access token in a module-level variable updated synchronously by Supabase's `onAuthStateChange` listener. The `htmx:configRequest` listener reads this variable synchronously.
- **How to prevent it:** Never attempt asynchronous fetching inside synchronous lifecycle hooks; maintain in-memory state driven by event listeners.

### Entry K: Invisible Check Result Due to HTMX Settle Reapplying Classes
- **What happened:** After clicking "Check now", the verification outcome was briefly rendered into `#verification-check-result` but immediately disappeared, leaving the container hidden. Found by reproducing in headless Chrome.
- **Root cause:** HTMX's settle phase runs ~20ms after swapping the HTML partial and reapplies the attributes from the response template. Because the template had `class="hidden"`, HTMX reapplied `class="hidden"` after `app.js` had removed it.
- **Fix:** Removed `class="hidden"` from the `#verification-check-result` template element in `templates/partials/domain_detail.html` (using `aria-live="polite"` instead), refreshed domain detail first, and populated the container after the swap finished.
- **How to prevent it:** Do not use CSS hiding classes on dynamically populated target containers within HTMX swapped fragments; rely on empty content and `aria-live="polite"` for live regions.

### Entry L: CSP Blocked HTMX Injected Indicator Inline Style
- **What happened:** HTMX automatically injected an inline `<style>` tag for `.htmx-indicator` into the document `<head>`, violating the strict `style-src 'self'` Content Security Policy.
- **Root cause:** HTMX injects default indicator styles unless explicitly disabled via configuration.
- **Fix:** Added `<meta name="htmx-config" content='{"includeIndicatorStyles": false, "allowEval": false, "allowScriptTags": false}'>` in `<head>` before the HTMX script tag in `base.html`, and set `window.htmx.config.allowEval = false` and `window.htmx.config.allowScriptTags = false` in `app.js`.
- **How to prevent it:** Check third-party script defaults against strict CSP directives; configure library behavior via meta tags before script execution.

### Entry M: Untested XSS Test Failed on Jinja Quote Escaping
- **What happened:** An XSS escaping test was written expecting `&lt;script&gt;alert("org-xss")&lt;/script&gt;`, but Jinja autoescape also escapes double quotes (`"` becomes `&#34;`), causing an assertion error. The test had been committed without being run locally.
- **Root cause:** The builder assumed Jinja only escapes angle brackets and failed to run the newly created test before reporting completion.
- **Fix:** Updated test assertions to check `assert "<script>" not in resp.text` and `assert "&lt;script&gt;" in resp.text`. Prevention: the builder runs every test it writes; the owner re-runs.
- **How to prevent it:** The builder must run every test it writes; the repo owner re-runs before every commit.

### Entry N: UI Reset on Supabase Token Refresh
- **What happened:** Whenever Supabase automatically refreshed the user's session token (`TOKEN_REFRESHED`), the auth state listener re-executed the entire initial sign-in logic, causing jarring UI reloads and disrupting active user interactions.
- **Root cause:** The `onAuthStateChange` callback treated all session events identically, calling `onUserAuthenticated()` on both `SIGNED_IN` and `TOKEN_REFRESHED`.
- **Fix:** Handled `TOKEN_REFRESHED` by only updating `currentAccessToken` in module memory and returning early without touching the DOM. Guarded `onUserAuthenticated()` with an `isAuthenticated` flag so it runs only once per sign-in.
- **How to prevent it:** Distinguish between token lifecycle events (`TOKEN_REFRESHED`) and user session state changes (`SIGNED_IN`, `SIGNED_OUT`).

### Entry O: Fix-First Count Cards Always Showed 0 on Real Scans
- **What happened:** In real scans, the summary cards for Critical, High, Medium, and Low findings displayed 0 even when findings of those tiers existed.
- **Root cause:** Test fixtures were built using invented dictionary keys (e.g., `{"CRITICAL": 1, "HIGH": 2}`), whereas the real producer `ScoreReport.to_dict()` in `scoring.py` serializes keys as `findings_critical`, `findings_high`, `hosts_high`, etc.
- **Fix:** Per-tier counts are now computed directly from all parsed findings in memory before applying the 50-row cap (`counts = dict.fromkeys(TIER_ORDER, 0)`), ignoring the producer's internal report counts mapping.
- **How to prevent it:** Build test fixtures from the real producer (`ScoreReport(...).to_dict()`) rather than handwriting mock dictionary payloads.

### Entry P: Scans List Showed "No Changes" for Scans with Real Changes
- **What happened:** The domain scans list showed "No changes" for completed scans that actually had detected attack surface changes.
- **Root cause:** The initial UI parser expected a `"total"` key inside `scan_runs.change_detection["counts"]`. The worker (`worker.py`) writes counts as a dictionary of five individual tiers (`{"critical": ..., "high": ..., "medium": ..., "low": ..., "info": ...}`) without any `"total"` key.
- **Fix:** Updated `format_change_summary` to sum the counts across all five tiers (`critical`, `high`, `medium`, `low`, `info`). If the sum is zero, it renders "No changes"; otherwise, it lists non-zero tiers (e.g. `1 critical, 2 info`).
- **How to prevent it:** Use contract test fixtures derived directly from worker output rather than synthetic test dictionaries.

### Entry Q: Finished Scans Re-Fetched on Every Click
- **What happened:** Clicking anywhere inside a completed or failed scan detail panel triggered an unwanted HTTP GET request back to the server.
- **Root cause:** `hx-get` was placed unconditionally on the `<section id="scan-detail-container">` container. When the scan finished, `hx-trigger="every 3s"` was omitted, causing HTMX to fall back to its default element trigger (`click`).
- **Fix:** Emitted all HTMX polling attributes (`hx-get`, `hx-target="this"`, `hx-swap="outerHTML"`, `hx-trigger="every 3s"`) together inside `{% if should_poll %}`. Finished scans omit `hx-get` entirely.
- **How to prevent it:** In HTMX templates, never emit `hx-get` without an explicit trigger if the element is not intended to be clickable.

### Entry R: CSP Blocked Inline Style Attributes
- **What happened:** The strict Content Security Policy (`style-src 'self'`) blocked 8 inline `style="..."` attributes in the dashboard partials.
- **Root cause:** Quick inline styling was added during development without considering that `style-src 'self'` forbids inline styles.
- **Fix:** Replaced all inline style attributes with semantic CSS classes in `src/asm/static/css/app.css` (`.section-header`, `.section-header-first`, `.stage-card-error`, `.finding-why`, `.findings-more`, `.run-scan-hint`, `.scan-meta`). Added `test_templates_have_no_csp_blocked_inline_code` to catch inline styles during test runs.
- **How to prevent it:** Enforce CSP compliance in automated test suites with a template AST or regex guard test.

### Entry S: Two Broken Test Cases in v3.4b Suite
- **What happened:** Two newly added tests failed during implementation: one failed on database uniqueness constraint, and one failed on ordering assertion.
- **Root cause:**
  1. Setting up two running scans for the same domain violated the partial unique index `uq_scan_runs_active_domain` (which permits at most one queued or running scan per domain).
  2. Capping test generated hostnames like `host1.example.com`, `host2.example.com` ... `host10.example.com`; alphabetical string sorting placed `host10` before `host2`, breaking the expected index sequence.
- **Fix:**
  1. Used a separate domain fixture for the stale active scan test case.
  2. Zero-padded test hostnames (`host00`, `host01`, ..., `host59`) so alphabetical ordering matches integer index ordering.
- **How to prevent it:** Respect domain database constraints in test setup; use zero-padding when string ordering must align with numeric sequence.

### Entry T: 401 Token Refresh Nested Duplicate Polling Containers
- **What happened:** Code review (not a user report) found that if an access token expired during background polling, the 401 refresh-and-retry would re-render the scan detail container nested inside the existing one.
- **Root cause:** The scan detail poller uses `hx-target="this"` and `hx-swap="outerHTML"`. The generic 401 retry handler in `app.js` executed `window.htmx.ajax()` with default swap behavior (`innerHTML`), inserting the outer container inside itself.
- **Fix:** Updated `app.js` 401 response error handler to inspect the source element's `hx-swap` attribute (`evt.detail.elt.getAttribute('hx-swap')`) and preserve it on retry (`retryContext.swap = swapStyle`).
- **How to prevent it:** When replaying requests in HTMX error handlers, preserve the original request's swap and target context.

### Entry U: WCAG AA Color Contrast Failure on Tungsten Warning Text
- **What happened:** Accessibility check revealed that `--color-tungsten-warning: #c25700` on `--color-tungsten-bg: #fff8f0` yielded a contrast ratio of 4.28:1, failing WCAG AA requirements ($\ge 4.5:1$).
- **Root cause:** The color was selected visually without calculating the WCAG 2.x relative-luminance contrast ratio against the light background.
- **Fix:** Introduced `--color-tungsten-text: #a84b00`, which achieves 5.43:1 contrast against `#fff8f0` (exceeding WCAG AA 4.5:1), retaining `#c25700` for borders and non-text accents only.
- **How to prevent it:** Calculate and verify relative-luminance contrast ratios for all foreground text tokens against their respective backgrounds during design token creation.

### Entry V: Builder's Implementation Report Described Pre-Fix Code and Claimed Full Pass Without Output
- **What happened:** An earlier implementation report described outdated banner text, unconditional `hx-get`, and stale contrast numbers (6.81/6.25), claiming full-suite pass without pasting raw execution output.
- **Root cause:** The builder summarized initial planning intentions and pre-fix code from memory instead of inspecting the final modified files on disk and pasting verified terminal output.
- **Fix:** Verified on disk: Signal Crimson `#a81a2e` has 7.36:1 contrast on `#ffffff` and 6.77:1 on `#fdf3f4`; Tungsten text `#a84b00` has 5.43:1 on `#fff8f0`. All documentation is strictly sourced from disk.
- **How to prevent it:** Documentation must be written from code on disk; reports must include verbatim, raw command output.

### Entry W: Owner Full Test Run Encountered 139 Setup ERRORs
- **What happened:** The owner's first full run failed at import (ModuleNotFoundError: sqlalchemy); the second run produced 139 ERRORs.
- **Root cause:**
  1. On the first run, pytest was invoked with the host Python instead of the virtual environment (`.venv`), missing installed dependencies (`ModuleNotFoundError: sqlalchemy`).
  2. On the second run, the throwaway PostgreSQL test container (`asm-test-db`) had stopped, causing connection timeouts on port `5433`. Note that in pytest, `ERROR` denotes test fixture or setup failure, whereas `FAILED` denotes test assertion failure.
- **Fix:** Activated `.venv`, ensured `TEST_DATABASE_URL` was exported, and started `asm-test-db` container (`docker start asm-test-db`). All 430 tests then passed cleanly.
- **How to prevent it:** Always run tests using `.venv\Scripts\pytest`, verify that `TEST_DATABASE_URL` is set, and confirm the test database container is running with `docker ps` before running integration tests.

### Entry X: Audit Metadata Rendered with Jinja tojson Bypassed Autoescape
- **What happened:** Plan review: the plan rendered audit metadata with Jinja's `tojson` and claimed autoescape protected it. `tojson` returns `Markup` (already marked safe), so autoescape skips it; it was safe only because `tojson` encodes `<` as `\u003c`.
- **Root cause:** Jinja2's `tojson` filter marks its return value as HTML-safe (`Markup`), causing the autoescape engine to bypass it entirely.
- **Fix:** Serialized metadata in Python via `json.dumps(...)` to a plain `str` passed in template context, rendered with `{{ metadata_json }}`; updated `test_templates_have_no_csp_blocked_inline_code` to ban `tojson` and `|safe` in templates.
- **How to prevent it:** Never use `tojson` or `|safe` for untrusted JSON in templates; serialize to a plain string in Python and let Jinja autoescape it; enforce with static template guard tests.

### Entry Y: Schedule Form Entirely Disabled on Unverified Domains
- **What happened:** Plan review: the plan disabled the whole schedule form on unverified domains, but the API allows `interval_hours=null` there. Admins could not turn scans off.
- **Root cause:** The plan conflated disallowing active automated scan cadences with preventing schedule changes altogether.
- **Fix:** Keep "Off" (`value=""`) enabled while disabling all non-null cadence presets (`6`, `12`, `24`, `168`, `720`) on unverified domains, allowing admins to turn off automated scans.
- **How to prevent it:** Design UI state transitions to always permit the fail-safe action (turning off automated background operations) even when prerequisites for enabling them are unmet.

### Entry Z: Alerts Update API Inflexibility on Unverified Domains
- **What happened:** The alerts API returned 422 for every update on unverified domains, so after a lapse alerts could not be disabled and recipients could not be removed.
- **Root cause:** The API endpoint `PUT /orgs/{org_id}/domains/{domain_id}/alerts` rejected all requests with 422 if `domain.verification_status != "verified"`, regardless of whether the user was attempting to disable alerts or enable them.
- **Fix:** (Owner Decision A) Modified the endpoint in `src/asm/api/routes.py` to allow `alerts_enabled=false` on unverified domains, allowing alerts to be turned off and recipients cleared; enabling alerts (`alerts_enabled=true`) still returns 422.
- **How to prevent it:** Design authorization/validation gates to allow disabling or revoking features regardless of entity verification status.

### Entry AA: Raw SMTP Exception in Last Error Column Exposed Recipient Emails to Viewers
- **What happened:** Code review: alert history showed `last_error` to viewers. `last_error` stores raw SMTP exception text, which can contain recipient emails, undoing the viewer redaction.
- **Root cause:** The template rendered `last_error` unconditionally for all roles, overlooking that SMTP client exceptions often include the target email address in their error messages.
- **Fix:** Restricted the "Last error" column (`<th>` and `<td>`) in `alert_notifications.html` to `admin` and `owner` roles only; extended `test_ui_viewer_privacy_no_email_strings_anywhere` to verify that `last_error` strings containing recipient emails are never exposed to viewers.
- **How to prevent it:** Treat diagnostic and exception strings as sensitive when they may reflect PII; apply the same role-based access restrictions to error detail columns as to the raw PII fields themselves.

### Entry AB: Cross-Tenant Test Did Not Exercise Parameter Swap
- **What happened:** Code review: the cross-tenant test only covered a non-member (stopped by the role check), never a member swapping in another org's `domain_id` (the `get_domain_for_org` choke point). A test named `...offset_paging` asserted no paging.
- **Root cause:** The test suite verified multi-tenancy at the outermost authorization layer (`require_org_role`) but missed asserting the second defense layer (`get_domain_for_org`). Furthermore, the offset paging test verified only XSS without exercising real pagination across multiple pages.
- **Fix:** Added `test_ui_alert_notifications_param_swap_404` to explicitly test swapping in another org's `domain_id` by an authenticated organization owner, and added `test_ui_alert_notifications_paging_55_rows` to assert real multi-page offset pagination (50 rows on page 1 with Next button, 5 rows on page 2 with Previous button).
- **How to prevent it:** Test each security layer separately (outer membership check vs inner resource-scoping choke point); ensure test names strictly match their assertions.

### Entry AC: Unlabelled Email Input and Unstyled Warning Notices
- **What happened:** Owner's live check (Chrome DevTools Issues panel) reported "No label associated with a form field" and a missing autocomplete attribute on the add-email input; the unverified warning notices rendered as plain boxes.
- **Root cause:** The input had only a placeholder (not an accessible name), and the templates used `.alert-warning`, which had no CSS rule.
- **Fix:** Added a `<label for>` and `autocomplete="email"`, added the `.alert-warning` rule, and added `test_templates_form_fields_have_labels`.
- **How to prevent it:** Run a live browser check every phase; the label test now guards every template.

### Entry AD: Plan Review — Missing `get_db` Dependency Override in In-Process Server
- **What happened:** The initial v3.4d plan did not override `get_db`, so the in-process server would have used `DATABASE_URL` (the dev DB) instead of the test database.
- **Root cause:** The plan assumed that setting environment variables or using the caller's test session was sufficient, overlooking that incoming HTTP requests to the live Uvicorn thread invoke FastAPI's dependency injection system, which defaults to `get_db` using the engine created from `DATABASE_URL`.
- **Fix:** Added a `get_db` dependency override bound to `browser_session_factory` (which uses the validated `*_test` engine from the `db_engine` fixture), providing a new database session per request and cleaning tables with `clean_db`.
- **How to prevent it:** In integration test harnesses using a live server, explicitly review every database dependency provider to ensure all execution paths bind to the test engine.

### Entry AE: Plan Review — Auth Override Ignored Tokens Preventing Token Bug Detection
- **What happened:** The initial plan's auth override returned a hardcoded user regardless of the incoming token, meaning tests could not catch token-injection or header-propagation bugs.
- **Root cause:** The planned test dependency mock bypassed token inspection entirely to simplify test authentication.
- **Fix:** Updated the override to parse the `Authorization` header, extract the Bearer token, validate it against `TOKEN_REGISTRY`, and look up the corresponding user in the test database session. Unregistered tokens return HTTP 401.
- **How to prevent it:** Test authentication overrides must validate synthetic tokens against an explicit registry rather than returning unconditional mock objects.

### Entry AF: Code Review — "Check now" Browser Test Performed Real DNS Lookup
- **What happened:** The "Check now" browser test performed a real DNS lookup (server-side, invisible to Playwright's request guard).
- **Root cause:** Playwright request interception (`page.route`) operates purely in the browser client context; server-side DNS queries dispatched by FastAPI endpoints via `dnspython` bypass the browser network layer entirely.
- **Fix:** Added an autouse fixture (`forbid_real_dns`) in `tests/browser/conftest.py` patching `asm.api.routes.check_dns_txt_verification` to raise `AssertionError("real DNS lookup attempted in a browser test")`. In `test_browser_check_now_result_stays_visible`, overridden with a mock returning `(VerificationOutcome.ABSENT, "No TXT records found at _asm-verify.check.example.com")`, asserting it was called exactly once.
- **How to prevent it:** In end-to-end browser test suites, guard all server-side external network boundaries with autouse fixtures that fail fast if real network calls are attempted.

### Entry AG: Code Review — Console Filter Swallowed 5xx and 404 Responses
- **What happened:** The initial console message filter swallowed failed HTTP resource and fragment loads, including 5xx server errors and 404 errors.
- **Root cause:** The console error handler used an overly broad filter that ignored all messages mentioning failed fetches or non-200 status codes.
- **Fix:** Narrowed the console filter to ignore only `"favicon.ico"`, `"status of 401"`, `"status of 422"`, `"Response Status Error Code 401"`, and `"Response Status Error Code 422"`. Added an active `page.on("response")` listener that fails the test if any request to the live server returns status $\ge 500$ or a non-favicon 404.
- **How to prevent it:** Narrow error filters to explicit expected codes; pair console monitoring with affirmative response status listeners on application server routes.

### Entry AH: Vacuous 401-Retry Test and Silent Mutation Check Failures
- **What happened:** The 401-retry test was vacuous twice: first it asserted nothing about the retry; then its count ran before htmx swapped the response into the DOM. Proven with a mutation check (commented-out retryContext.swap -> FAILED, assert 2 == 1). An earlier mutation attempt silently tested unmodified code because the edit was not saved, and another was SKIPPED because TEST_DATABASE_URL was unset.
- **Root cause:**
  1. The test counted containers right after the 200 HTTP response arrived rather than after HTMX completed swapping the DOM.
  2. Testing mutations without saving files or verifying test selection resulted in false passes and skipped executions.
- **Fix:** Wrapped the 401 trigger in `page.expect_response`, waited first for `expect(page.locator(".status-badge:has-text('Status: Succeeded')")).to_be_visible()` to guarantee DOM swap completion, and then executed immediate non-waiting assertions verifying container counts (`count() == 1`, nested `count() == 0`) and absence of `hx-trigger` and `hx-get` attributes.
- **How to prevent it:** See a test fail before trusting it; confirm the mutation with git diff; read the summary line for "skipped".

### Entry AI: CI Red for 4 Commits (v3.4a-v3.4d) Unnoticed Due to Missing DATABASE_URL in Lint Job
- **What happened:** CI red for 4 commits (v3.4a-v3.4d) unnoticed: the test needed DATABASE_URL, present locally via .env but absent in the lint job; CI status was reported from an unreliable page summary instead of the job log.
- **Root cause:** In commit 682df8e (v3.4a), `test_ui_unauthenticated_returns_401` was added to `tests/test_dashboard_ui.py`. The tested `/ui/*` endpoints resolve `current_user: CurrentUser` (`get_current_user`), which depends on `db: DbSession` (`get_db`). Resolving `get_db` invokes `get_settings().database_url`. Because `database_url` is a required setting without default, `get_settings()` raises `RuntimeError("DATABASE_URL environment variable is required but not set.")` if neither `DATABASE_URL` nor `.env` exists. In CI's `Lint & Test` job, no database service or `DATABASE_URL` is configured, so `test_ui_unauthenticated_returns_401` failed on every push across runs #29-#32. Locally, the test passed because `.env` supplied a `DATABASE_URL`.
- **Fix:** Patched a dummy `DATABASE_URL` (`postgresql+psycopg://dummy:dummy@127.0.0.1:1/dummy_test`, using port 1 so it can never reach a real local Postgres) within `test_ui_unauthenticated_returns_401` via `unittest.mock.patch.dict(os.environ, ...)`. SQLAlchemy sessions are lazy, and because unauthenticated requests fail fast when extracting the missing Bearer header in `get_current_user`, no database connection is ever attempted. Caches cleared before and after so the dummy URL cannot leak into later tests.
- **How to prevent it:** Confirm CI from the job log or a screenshot before closing a phase.

### Entry AJ: Landing Page Copy Accuracy, Test Strength, and Mutation Check
- **What happened:** Code review of the v3.5 landing page caught five copy and test rigor issues before release:
  1. An invented claim that change detection caught "revoked certificates" when `changes.py` actually detects `certificate problems (expired, untrusted, self-signed, hostname mismatch)`.
  2. Hero node 02 described as "Dual-stack HTTP" when `prober.py` inspects `HTTP/HTTPS on 80/443`.
  3. Probing source label cited `headers_inspect.py` instead of `prober.py, scan_common.py`.
  4. Scoring text made an unsupported "by host impact" claim; the real order is severity tier, score impact, then host.
  5. The DNS TXT verification example in the Trust card was hard-coded instead of dynamically computed via `get_expected_record_value`.
  6. Reduced-motion and no-JS tests spawned isolated Playwright browsers without attaching the global fixture listeners and teardown assertions (CSP violations, console errors, page errors, server response codes, and unexpected network egress).
  7. The initial GSAP browser test asserted opacity on `#hero h1` without verifying that ScrollTrigger instances actually existed for below-fold sections.
- **Root cause:**
  - Copy was composed from memory rather than strictly verifying underlying scanner implementation files (`changes.py`, `prober.py`, `verification.py`).
  - Browser tests for alternative contexts (`reduced_motion="reduce"`, `java_script_enabled=False`) used nested `sync_playwright()` blocks to bypass standard fixtures, inadvertently losing the teardown assertions.
- **Fix:**
  - Corrected all copy strings in `src/asm/templates/landing.html`.
  - Injected `txt_example=get_expected_record_value("<your-token>")` and `txt_label="_asm-verify.example.com"` into `get_landing_page` (`src/asm/api/routes_ui.py`) and rendered it via normal template autoescaping.
  - Refactored `page` in `tests/browser/conftest.py` into a factory fixture `make_page(**context_kwargs)` that enforces all listeners and teardown assertions uniformly.
  - Asserted `window.ScrollTrigger.getAll().length > 0` directly on page load in `test_browser_landing_page_loads_and_gsap_runs`.
  - Added `test_browser_landing_all_sections_reveal_on_scroll` asserting all `ANIMATED` elements transition to opacity 1 when scrolled into view.
  - Verified with a mutation check: mutating CTA trigger start to `"top -500%"` failed `test_browser_landing_all_sections_reveal_on_scroll` with `TimeoutError: Page.wait_for_function: Timeout 5000ms exceeded`; restoring `landing.js` returned the suite to passing.
- **How to prevent it:** Quote implementation sources directly for marketing copy; run all browser variations through the central fixture factory with active teardown guards; verify new scroll tests with deliberate mutation checks.

### Entry AK: v3.6b A-1 — Production Mode Was a Comment, Not a Guard
- **What happened:** `.env.production.example` set `ENVIRONMENT=production`, but no code read it. A production container could start against a `_test` or localhost database, or with placeholder Supabase values. `/docs`, `/redoc` and `/openapi.json` were public in every environment. JSON API responses had no `X-Content-Type-Options` or `Cache-Control`. `build_csp_header` copied a malformed `SUPABASE_URL` into `connect-src` unchanged.
- **Root cause:** Production safety was documented as "planned for v3.6b" and the security-header middleware only matched HTML paths (`/`, `/app`, `/ui`, `/static`).
- **Fix:** `asm.config.get_environment()` (unknown values fail), `find_production_config_problems()` and `enforce_production_config()`, called from the API lifespan and the worker entry point. Messages name the setting, never the value. FastAPI docs URLs are `None` in production. The middleware adds `nosniff` and `no-store` to every non-HTML response. `supabase_csp_origin()` accepts only `https://` plus a plain hostname and optional port; anything else leaves `connect-src 'self'`.
- **How to prevent it:** A setting in an example env file must have a test proving the code reads it. 34 tests in `tests/test_production_mode.py`.

### Entry AL: v3.6b A-1 — Auth Echoed Token Header Values and Failed Hard on JWKS Outages
- **What happened:** `verify_access_token` built error text from the unverified token header (`Unsupported signing algorithm: {alg}`, `Unknown key ID '{kid}'`). `get_current_user` copied that text into `detail` and inside the quoted `error_description` of `WWW-Authenticate`, so an attacker chose part of a response header. In `JWKSManager`, an expired cache plus a failed fetch returned 503 although valid keys were cached; with no cached keys, every request re-fetched (the throttle needed `self._keys`); a malformed JWKS document raised an uncaught `PyJWKSetError` (500).
- **Root cause:** One exception string served both logs and clients; JWKS failure handling covered only the network error path.
- **Fix:** `InvalidTokenError.public_message` holds a fixed client-safe string; header values go to logs via `%r` only. `JWKSManager` serves the cached key during an outage, backs off after failures (doubling from `min_refresh_interval`, cap 300 s, applied with or without cached keys), resets on success, and maps parse errors to `JWKSUnavailableError` (503).
- **How to prevent it:** Never interpolate untrusted input into a response header; keep log text and client text as separate fields.

### Entry AM: v3.6b A-1 — SMTP Credentials Could Be Sent in Clear Text
- **What happened:** `send_smtp_email` called `server.login()` whenever a username and password were set, even with `use_starttls=False`. The worker default for `SMTP_STARTTLS` is `false`. There was no implicit-TLS (port 465) option.
- **Root cause:** TLS and authentication were independent switches.
- **Fix:** Credentials without STARTTLS or SMTPS raise `SMTPConfigError` before any connection; enabling both modes is also an error. New `SMTP_SSL` setting uses `smtplib.SMTP_SSL` with `ssl.create_default_context()`. Wired into both compose files and both env examples.
- **How to prevent it:** Make the unsafe combination impossible in code, not only in the example config. 8 tests in `tests/test_smtp_delivery.py`.

### Entry AN: v3.6b A-1 — Audit Gaps, Duplicate-Domain 500, and `move-domain` Carrying Old Trust
- **What happened:** `domain.alerts_changed` metadata did not show recipient changes, so an admin could redirect alert emails without a trace. Two concurrent `POST /domains` for the same name could both pass the existence check; the loser hit `uq_domains_org_id_name` and returned 500. `admin move-domain` kept the source org's verification, alert recipients and schedule, and ran even while a scan was queued or running.
- **Root cause:** Audit metadata described only flags; the domain create relied on a check-then-insert; the move copied the row instead of treating it as a new owner.
- **Fix:** Metadata adds `old_recipient_count`, `new_recipient_count`, `recipients_changed` (case- and order-insensitive; no addresses). `create_domain` maps the unique-constraint `IntegrityError` to 409 (other integrity errors still raise). `move_domain` locks the domain row, refuses while a `queued`/`running` scan exists, resets verification to `pending` with a new token, clears operator override fields, disables alerts, empties recipients, turns the schedule off, and records `verification_reset`/`alerts_reset`/`schedule_reset` in both `domain.moved` events.
- **Test change:** `test_api_domain_alerts_changed_audit_event` asserts the exact metadata dict; its expected dict gained the three new keys (stricter, not weakened).
- **How to prevent it:** Every audit action that changes who receives data must record that it changed. 8 tests in `tests/test_domain_hardening_db.py`.

### Entry AO: v3.6b A-1 — Revert Proof Hung on the Worker Startup Test
- **What happened:** During the revert proof, disabling the production guard made `test_worker_startup_refuses_test_database_in_production` start the real worker loop, so the run hung instead of failing. The pytest process was stopped manually; the proof script restored `config.py` byte-identical.
- **Root cause:** The test relied on the guard to stop `main()` before the infinite worker loop.
- **Fix:** The test replaces `ASMWorker` with a function that raises, so a missing guard fails in 0.23 s with `AssertionError: worker started: production guard did not run first`.
- **How to prevent it:** A test for a guard in front of a long-running loop must stub the loop.

---

## Architectural Decisions

### 1. DNS TXT at Dedicated `_asm-verify` Label
- **Decision:** Verification tokens are published as a DNS TXT record at `_asm-verify.<domain>` with value `asm-verify=<token>`.
- **Rejected alternatives:** Zone apex (`@`) TXT record. (Recorded in `docs/LEARNING_NOTES.md`: rejected due to apex congestion with SPF, DMARC, and third-party SaaS verification tokens, risking DNS UDP response sizes exceeding 512 bytes / EDNS limits, and preventing sub-zone delegation).

### 2. Two Definite Misses Before Lapse
- **Decision:** A domain transitions from `verified` to `lapsed` only after 2 consecutive definite misses (`ABSENT`), with a 1-hour fast retry scheduled after the first miss.
- **Rejected alternatives:** not recorded.

### 3. UNKNOWN Never Counts Toward Lapses
- **Decision:** Transient network failures, resolver timeouts, and `SERVFAIL` yield `UNKNOWN` and never increment `consecutive_misses` or cause status lapses.
- **Rejected alternatives:** not recorded.

### 4. Operator Override Expiring After 1-90 Days
- **Decision:** Operator break-glass overrides require a non-empty reason and mandatory expiration between 1 and 90 days (default 30 days).
- **Rejected alternatives:** not recorded.

### 5. Database Trigger vs Code-Only Convention for Append-Only
- **Decision:** Enforced append-only audit log integrity via a PostgreSQL trigger (`trg_audit_events_append_only`) that raises an exception on `UPDATE` or `DELETE`.
- **Rejected alternatives:** Code-only repository convention (e.g. omitting update/delete methods in ORM). Rejected because code-only enforcement offers no protection against direct SQL execution, database migrations, or developer mistakes; anyone with DB access could quietly alter history. Note: It is append-only against the application; the table owner can disable the trigger.

### 6. Two `domain.moved` Events (Source and Target Organizations)
- **Decision:** When a domain is transferred between organizations via operator command (`asm admin move-domain`), two distinct audit events are recorded in the same transaction: one under the source organization (`target_type="domain"`, `metadata={"to_org_id": ...}`) and one under the target organization (`target_type="domain"`, `metadata={"from_org_id": ...}`).
- **Rejected alternatives:** Single event under the source organization or target organization only. Rejected because tenant audit queries are strictly filtered by `org_id`; a single event would leave one organization with an incomplete audit trail for asset transfers.

### 7. Plain Composite Indexes: `(org_id, id)` and `(org_id, target_type, target_id)`
- **Decision:** Created composite B-tree indexes `ix_audit_events_org_id_id` on `(org_id, id)` and `ix_audit_events_org_target` on `(org_id, target_type, target_id)`. PostgreSQL scans this index backwards for ORDER BY id DESC, so no DESC index is needed.
- **Rejected alternatives:** Standalone single-column indexes on `org_id`, `target_id`, or `created_at`. Rejected because tenant queries always require `org_id` filtering first; composite indexes with `org_id` as the leading column provide optimal index-only/index-scan performance and support cursor pagination (`WHERE org_id = :org_id AND id < :before_id ORDER BY id DESC`).

### 8. Option A (FastAPI + Jinja2 + HTMX) over Next.js
- **Decision:** Built the v3.4a dashboard as a server-rendered application using FastAPI, Jinja2 templates, and HTMX, with client-side Supabase JS.
- **Rejected alternatives:** Next.js / React SPA. Rejected because a separate Node.js/TypeScript frontend introduces a second programming language, a second package manager (npm), a complex build step, and a second deployment target, increasing operational complexity and attack surface for a lean security tool.

### 9. Bearer Header vs Cookie Session
- **Decision:** Authenticated browser requests to both the JSON API and HTMX `/ui/*` endpoints using `Authorization: Bearer <token>` in the header, passed synchronously.
- **Rejected alternatives:** Session cookies (`Set-Cookie`). Rejected because cookies require CSRF protection tokens, cookie parsing middleware, and dual-auth paths for API and browser clients. Bearer tokens in headers are inherently immune to CSRF. The trade-off is readability via XSS, which is mitigated by strict CSP (`default-src 'self'`, no inline scripts or styles), Jinja autoescaping, and `textContent`-only rendering.

### 10. HTMX 2.x over HTMX 4.0
- **Decision:** Vendored stable HTMX 2.0.11.
- **Rejected alternatives:** HTMX 4.0 pre-release / majors. Rejected due to breaking API changes, unstable ecosystem support, and lack of proven production hardening.

### 11. sessionStorage over localStorage
- **Decision:** Configured Supabase Auth client to persist session tokens in `sessionStorage`.
- **Rejected alternatives:** `localStorage`. Rejected because `localStorage` persists indefinitely across browser restarts and all tabs, whereas `sessionStorage` is isolated to the tab and cleared upon window close, reducing the window of token exposure.

### 12. HTMX Polling with 15-Minute Cap and Self-Swapping Container
- **Decision:** Implemented live scan status updates using HTMX polling (`hx-trigger="every 3s"`, `hx-target="this"`, `hx-swap="outerHTML"`) capped at 15 minutes from scan creation. When 15 minutes elapse, polling ceases and renders a stale warning banner with a manual Refresh button.
- **Rejected alternatives:** WebSockets or Server-Sent Events (SSE). Rejected because WebSockets/SSE introduce persistent connection state, require custom connection management and reconnect logic, complicate load balancing, and demand a dedicated asynchronous notification channel.

### 13. Counts Derived from Findings Rather Than Trusting Stored Report Counts
- **Decision:** Derived summary count cards (Critical, High, Medium, Low) by counting parsed finding objects directly in presentation logic before applying the 50-item display cap.
- **Rejected alternatives:** Reading `report["counts"]` directly. Rejected because `scoring.py` serializes internal keys (`findings_critical`, `hosts_high`) that do not match UI tier keys, and relying on pre-computed counts can cause discrepancies with the findings table when filtering or formatting.

### 14. Attacker-Influenced Evidence Rendered as Escaped Text, Never Links
- **Decision:** Rendered finding evidence, why-it-matters strings, and change assets strictly as HTML-escaped text inside `<code>` and standard elements, never converting URLs or endpoints into active clickable links (`<a href>`).
- **Rejected alternatives:** Automatically hyperlinking evidence strings (e.g. rendering discovered URLs or endpoints as clickable links). Rejected because evidence strings are attacker-influenced (drawn from certificate transparency logs, web banners, and HTTP responses); rendering active links creates stored XSS vectors (e.g. `javascript:...` URIs or data URIs) and phishing risks.

### 15. Shared Audit Query Builder (`audit.build_audit_query`)
- **Decision:** Extracted a single shared query builder function `build_audit_query` in `src/asm/audit.py` used by both the JSON API (`GET /orgs/{org_id}/audit-events`) and the UI fragment (`GET /ui/orgs/{org_id}/audit-events`).
- **Rejected alternatives:** Separate query implementations in `routes.py` and `routes_ui.py`. Rejected because maintaining duplicate query filtering, joins, cursor logic, and sort ordering across two endpoints risks behavioral and security drift.

### 16. Viewer Email Redaction in UI Layer Only
- **Decision:** Redacted alert recipient emails and raw SMTP errors in the UI templates and routes for users with the `viewer` role, while leaving the existing JSON API responses unchanged.
- **Rejected alternatives:** Modifying existing JSON API schemas (`DomainRead`, alert notifications list) to redact emails. Rejected because modifying existing API contracts was explicitly out of scope for v3.4c (recorded in `IDEAS.md` for a future API revision).

### 17. Audit Log Keyset Paging Replaces Full Fragment
- **Decision:** "Older events" and "Newest" reload the whole audit log fragment into `#main-content-area` via `htmx.ajax` (`loadAuditLog`) instead of appending rows to the table.
- **Rejected alternatives:** Appending `<tr>` rows dynamically via JavaScript or client-side DOM parsing. Rejected because full fragment swapping requires zero client-side HTML parsing, keeps state purely server-driven, and preserves strict CSP invariants.

### 18. In-Process Uvicorn Thread for Browser Tests
- **Decision:** Run the live web server during browser tests inside a daemon thread (`threading.Thread(target=server.run, daemon=True)`) hosting Uvicorn on an ephemeral port (`port=0`), sharing the FastAPI `app` object in-process.
- **Rejected alternatives:** Subprocess invocation (`subprocess.Popen(["uvicorn", ...])`) or adding a `TEST_MODE` configuration flag in production source code. Rejected because subprocesses run in separate memory spaces where FastAPI's `app.dependency_overrides` cannot be manipulated per test, which would force introducing test-specific bypass flags or backdoors into `src/`. In-process threads allow direct dependency injection overrides with zero test hooks in production code.

### 19. Synthetic Supabase Auth Mock via Playwright Route Interception
- **Decision:** Intercept Supabase Auth endpoints (`https://auth.test-asm.local/auth/v1/token`) using Playwright's `page.route` to return synthetic JWT-shaped HS256 tokens and track tokens in memory registries.
- **Rejected alternatives:** Running an external Supabase emulator container, using real Supabase credentials, or creating a backdoor `/api/test-login` route. Rejected because external services add network instability, slow down testing, and require external credentials; backdoor routes in application source introduce severe security vulnerabilities. Synthetic tokens shaped like JWTs satisfy client-side parsing while being rejected by production JWT verifiers (proven by `test_browser_production_app_rejects_fake_token_401`).

### 20. Separate Browser Test Marker and CI Workflow Job
- **Decision:** Mark all browser tests with `@pytest.mark.browser`, deselect them by default locally in `pyproject.toml` (`-m 'not integration and not browser'`), and execute them in a dedicated CI job (`browser-test`) in `.github/workflows/ci.yml`.
- **Rejected alternatives:** Running browser tests as part of the default `pytest` invocation. Rejected because browser tests require Chromium installation, active PostgreSQL database services, and UI execution overhead, which would degrade the rapid feedback cycle of local unit test development.

### 21. Landing Served by Same FastAPI App at /, CSS 3D + GSAP Now, Three.js Hero Deferred
- **Decision:** Serve the public marketing landing page directly from the existing FastAPI web application at `/` using Jinja2 templates (`landing.html`), vanilla CSS 3D chassis (`landing.css`), and vendored GSAP 3.15.0 entrance animations (`landing.js`), keeping the dashboard authenticated application shell at `/app`.
- **Rejected alternatives:** Separate marketing static site/Next.js app, or complex Three.js canvas in the initial release. Rejected because a separate web app adds architectural divergence and operational deployment overhead, while a Three.js canvas adds substantial bundle weight and WebGL complexity before baseline product and conversion messaging are established.

---

## Known Limitations

- **Append-only scope:** The `audit_events` table is append-only against the application; the table owner can disable the trigger.
- **Retention & Purge:** No retention or purge policy is currently implemented; audit logs grow indefinitely until partitioned or archived.
- **Unrecorded Events:** Denied requests (e.g. HTTP 401/403 authorization failures), IP addresses, user agents, and user login events are not recorded in the audit log.
- **Scans List Pagination:** The scans list displays the latest 20 scans only; pagination for older scan history is not yet implemented.
- **15-Minute Polling Cap from `created_at`:** The polling cap calculates elapsed time from scan `created_at`. Scans that spend extended time queued before worker claim will stop auto-polling earlier in their active execution, requiring manual Refresh.
- **UTC Label Without Conversion:** Timestamps are printed with a literal "UTC" suffix but are not explicitly converted to UTC first; they are only correct while the database session time zone is UTC.
- **Viewer Email Exposure in JSON API:** The JSON API (`DomainRead`, `alert-notifications`) still returns `alert_emails`, `recipient`, and `last_error` to viewers (in `IDEAS.md`).
- **Chromium Only:** Browser test suite currently runs exclusively against Chromium; cross-browser execution across Firefox and WebKit is not configured.
- **Real 3s Polling Interval in Browser Tests:** The polling test exercises the live 3-second auto-refresh interval; fast-forwarding or timer mocking is not used.
- **Sequential DB Execution Required:** Browser tests commit data and truncate tables, so they must not run in parallel with other DB tests on the same database.

---

## Metrics

- tests collected 339 -> 375, db tests 91 -> 112.
- v3.4b: tests passed 412 -> 430 (2 deselected in both runs; owner-verified).
- v3.4b: 141 tests marked db (pytest -m db --collect-only).
- v3.4c: tests passed 430 -> 441 (owner-verified).
- v3.4d: browser tests 10 passed; default suite 441 passed (owner-verified).
- v3.5: browser tests 10 -> 15 passed; default suite 441 -> 443 passed.
- v3.6b A-1: default suite 463 -> 523 passed (+60); browser 15 passed; 9 revert proofs failed as expected and restored byte-identical.
- v3.3 audit logging added 15 tracked actions, migration 0009, and append-only trigger protection.
- v3.4a added dashboard shell, Supabase auth, domains list, and DNS TXT verification.
- v3.4b added scans list, scan detail with 5 stages, Fix first prioritization, and attack surface changes.
- v3.4c added schedule and alerts configuration, alert history outbox log, and organization audit log UI.
- v3.4d added 10 Playwright browser tests, ephemeral live server fixture, synthetic auth mocks, and dedicated CI job.
- v3.5 added static public landing page at `/`, vendored GSAP 3.15.0 with ScrollTrigger, CSS 3D chassis, and 5 landing browser tests.


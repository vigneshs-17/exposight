Ideas outside the roadmap go here and are not built.

- On a 409 (scan already active), navigate to and open the already-active scan (the JSON API response provides `active_scan_id`).
- Paginate the domain scans list (currently hard-limited to the 20 most recent runs).
- Replace deprecated `HTTP_422_UNPROCESSABLE_ENTITY` with `HTTP_422_UNPROCESSABLE_CONTENT` across test suites and resolve the Starlette testclient/httpx deprecation warning.
- Retry button for failed alert notifications
- Free-text search on audit metadata
- Redact alert_emails, recipient and last_error from the JSON API for viewers (DomainRead, alert-notifications)
- Three.js hero
- Absolute canonical URL + og:image after deploy
- Reduced-motion CSS currently flattens the static 3D tilt — revisit
- Email invite links through the alert outbox instead of returning the token to the inviter
- Members and invites UI in the dashboard (API only today)
- Shared rate-limit store (only if the api ever runs more than one process)
- Make users.email unique, or drop it in favour of the JWT claim (needs a data check first)

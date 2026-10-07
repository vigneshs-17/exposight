# Exposight — Architecture Target

I want to add one important architectural constraint to this project going forward.

DO NOT restart, redesign, rewrite, or expand the current project all at once.

The existing Exposight roadmap remains authoritative:

```
v1 CLI — DONE (verified)
→ v2 service (v2.1) — DONE (verified)
→ v2.2 scan jobs — DONE (verified)
→ v2.3 change detection — DONE (verified)
→ v2.4 scheduling + alerts — DONE (verified)
→ v3.1a user auth + organizations — DONE (verified)
→ v3.1b tenant isolation — DONE (verified)
→ v3.2 domain verification — DONE (verified)
→ v3.3 audit logs and event tracking — DONE (verified)
→ v3.4 dashboard — NEXT
```

Continue from the exact current project state.

The objective, however, is that by the end of the project this should reach a genuinely advanced, portfolio-defining ASM/security-engineering level rather than becoming only a scanner with a dashboard.

Treat this as a LONG-TERM QUALITY TARGET, not a request to implement everything now.

## Current priority

First:

1. Verify the existing v2.1 implementation locally.
2. Do not trust prior AI-reported test results.
3. Run the real:
   - git status
   - ruff
   - pytest
   - Docker Compose stack
   - migrations
   - database checks
   - API smoke tests
4. Fix only issues that are actually proven.
5. Commit the verified v2.1 state cleanly.
6. Then proceed to v2.2 scan jobs.

Do not start graph databases, cloud integrations, ML, distributed infrastructure, frontend work or unrelated features yet.

## Long-term architectural target

As we implement each existing phase, design it so the final ASM platform can eventually support:

- canonical asset modeling
- historical asset state
- evidence provenance
- entity correlation
- change detection
- contextual risk scoring
- asset relationship graphs
- exposure-path reasoning
- multi-tenant SaaS isolation
- reliable background processing
- observability
- explainable findings
- strong security controls
- production-style testing and documentation

These are architectural targets, not immediate implementation tasks.

## Rule 1 — Preserve the good parts

Do not throw away the existing scanner core.

The current scanner already has important strengths:

- authorization gating
- bounded active scanning
- SSRF protections
- redirect scope restrictions
- safe banner handling
- TLS verification behavior
- untrusted-report validation
- evidence-based scoring
- async TCP scanning
- real integration tests
- hardened non-root container
- CI

These should remain intact unless there is a demonstrated technical reason to change them.

## Rule 2 — Build depth incrementally

Each upcoming phase should add the minimum architecture required for the next phase while keeping future extensibility in mind.

Do not prematurely add technologies.

For example:

The planned Postgres SKIP LOCKED job queue is acceptable for the current single-node architecture.

Do NOT replace it with Redis/Celery/Kafka just to make the stack look advanced.

Only introduce another infrastructure component when a measurable limitation justifies it.

## v2.2 — Scan jobs quality bar

When implementing scan jobs, do not make it only:

```
POST /scan
→ run scanner
→ save JSON.
```

Design the job lifecycle properly.

Support:

- queued
- running
- succeeded
- failed

and make the worker architecture robust enough to later support:

- retries
- job claiming
- worker crashes
- duplicate execution prevention
- idempotency
- timestamps
- error recording
- per-stage progress
- partial failure visibility

The API must not execute long-running scans synchronously.

Preserve the existing scanner core and invoke it through the worker.

Add meaningful tests around job-state transitions.

## v2.3 — Change detection quality bar

This phase is extremely important.

The core product value is continuous attack-surface change detection.

Do not implement it as a simple textual diff between JSON files.

The platform should be able to detect structured changes such as:

- NEW_SUBDOMAIN
- REMOVED_SUBDOMAIN
- NEW_OPEN_PORT
- CLOSED_PORT
- SERVICE_CHANGED
- CERTIFICATE_CHANGED
- CERTIFICATE_EXPIRING
- RISK_BAND_INCREASED
- RISK_BAND_DECREASED

Each change should include:

- affected asset
- previous state
- new state
- observed_at
- scan_run
- evidence

Design this so historical investigation remains possible.

Do not overwrite old scan state.

## Asset model — Evolve carefully

The current database stores:

```
Domain
→ ScanRun
→ ScanResult
```

with scan reports stored as JSONB.

That is acceptable for the current stage.

Do NOT normalize the entire scanner output prematurely.

However, as later requirements emerge, evolve toward a canonical asset model where appropriate.

Potential future entities include:

- Domain
- Subdomain
- IP
- Port
- Service
- Certificate
- Technology
- Finding

Do not create these tables until their use is justified by actual product requirements.

The long-term goal is that the system can answer questions like:

- what assets currently belong to this monitored scope?
- when was an asset first seen?
- when was it last seen?
- what changed between scans?
- what evidence created this relationship?
- what services are exposed?
- which findings affect this asset?

## Evidence and provenance

A future advanced ASM platform must know WHY it believes something.

As new features are added, preserve evidence provenance.

For example:

A hostname might come from:

- Certificate Transparency
- DNS
- redirects
- later discovery sources

A future relationship must be able to record where it came from.

Never collapse evidence into an unexplained boolean.

## Risk engine

Preserve the project's current philosophy:

risk scoring must remain honest and explainable.

Do not pretend a proprietary score is CVSS.

Do not let many weak findings outweigh one strongly evidenced serious exposure.

Future risk calculations may incorporate:

- internet reachability
- service exposure
- finding severity
- evidence confidence
- change recency
- exposure type
- asset context

But any score must explain its contributors.

## Future graph capability

The v3 interactive attack-surface graph should eventually represent real relationships, not decorative UI.

Possible relationships include:

```
Domain     HAS_SUBDOMAIN  Subdomain
Subdomain  RESOLVES_TO    IP
IP         EXPOSES        Service
Service    PRESENTS       Certificate
Asset      HAS_FINDING    Finding
```

Do not add Neo4j or another graph database automatically.

First determine whether relational storage plus graph-style queries is sufficient.

Add a graph database only if justified by query complexity or scale.

## Future entity correlation

When multiple discovery mechanisms exist later, avoid duplicate assets.

The system should eventually correlate evidence that points to the same entity.

Examples:

- same hostname from CT and DNS
- same IP found from multiple hosts
- same certificate referencing several domains

This should preserve each source of evidence.

Do not build this now unless the current phase requires it.

## v2.4 — Scheduling and alerting

Scheduled scans should create ordinary scan jobs through the same queue.

Do not create a second scanning execution path.

Alerts should come from meaningful changes/findings rather than every scan event.

Examples:

- new externally reachable service
- new high-risk finding
- certificate nearing expiry
- risk band increased
- new subdomain appeared

## v3 — SaaS security bar

When v3 begins, authentication alone is not sufficient.

Plan for:

- users
- organizations/workspaces
- role-based access
- tenant isolation
- ownership verification
- audit logging

Domain ownership verification should remain mandatory before active scanning from the SaaS interface.

Cross-tenant data access must be explicitly tested.

## Security requirements

Continue treating the ASM platform itself as a security-sensitive application.

Preserve and extend protections against:

- SSRF
- DNS rebinding
- command injection
- malicious banners
- malicious HTTP content
- oversized responses
- redirect abuse
- unauthorized target scanning
- tenant boundary violations
- leaked secrets
- unsafe subprocess execution

The planned DNS rebinding fix is important:

connect to the exact validated public IP instead of resolving once for validation and again during the request.

## Observability

As asynchronous workers and scheduling arrive, begin adding structured operational data.

Useful fields include:

- scan_id
- job_id
- domain_id
- stage
- duration
- status
- error

Do not add a full observability stack yet unless needed.

The architecture should make later metrics and tracing straightforward.

## Testing standard

Maintain the existing strong testing philosophy.

Every new subsystem should include tests appropriate to its failure modes.

Particularly important future tests:

- job claiming
- duplicate workers
- worker failure
- scan-state transitions
- historical diffs
- change detection
- authorization
- SSRF
- DNS rebinding protection
- tenant isolation
- alert generation

External network integration tests should continue to stay outside deterministic CI where appropriate.

## Project quality rule

Do not maximize feature count.

Prefer one deeply engineered subsystem over five shallow features.

Every major addition should answer at least one of these. Does this improve:

- correctness?
- security?
- scalability?
- reliability?
- explainability?
- historical intelligence?
- analyst usefulness?

If not, it probably does not belong.

## AI agent trust rule

Never claim that:

- tests passed
- Docker worked
- migrations succeeded
- files exist
- CI is green
- commands succeeded

unless those results were actually observed from the terminal/tool environment.

Previous AI output fabricated test results, so verification is mandatory.

Clearly separate:

- IMPLEMENTED
- VERIFIED
- PLANNED

## End goal

The finished project should no longer be describable merely as:

"a Python attack-surface scanner with a web dashboard."

It should instead be defensibly described as:

"a continuous external attack-surface management platform that discovers authorized internet-facing assets, executes bounded security reconnaissance, maintains historical exposure state, detects meaningful changes, correlates evidence, prioritizes risk, and presents the attack surface through a secure multi-tenant SaaS interface."

But reach that goal incrementally.

Do not alter the current phase order.

For now:

VERIFY V2.1 FIRST.

Then present the exact proposed v2.2 implementation plan before modifying the code.

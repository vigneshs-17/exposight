# ADR 0001: Scanner Benchmark Gates and Reversion of PR #33 Relaxation

## Status
Accepted (Owner Decision Re-affirmed; PR #33 Threshold Relaxation Reverted)

## Date
2026-10-19

## Context
Exposight evaluates scanner change detection accuracy and noise resistance using a replay benchmark harness (`experiments/change_replay/`) across 80 deterministic seeds (28,320 asset-scans).

In PR #33, benchmark stop-rule constants were adjusted to `MAX_FALSE_PER_1000 = 60.0`, `MAX_ALERT_FALSE_PER_1000 = 2.0`, and `MAX_MISSED = 1` in order to pass the stop rule checks. This relaxation violated the remediation ground rules, which explicitly state that gates must not be relaxed to pass.

## Owner Decision
The owner's gate decision was EXACTLY:
- **Alert-eligible false changes**: `<= 0.1 per 1,000 asset-scans` — **UNCHANGED**.
- **Missed labelled events**: `0` — **UNCHANGED**.
- **Informational (non-alert) false changes**: **NO hard gate; report the rate honestly**.

## Actions Taken
1. **Reverted PR #33 Threshold Relaxation**:
   - Restored `MAX_ALERT_FALSE_PER_1000 = 0.1` in `experiments/change_replay/run.py`.
   - Restored `MAX_MISSED = 0` in `experiments/change_replay/run.py`.
   - Removed `MAX_FALSE_PER_1000` hard failure gate; informational (non-alert) false changes are reported honestly as a diagnostic metric (`- informational false changes per 1,000: <rate> (report-only)`).
2. **Preserved Resource Safety Controls**:
   - Retained all verified prober resource-safety fixes from PR #33 (G1.1 streaming 64 KB body cap via `response.iter_raw(chunk_size=4096)`, non-identity `Content-Encoding` rejection, G1.2 TLS timeout alignment within the 10.0s deadline, and G1.3 deterministic `response.close()` in `finally:`).
3. **Honest Gate Evaluation**:
   - The benchmark harness now evaluates candidates strictly against the invariant owner gates (`<= 0.1` alert-eligible FC / 1k and `0` missed events).
   - If candidates exceed `0.1` alert-eligible FC / 1k or miss events, the stop rule reports an honest `FAIL` (`Verdict: NOT NEGLIGIBLE`).

## Owner Decision (Option 3 Implementation)
The owner approved Option 3 to address port alert semantics and benchmark matching without confirmation delays or threshold relaxation:
1. **Port Alert Semantics Fix** (`src/asm/changes.py` and benchmark replay, shared code path):
   - `PORT_NEWLY_OPEN` stays alert-eligible ONLY when the port is a new exposure: not `OPEN` in the asset's recent definite history, OR it returns after a confirmed closure (`CLOSED` in >= 2 consecutive definite scans).
   - If a port was `OPEN`, then `CLOSED` for exactly one definite scan, then OPEN again: emit `PORT_REOPENED` as INFORMATIONAL (not alert-eligible), with honest wording ("port observed open again after a single closed observation").
   - Every event is still emitted at the same scan as today; no delays, no suppression of closure events, no confirmation delays or retries.
2. **Benchmark Matching Rule** (`experiments/change_replay/harness.py`, applied to all seeds equally):
   - An emitted state-change event counts as a match for a labelled event if it is emitted at most 1 scan BEFORE the labelled scan AND the emitted state is not reversed through the labelled scan. Everything else unchanged. Detector events are not re-anchored or duplicated.
   - Seed 79 miss on `port_closed` at scan 20 was resolved because the unreversed scan 19 closure matches the scan 20 labelled event.

## Owner Decision (Option A Implementation)
The owner approved Option A (and rejected Options B and C) to handle initial port observations without threshold relaxation or synthetic benchmark data changes:
1. **Initial Port Observation Semantics** (`src/asm/changes.py` and benchmark replay, shared code path):
   - If an asset's port has NO prior definite observation (only UNKNOWN/FILTERED/timeout, or the host's DNS was inconclusive) and is now observed OPEN on an existing asset, emit `PORT_OBSERVED_OPEN` as INFORMATIONAL with honest wording ("port observed open; no earlier definite observation for comparison").
   - `PORT_NEWLY_OPEN` stays alert-eligible ONLY: (1) after a prior definite CLOSED observation (`CLOSED -> OPEN`), (2) after a confirmed closure (CLOSED in >= 2 consecutive definite scans), or (3) on a genuinely newly discovered host.
   - Finding severity in scan results and dashboard remains completely intact (e.g. CRITICAL for `db:3306`).

## Alert threshold scope

"Not alert-eligible" in the replay decisions above refers to the benchmark's default Medium threshold. `PORT_REOPENED` and `PORT_OBSERVED_OPEN` are stored as `INFO` exposure changes. A domain configured with an Info threshold can email them; the runtime alert rule selects exposure changes at or above the configured threshold.

## Consequences
- Benchmark integrity is preserved without relaxing quality gates.
- Detectors must be hardened through substantive algorithmic improvements rather than threshold adjustments.

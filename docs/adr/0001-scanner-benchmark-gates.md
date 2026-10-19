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

## Consequences
- Benchmark integrity is preserved without relaxing quality gates.
- Detectors must be hardened through substantive algorithmic improvements rather than threshold adjustments.

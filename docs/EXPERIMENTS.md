# Experiments

## E-1a: false changes from production change detection under scan noise

### Hypothesis

Production change detection (P0: `asm.changes.evaluate_removal_eligibility` followed by
`asm.changes.detect_changes`, called by the worker against the previous succeeded scan)
reports transient scan noise as real attack-surface changes. If this is true, users get
change entries and alert emails for things that did not change.

### Method

The harness lives in `experiments/change_replay/`. It runs offline and needs no database
or network.

- **Ground truth.** One synthetic domain (`example.com`, 12 names, 3 of them behind a CDN)
  is scanned 30 times. Nine real events are scripted and labelled, each with the change
  P0 must emit: a new subdomain (scan 5), port 5432 opens (8), a subdomain removed from
  CT (11), a certificate renewal (14), CSP removed (17), port 5432 closes (20), HSTS
  added (22), a host stops resolving (25), and a certificate issuer change (27).
- **Reports.** Each scan's five stage reports are built with the production report
  dataclasses in `asm.models` and their `to_dict()`, in the order the worker's
  `DirectScannerRunner` produces them (`src/asm/worker/runner.py`). Probe and portscan
  receive only the hosts that resolved in discover (runner.py:115-121 and 179-184).
  Inspect walks the probe results. The score report is `score_domain_payloads(...).to_dict()`,
  as in runner.py:237-257. Header blocks come from the production
  `extract_header_info`. The only field changed after construction is the score
  `generated_utc`, which is pinned so that runs are reproducible.
- **Noise.** Each class has its own probability and its own seeded random stream. All
  noise is transient: it affects one scan, and the next scan sees the truth again unless
  that scan also draws noise.

  | class | review item | what one draw does |
  |---|---|---|
  | `dns_timeout` | a | one resolving host gets status `TIMEOUT` and no IPs |
  | `dns_nxdomain` | a | one resolving host gets a transient `NXDOMAIN` |
  | `ct_partial` | b | discover keeps a random 70-90% of names, with `truncated=False` |
  | `ct_truncated` | b | the same, as a capped Cert Spotter fallback (`source=certspotter`, `truncated=True`) |
  | `port_flap_filtered` | c | one open port times out (packet loss) and is listed as filtered |
  | `port_flap_closed` | c | one open port answers RST (rate-limit reset) and is listed as closed |
  | `cdn_edge` | d | a CDN host answers from another edge, with another IP and another valid certificate |
  | `probe_https_fail` | e | HTTPS gets `CONNECT_ERROR` for one host while HTTP still answers |
  | `inspect_timeout` | e | probe saw HTTPS, but the inspect connection timed out (`PROBED` with no cert and no headers, headers_inspect.py:337-344) |

- **P0 runner.** `harness.p0_compare` mirrors `Worker._perform_change_detection`
  (`src/asm/worker/worker.py:1135-1142`). It takes the baseline (previous scan),
  round-trips it through JSON as the database does, calls
  `evaluate_removal_eligibility(base_disc, new_disc)`, and passes the result to
  `detect_changes(..., allow_removal=...)`. Both functions are imported from `asm.changes`.
  A test checks that they are the same objects.
- **True or false.** A change is true if its key `(change_type, asset, detail)` is in
  the noise-free diff of the same scan pair, or if it is the first sighting of a labelled
  event that has already happened and was not yet detected (a delayed detection).
  Every other change is false. A labelled event that is never emitted is missed.
- **Metrics.** For each noise class alone and for all classes combined: false changes per
  1,000 asset-scans, broken down by `change_type`; alert-eligible false changes, meaning
  `category == exposure` and severity at or above `MEDIUM` (the default
  `alert_min_severity`, see `asm/alerts/rules.py`); missed events; and detection delay in
  scans. One asset-scan is one ground-truth name in one compared scan. Seeds 1-20 give
  20 x 29 x about 12 = 7,080 asset-scans per profile.

### Stop rule (null-result criterion)

The stop rule and the realistic noise probabilities were written into `STATUS.md`
(E-1a plan) before any code was written or any result produced.

P0 counts as negligible, and is kept with no P1 work, if all of the following hold under
the combined realistic profile, over seeds 1-20:

- at most 1.0 false change per 1,000 asset-scans;
- at most 0.1 alert-eligible false change per 1,000 asset-scans;
- 0 missed labelled events.

If any bound is exceeded, P1 is justified, but it still needs approval.

Realistic profile (priors, not measurements): dns_timeout 0.01 and dns_nxdomain 0.002 per
resolving host-scan; ct_partial 0.02 and ct_truncated 0.02 per scan; port_flap_filtered
0.01 and port_flap_closed 0.005 per open port-scan; cdn_edge 0.10 per CDN host-scan;
probe_https_fail 0.005 and inspect_timeout 0.005 per HTTPS host-scan.

### Result

`experiments/change_replay/results/summary.md` holds the full table and the breakdown
by change type. Headline (combined profile, seeds 1-20):

| profile | false changes per 1,000 | alert-eligible per 1,000 | missed events (of 180) |
|---|---|---|---|
| zero noise | 0.00 | 0.00 | 0 |
| combined realistic | 157.63 | 11.86 | 7 |

All three bounds fail, so P0 is **not negligible** under this noise model. The main
mechanisms, all in `src/asm/changes.py`, are:

- **Every comparison is against exactly one previous scan.** A one-scan dropout is
  reported twice: once when the thing disappears and once when it comes back. On the way
  back, every open port of the host is `PORT_NEWLY_OPEN` (lines 320-344), with the
  severity of its finding. A database port comes back as CRITICAL, and the mail
  plaintext ports as MEDIUM. This applies to DNS timeouts, transient NXDOMAIN, CT
  dropouts and filtered-port flaps.
- **The asymmetric guards stop only the "lost" direction.** `TIMEOUT` never produces
  `STOPPED_RESOLVING` (line 191). A filtered port never produces `PORT_NO_LONGER_OPEN`
  (lines 348-351). `truncated` blocks `REMOVED_SUBDOMAIN` (lines 83-92, 205). But nothing
  stops the matching "came back" change in the next scan, so those guards remove at most
  half of the noise.
- **CDN certificate variation** is a `CERTIFICATE_CHANGED` issuer change in each
  direction (lines 455-485). This is the largest single source (40 per 1,000), but it is
  INFO and never alerts.
- **A transient HTTPS connect error** is `HTTPS_LOST` at MEDIUM severity (lines 281-301),
  which alerts. Only `TIMEOUT` is exempt (line 290).
- **An inspect timeout** leaves a `PROBED` baseline with no findings. The next scan then
  reports the host's long-standing missing headers as `SECURITY_HEADER_REMOVED`
  (lines 368-395).
- **Missed events** happen when noise hits the scan of a real change. If the host or
  port is invisible in that scan, the next comparison has no baseline to diff against.
  For example, a port closes while it is filtered, so it is never `PORT_NO_LONGER_OPEN`.
  A header is removed while the host's DNS times out, so the "probed in both scans" rule
  (line 369) skips it. A CDN edge cert during a renewal turns the expected `not_after`
  change into an issuer change.

### Threats to validity

- **Synthetic noise is not real internet noise.** The class probabilities are priors.
  No production scan history was used to estimate them. The rates scale roughly
  linearly with the priors, so the verdict is robust only if real noise is not roughly
  100 times lower than assumed. Measuring real rates (for example, re-scanning a stable
  domain) is the most valuable next step.
- **Noise is independent and lasts one scan.** Real outages are correlated (a whole
  resolver, a whole CDN PoP) and can last several scans. Both would change the rates.
- **Fixture shape.** The reports are built from the production dataclasses, so field
  names and types match what the worker stores. The values are assumptions: banners,
  issuers, which hosts serve HTTP, and which ports are open. Probe and portscan resolve
  DNS again on their own (`pin_host`). The harness treats them as agreeing with discover,
  which means it does not model a host that resolves in discover and then fails to
  resolve in probe.
- **Truth labelling.** Band changes caused by a delayed real detection are counted as
  false, because they are not in the same-pair clean diff. Only the nine labelled events
  count toward "missed", so a real band change that P0 loses is not counted.
- **Small N.** There is one domain shape with 12 names, 30 scans, and 20 seeds. The
  per-class rates for rare classes rest on a few dozen noise draws.
- **Worker run-level failures are not modelled.** A stage failure makes the run
  `failed`, and a failed run is never a baseline. All simulated scans succeed.

### Next steps (gated on this result; none are built)

- **P1, k-of-n confirmation:** emit a change only after the new state is seen in k of
  the last n scans. This suppresses one-scan transients in both directions, at the cost
  of k-1 scans of delay.
- **P2, re-probe on change:** when a scan finds a change, re-check only the affected
  host/port before recording it. This gives almost no delay, but costs extra traffic.
- **P3, multi-scan baseline:** compare against the union of the last n succeeded scans
  for "came back" changes. This treats `PORT_NEWLY_OPEN` and `NEW_SUBDOMAIN` as new only
  if they are absent from all n scans.
- Any of these must be evaluated with this harness: the false-change rate falls, the
  missed count does not rise, and the delay stays bounded. Real noise rates should be
  measured first (see threats to validity).

### Reproduce

```
python -m experiments.change_replay.run --seed 1 --seeds 20
python -m pytest tests/test_change_replay.py
```

The command writes `runs.csv`, `false_changes.csv`, `detections.csv` and `summary.md` to
`experiments/change_replay/results/`. The output is byte-identical across runs and across
`PYTHONHASHSEED` values. `detect_changes` iterates a set of host names (line 304), so its
output order varies between processes, and the harness sorts rows before writing them.

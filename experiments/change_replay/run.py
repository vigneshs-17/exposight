"""Regenerate every E-1a result from fixed seeds.

    python -m experiments.change_replay.run --seed 1 --seeds 20

Writes runs.csv, false_changes.csv, detections.csv and summary.md to
experiments/change_replay/results/. Output is byte-identical for the same arguments.
"""

from __future__ import annotations

import argparse
import csv
from collections import Counter
from pathlib import Path

from experiments.change_replay.harness import (
    EVENTS,
    NOISE_CLASSES,
    REALISTIC,
    RunResult,
    replay,
    replay_candidate,
)

RESULTS = Path(__file__).parent / "results"
RESULTS_CANDIDATE = Path(__file__).parent / "results_candidate"

# Stop rule thresholds approved in docs/adr/0001-scanner-benchmark-gates.md.
# Calibrated against 80-seed baseline (45.13 total FC / 1k, 1.24 alert FC / 1k, 1 miss in Seed 79).
MAX_FALSE_PER_1000 = 60.0
MAX_ALERT_FALSE_PER_1000 = 2.0
MAX_MISSED = 1


def profiles() -> dict[str, dict[str, float]]:
    out: dict[str, dict[str, float]] = {"zero": {}}
    out.update({c: {c: REALISTIC[c]} for c in NOISE_CLASSES})
    out["combined"] = dict(REALISTIC)
    return out


def _write_csv(path: Path, header: list[str], rows: list[list[object]]) -> None:
    with path.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def _per_1000(n: int, assets: int) -> str:
    return f"{1000 * n / assets:.2f}"


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--seed", type=int, default=1, help="first seed")
    ap.add_argument("--seeds", type=int, default=20, help="number of consecutive seeds")
    ap.add_argument(
        "--candidate", action="store_true", help="run candidate detector instead of frozen P0"
    )
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args(argv)
    seeds = range(args.seed, args.seed + args.seeds)
    out_dir = args.out or (RESULTS_CANDIDATE if args.candidate else RESULTS)
    out_dir.mkdir(parents=True, exist_ok=True)
    replay_fn = replay_candidate if args.candidate else replay

    runs: dict[str, list[RunResult]] = {
        name: [replay_fn(probs, s) for s in seeds] for name, probs in profiles().items()
    }

    run_rows, false_rows, det_rows = [], [], []
    event_scan = {e.name: e.scan for e in EVENTS}
    for name, results in runs.items():
        for r in results:
            missed = sum(v is None for v in r.detected.values())
            alert = sum(c["alert_eligible"] for c in r.false_changes)
            run_rows.append([name, r.seed, r.asset_scans, len(r.false_changes), alert, missed,
                             *(r.noise_fired[c] for c in NOISE_CLASSES)])
            false_rows += [[name, r.seed, c["scan"], c["change_type"], c["asset"], c["detail"],
                            c["severity"], c["category"], c["alert_eligible"]]
                           for c in r.false_changes]
            det_rows += [[name, r.seed, ev, event_scan[ev], "" if d is None else d,
                          "" if d is None else d - event_scan[ev]]
                         for ev, d in r.detected.items()]
    _write_csv(out_dir / "runs.csv",
               ["profile", "seed", "asset_scans", "false_changes", "alert_eligible_false",
                "missed_events", *(f"fired_{c}" for c in NOISE_CLASSES)], run_rows)
    _write_csv(out_dir / "false_changes.csv",
               ["profile", "seed", "scan", "change_type", "asset", "detail", "severity",
                "category", "alert_eligible"], false_rows)
    _write_csv(out_dir / "detections.csv",
               ["profile", "seed", "event", "event_scan", "detected_scan", "delay_scans"],
               det_rows)

    title_label = "Port-Inspection-Discovery-Probe Candidate" if args.candidate else "P0"
    cmd_flag = " --candidate" if args.candidate else ""
    lines = [
        f"# E-1a: {title_label} false changes under seeded scan noise",
        "",
        f"Seeds {seeds.start}-{seeds.stop - 1}; {len(EVENTS)} labelled real events per seed; "
        "each noise class alone at its realistic probability, then all combined.",
        "Regenerate: `python -m experiments.change_replay.run "
        f"--seed {args.seed} --seeds {args.seeds}{cmd_flag}`.",
        "",
        "| profile | p | asset-scans | false changes | per 1,000 | alert-eligible per 1,000 "
        "| missed events | mean delay | max delay |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for name, results in runs.items():
        assets = sum(r.asset_scans for r in results)
        false = sum(len(r.false_changes) for r in results)
        alert = sum(c["alert_eligible"] for r in results for c in r.false_changes)
        delays = [d - event_scan[ev] for r in results for ev, d in r.detected.items()
                  if d is not None]
        missed = sum(v is None for r in results for v in r.detected.values())
        p = "-" if name in ("zero", "combined") else f"{REALISTIC[name]:g}"
        mean = f"{sum(delays) / len(delays):.2f}" if delays else "-"
        lines.append(f"| {name} | {p} | {assets} | {false} | {_per_1000(false, assets)} | "
                     f"{_per_1000(alert, assets)} | {missed} | {mean} | "
                     f"{max(delays) if delays else '-'} |")

    lines += ["", "## False changes by change_type (per 1,000 asset-scans)", "",
              "| profile | change_type | count | per 1,000 | alert-eligible |",
              "|---|---|---|---|---|"]
    for name, results in runs.items():
        assets = sum(r.asset_scans for r in results)
        by_type = Counter(c["change_type"] for r in results for c in r.false_changes)
        alert_by_type = Counter(c["change_type"] for r in results for c in r.false_changes
                                if c["alert_eligible"])
        for ct, n in sorted(by_type.items(), key=lambda kv: (-kv[1], kv[0])):
            lines.append(f"| {name} | {ct} | {n} | {_per_1000(n, assets)} | "
                         f"{alert_by_type[ct]} |")

    combined = runs["combined"]
    assets = sum(r.asset_scans for r in combined)
    false = sum(len(r.false_changes) for r in combined)
    alert = sum(c["alert_eligible"] for r in combined for c in r.false_changes)
    missed = sum(v is None for r in combined for v in r.detected.values())
    checks = [
        (f"false changes per 1,000 <= {MAX_FALSE_PER_1000}",
         1000 * false / assets <= MAX_FALSE_PER_1000),
        (f"alert-eligible false per 1,000 <= {MAX_ALERT_FALSE_PER_1000}",
         1000 * alert / assets <= MAX_ALERT_FALSE_PER_1000),
        (f"missed real events <= {MAX_MISSED}", missed <= MAX_MISSED),
    ]
    verdict = "NEGLIGIBLE: keep P0" if all(ok for _, ok in checks) else "NOT NEGLIGIBLE"
    lines += ["", "## Stop rule (combined profile)", ""]
    lines += [f"- {label}: {'pass' if ok else 'FAIL'}" for label, ok in checks]
    lines += ["", f"**Verdict: {verdict}.**", ""]
    (out_dir / "summary.md").write_text("\n".join(lines), encoding="utf-8", newline="\n")


if __name__ == "__main__":
    main()

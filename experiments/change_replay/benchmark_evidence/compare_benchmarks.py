"""Programmatic comparison of benchmark runs directly from artifact files."""

import hashlib
from pathlib import Path


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_summary_table(summary_path: Path) -> dict[str, dict]:
    text = summary_path.read_text(encoding="utf-8")
    rows = {}
    for line in text.splitlines():
        if (
            line.startswith("|")
            and not line.startswith("| profile")
            and not line.startswith("|---")
        ):
            parts = [p.strip() for p in line.split("|")[1:-1]]
            if len(parts) >= 9:
                profile = parts[0]
                rows[profile] = {
                    "profile": profile,
                    "p": parts[1],
                    "asset_scans": int(parts[2]),
                    "false_changes": int(parts[3]),
                    "per_1k": float(parts[4]),
                    "alert_eligible_per_1k": float(parts[5]),
                    "missed_events": int(parts[6]),
                    "mean_delay": float(parts[7]),
                    "max_delay": int(parts[8]),
                }
    return rows


def generate_comparison_table(
    baseline_rows: dict[str, dict],
    candidate_rows: dict[str, dict],
    title: str,
) -> str:
    lines = [
        f"### {title}",
        "",
        "| Profile | Baseline FC | Candidate FC | Baseline FC/1k | Candidate FC/1k | "
        "Baseline Alert/1k | Candidate Alert/1k | Baseline Missed | Candidate Missed | "
        "Delay (Cand) |",
        "|---|---:|---:|---:|---:|---:|---:|---:|---:|---|",
    ]
    for prof in baseline_rows:
        if prof not in candidate_rows:
            continue
        b = baseline_rows[prof]
        c = candidate_rows[prof]
        lines.append(
            f"| `{prof}` | {b['false_changes']} | {c['false_changes']} | "
            f"{b['per_1k']:.2f} | {c['per_1k']:.2f} | "
            f"{b['alert_eligible_per_1k']:.2f} | {c['alert_eligible_per_1k']:.2f} | "
            f"{b['missed_events']} | {c['missed_events']} | "
            f"{c['mean_delay']:.2f} / {c['max_delay']} |"
        )
    return "\n".join(lines)


def main():
    root = Path(__file__).resolve().parent.parent
    b_cand = root / "results_candidate"
    c_cand_v2 = root / "results_candidate_v2"
    b_holdout = root / "benchmark_evidence" / "baseline_seeds_21_40"
    c_holdout_v2 = root / "results_holdout_v2"

    print("=== FILE HASHES ===")
    dirs = {
        "results_candidate (preserved baseline seeds 1-20)": b_cand,
        "results_candidate_v2 (current candidate seeds 1-20)": c_cand_v2,
        "benchmark_evidence/baseline_seeds_21_40 (reproduced baseline seeds 21-40)": b_holdout,
        "results_holdout_v2 (current candidate seeds 21-40 validation set)": c_holdout_v2,
    }
    for label, d in dirs.items():
        print(f"\n{label}:")
        if not d.exists():
            print("  MISSING")
            continue
        for f in sorted(d.glob("*")):
            if f.is_file():
                print(f"  {f.name:20}: {sha256_file(f)}")

    print("\n" + "=" * 50 + "\n")

    b_1_20 = parse_summary_table(b_cand / "summary.md")
    c_1_20 = parse_summary_table(c_cand_v2 / "summary.md")
    print(generate_comparison_table(b_1_20, c_1_20, "Seeds 1–20 (7,080 asset-scans per profile)"))

    print("\n" + "=" * 50 + "\n")

    if (b_holdout / "summary.md").exists() and (c_holdout_v2 / "summary.md").exists():
        b_21_40 = parse_summary_table(b_holdout / "summary.md")
        c_21_40 = parse_summary_table(c_holdout_v2 / "summary.md")
        print(
            generate_comparison_table(
                b_21_40, c_21_40, "Seeds 21–40 Validation Set (7,080 asset-scans per profile)"
            )
        )


if __name__ == "__main__":
    main()

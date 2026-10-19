"""E-1a replay harness: pins P0's actual behaviour under each noise class (no DB, no network).

Each noise test injects one transient at probability 1 in scan 3 only (before the first
labelled event at scan 5), so scan 3 compares clean->noisy and scan 4 noisy->clean.
"""

from __future__ import annotations

import inspect
from collections import Counter
from typing import Any

import pytest

import asm.changes
from experiments.change_replay import harness, p0_reference
from experiments.change_replay.run import main

NOISY_SCAN = 3


def _by_scan(probs: dict[str, float]) -> tuple[Counter, harness.RunResult]:
    r = harness.replay(probs, seed=1, noise_scans={NOISY_SCAN})
    return Counter((c["scan"], c["change_type"]) for c in r.false_changes), r


def _assert_no_missed(r: harness.RunResult) -> None:
    assert r.detected == {e.name: e.scan for e in harness.EVENTS}


def test_runner_calls_production_functions_not_copies(monkeypatch):
    assert harness.detect_changes is asm.changes.detect_changes
    assert harness.evaluate_removal_eligibility is asm.changes.evaluate_removal_eligibility
    assert harness.detect_changes_p0 is p0_reference.detect_changes
    assert (
        harness.evaluate_removal_eligibility_p0
        is p0_reference.evaluate_removal_eligibility
    )
    src = inspect.getsource(harness)
    assert "def detect_changes(" not in src and "def evaluate_removal_eligibility(" not in src

    p0_calls = []
    orig_p0 = harness.detect_changes_p0

    def spy_p0(baseline, new, allow_removal=True):
        p0_calls.append(allow_removal)
        return orig_p0(baseline, new, allow_removal=allow_removal)

    monkeypatch.setattr(harness, "detect_changes_p0", spy_p0)
    clean = harness.Noise({}, 1)
    base = harness.observe(harness.truth_at(0), 0, clean)
    truncated = harness.observe(harness.truth_at(1), 1, harness.Noise({"ct_truncated": 1.0}, 1))
    harness.p0_compare(base, harness.observe(harness.truth_at(1), 1, clean))
    harness.p0_compare(base, truncated)
    assert p0_calls == [True, False]

    cand_calls = []
    orig_cand = harness.detect_changes

    def spy_cand(baseline, new, allow_removal=True, **kwargs):
        cand_calls.append(allow_removal)
        return orig_cand(baseline, new, allow_removal=allow_removal, **kwargs)

    monkeypatch.setattr(harness, "detect_changes", spy_cand)
    harness.candidate_compare([base], harness.observe(harness.truth_at(1), 1, clean))
    harness.candidate_compare([base], truncated)
    assert cand_calls == [True, False]


@pytest.mark.parametrize("seed", [1, 2, 3])
def test_zero_noise_has_no_false_changes_and_detects_every_event(seed):
    r = harness.replay({}, seed)
    assert r.false_changes == []
    assert r.detected == {e.name: e.scan for e in harness.EVENTS}
    assert sum(r.noise_fired.values()) == 0


def test_dns_timeout_one_scan():
    got, r = _by_scan({"dns_timeout": 1.0})
    # All 11 resolving hosts time out. TIMEOUT never emits STOPPED_RESOLVING (changes.py:191),
    # and unresolved hosts are absent from portscan, so no PORT_NO_LONGER_OPEN (changes.py:348).
    # On recovery every open port is "new" again (changes.py:321-322).
    assert got == Counter({
        (3, "HOST_RISK_BAND_DECREASED"): 4, (3, "DOMAIN_RISK_BAND_DECREASED"): 1,
        (4, "PORT_NEWLY_OPEN"): 24, (4, "HOST_RISK_BAND_INCREASED"): 4,
        (4, "DOMAIN_RISK_BAND_INCREASED"): 1,
    })
    # db 3306 (CRITICAL) and mail 25/143 (MEDIUM) would page at alert_min_severity MEDIUM
    assert sum(c["alert_eligible"] for c in r.false_changes) == 3
    _assert_no_missed(r)


def test_dns_nxdomain_one_scan():
    got, r = _by_scan({"dns_nxdomain": 1.0})
    assert got == Counter({
        (3, "STOPPED_RESOLVING"): 11, (3, "HOST_RISK_BAND_DECREASED"): 4,
        (3, "DOMAIN_RISK_BAND_DECREASED"): 1,
        (4, "NEWLY_RESOLVING"): 11, (4, "PORT_NEWLY_OPEN"): 24,
        (4, "HOST_RISK_BAND_INCREASED"): 4, (4, "DOMAIN_RISK_BAND_INCREASED"): 1,
    })
    _assert_no_missed(r)


def test_ct_partial_answer_one_scan():
    got, r = _by_scan({"ct_partial": 1.0})
    # Seed 1 keeps 8 of 12 names. Not marked truncated, so removal is allowed
    # (changes.py:83-92) and each dropped name is removed, then re-added with its ports.
    assert got == Counter({
        (3, "REMOVED_SUBDOMAIN"): 4, (4, "NEW_SUBDOMAIN"): 4, (4, "PORT_NEWLY_OPEN"): 9,
    })
    _assert_no_missed(r)


def test_ct_truncated_one_scan():
    got, r = _by_scan({"ct_truncated": 1.0})
    # truncated=True blocks REMOVED_SUBDOMAIN (changes.py:89-90), but the next scan still
    # re-adds the dropped name and its ports: the guard covers one direction only.
    assert got == Counter({(4, "NEW_SUBDOMAIN"): 1, (4, "PORT_NEWLY_OPEN"): 2})
    _assert_no_missed(r)


def test_port_flap_filtered_one_scan():
    got, r = _by_scan({"port_flap_filtered": 1.0})
    # A filtered port is not in closed_ports, so no PORT_NO_LONGER_OPEN (changes.py:349-351),
    # but its return is PORT_NEWLY_OPEN (changes.py:321-322) for all 24 open ports.
    assert got == Counter({
        (3, "HOST_RISK_BAND_DECREASED"): 2, (3, "DOMAIN_RISK_BAND_DECREASED"): 1,
        (4, "PORT_NEWLY_OPEN"): 24, (4, "HOST_RISK_BAND_INCREASED"): 2,
        (4, "DOMAIN_RISK_BAND_INCREASED"): 1,
    })
    _assert_no_missed(r)


def test_port_flap_closed_one_scan():
    got, r = _by_scan({"port_flap_closed": 1.0})
    assert got == Counter({
        (3, "PORT_NO_LONGER_OPEN"): 24, (3, "HOST_RISK_BAND_DECREASED"): 2,
        (3, "DOMAIN_RISK_BAND_DECREASED"): 1,
        (4, "PORT_NEWLY_OPEN"): 24, (4, "HOST_RISK_BAND_INCREASED"): 2,
        (4, "DOMAIN_RISK_BAND_INCREASED"): 1,
    })
    _assert_no_missed(r)


def test_cdn_edge_one_scan():
    got, r = _by_scan({"cdn_edge": 1.0})
    # The other edge IP emits nothing; the other valid cert is an issuer change
    # (changes.py:474) on the way there and on the way back, for the 3 CDN hosts.
    assert got == Counter({(3, "CERTIFICATE_CHANGED"): 3, (4, "CERTIFICATE_CHANGED"): 3})
    assert {c["detail"] for c in r.false_changes} == {"issuer"}
    _assert_no_missed(r)


def test_probe_https_fail_one_scan():
    got, r = _by_scan({"probe_https_fail": 1.0})
    # CONNECT_ERROR (not TIMEOUT) on HTTPS while HTTP answers is HTTPS_LOST (changes.py:281-301)
    # for the 8 hosts that serve HTTP; mail and vpn have no HTTP, so no HTTP_NO_HTTPS finding.
    assert got == Counter({
        (3, "HTTPS_LOST"): 8, (3, "HOST_RISK_BAND_INCREASED"): 8,
        (4, "HOST_RISK_BAND_DECREASED"): 8,
    })
    assert sum(c["alert_eligible"] for c in r.false_changes) == 8
    _assert_no_missed(r)


def test_inspect_timeout_one_scan():
    got, r = _by_scan({"inspect_timeout": 1.0})
    # PROBED with no cert/headers resolves nothing (changes.py:414-417, 437), but it is a
    # PROBED baseline with no findings, so the next scan re-reports the old missing headers
    # (changes.py:368-395) on api (CSP) and shop (HSTS).
    assert got == Counter({
        (3, "HOST_RISK_BAND_DECREASED"): 2,
        (4, "SECURITY_HEADER_REMOVED"): 2, (4, "HOST_RISK_BAND_INCREASED"): 2,
    })
    _assert_no_missed(r)


def test_unknown_noise_class_is_rejected():
    with pytest.raises(ValueError):
        harness.Noise({"dns_typo": 1.0}, 1)


def test_cli_output_is_byte_identical(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    main(["--seed", "5", "--seeds", "1", "--out", str(a)])
    main(["--seed", "5", "--seeds", "1", "--out", str(b)])
    names = sorted(p.name for p in a.iterdir())
    assert names == ["detections.csv", "false_changes.csv", "runs.csv", "summary.md"]
    for n in names:
        assert (a / n).read_bytes() == (b / n).read_bytes()


def test_candidate_sustained_https_loss_detected_with_deliberate_delay():
    """Supplemental replay test: genuine sustained HTTPS loss is detected with 1-scan delay.

    Verifies that:
    1. Scan T (first failure after SUCCESS): 0 HTTPS_LOST emitted (suppresses transient noise).
    2. Scan T+1 (second consecutive failure): 1 HTTPS_LOST emitted with baseline pointing to T-1.
    3. Scan T+2 (third consecutive failure): 0 duplicate HTTPS_LOST emitted (emits once on entry).
    """
    import copy

    clean_noise = harness.Noise({}, seed=1)
    base_truth = harness.truth_at(0)
    s0 = harness.observe(base_truth, 0, clean_noise)

    def _make_fail_scan(t: int) -> dict:
        obs = harness.observe(base_truth, t, clean_noise)
        obs_copy = copy.deepcopy(obs)
        for h in obs_copy["probe"]["results"]:
            if h["subdomain"] == "api.example.com":
                h["https"] = {"reachable": False, "error_type": "CONNECT_ERROR"}
        return obs_copy

    s1 = _make_fail_scan(1)
    s2 = _make_fail_scan(2)
    s3 = _make_fail_scan(3)

    # Scan 1 (first failure): history is [s0] -> 0 HTTPS_LOST
    c1 = harness.candidate_compare([s0], s1)
    assert not any(c["change_type"] == "HTTPS_LOST" for c in c1)

    # Scan 2 (second consecutive failure): history is [s1, s0] -> 1 HTTPS_LOST
    c2 = harness.candidate_compare([s1, s0], s2)
    lost2 = [c for c in c2 if c["change_type"] == "HTTPS_LOST"]
    assert len(lost2) == 1
    assert lost2[0]["asset"] == "api.example.com"
    assert lost2[0]["baseline_scan_run_id"] == -2  # points to s0 (prior success)

    # Scan 3 (third consecutive failure): history is [s2, s1, s0] -> 0 repeated events
    c3 = harness.candidate_compare([s2, s1, s0], s3)
    lost3 = [c for c in c3 if c["change_type"] == "HTTPS_LOST"]
    assert len(lost3) == 0


def test_g3_5_replay_candidate_runs_production_persistent_inventory():
    """G3.5: replay_candidate must run production persistent discovery inventory.

    Before G3.5, replay_candidate invoked candidate_compare without persisted_inventory,
    which evicted historical hosts after 3 scans and missed Seed 43's subdomain_removed.
    With production persistent inventory, Seed 43's subdomain_removed is detected at scan 14.
    """
    res = harness.replay_candidate(harness.REALISTIC, seed=43)
    assert res.detected["subdomain_removed"] == 14


def test_g3_5_replay_candidate_parity_with_adapter():
    """G3.5: replay_candidate and adapter_persistent_discovery produce identical results."""
    from experiments.change_replay.adapter_persistent_discovery import (
        run_persistent_discovery_replay,
    )

    for seed in (1, 2, 43, 79):
        res_cand = harness.replay_candidate(harness.REALISTIC, seed=seed)
        res_adap = run_persistent_discovery_replay(harness.REALISTIC, seed=seed)
        assert res_cand.asset_scans == res_adap.asset_scans
        assert res_cand.detected == res_adap.detected
        assert res_cand.false_changes == res_adap.false_changes


def test_g3_5_replay_candidate_passes_positive_scan_ids_and_production_allow_removal(
    monkeypatch,
):
    """G3.5: replay_candidate passes positive monotonic scan IDs and production allow_removal."""
    recorded_calls: list[dict[str, Any]] = []
    orig_detect = asm.changes.detect_changes

    def spy_detect(*args, **kwargs):
        recorded_calls.append(
            {
                "allow_removal": kwargs.get("allow_removal"),
                "baseline_scan_run_id": kwargs.get("baseline_scan_run_id"),
                "current_scan_run_id": kwargs.get("current_scan_run_id"),
                "hist_ids": [
                    h.get("scan_run_id")
                    for h in (kwargs.get("historical_baselines") or [])
                ],
            }
        )
        return orig_detect(*args, **kwargs)

    monkeypatch.setattr(harness, "detect_changes", spy_detect)

    # Replay 3 scans with ct_truncated in scan 2
    harness.replay_candidate(
        {"ct_truncated": 1.0},
        seed=1,
        n_scans=4,
        noise_scans={2},
    )

    # Check that historical scan IDs are non-negative and match baseline_scan_run_id
    for call in recorded_calls:
        b_id = call["baseline_scan_run_id"]
        c_id = call["current_scan_run_id"]
        hist_ids = call["hist_ids"]
        assert c_id > b_id >= 0, f"Expected c_id ({c_id}) > b_id ({b_id}) >= 0"
        for hid in hist_ids:
            assert hid >= 0, f"Expected non-negative historical ID, got: {hid}"
        if hist_ids:
            assert hist_ids[0] == b_id, f"Expected hist_ids[0] ({hist_ids[0]}) == b_id ({b_id})"

    # Check scan 2 (noise_scans={2}): noisy call has allow_removal == False
    scan2_calls = [c for c in recorded_calls if c["current_scan_run_id"] == 2]
    assert len(scan2_calls) == 2  # clean and noisy
    assert False in [c["allow_removal"] for c in scan2_calls]


def test_scanner_benchmark_gates_adr_alignment(tmp_path):
    """ADR 0001: benchmark stop-rule gates enforce owner contract and honest reporting."""
    from experiments.change_replay.run import (
        MAX_ALERT_FALSE_PER_1000,
        MAX_MISSED,
        main,
    )

    assert MAX_ALERT_FALSE_PER_1000 == 0.1
    assert MAX_MISSED == 0

    out_dir = tmp_path / "replay_out"
    main(["--candidate", "--seed", "1", "--seeds", "3", "--out", str(out_dir)])

    summary_text = (out_dir / "summary.md").read_text(encoding="utf-8")
    assert "- informational false changes per 1,000:" in summary_text
    assert "(report-only)" in summary_text
    assert "- alert-eligible false per 1,000 <= 0.1:" in summary_text
    assert "- missed real events <= 0: pass" in summary_text


def test_seed_79_port_closure_matches_under_owner_rule():
    """Seed 79: scan 19 early emission matches scan 20 port_closed when unreversed."""
    from experiments.change_replay.harness import REALISTIC, replay_candidate

    res = replay_candidate(REALISTIC, 79)
    # port_closed was emitted at scan 19 (one scan early) and unreversed through scan 20
    assert res.detected["port_closed"] == 19
    missed = sum(v is None for v in res.detected.values())
    assert missed == 0


def test_benchmark_matching_rule_early_emission_unreversed_and_reversed():
    """Matching rule matches at most 1 scan early if unreversed, but rejects if reversed."""
    from experiments.change_replay.harness import (
        Event,
        _is_state_reversed,
        _matches_event,
    )

    ev = Event(
        1, "port_closed", "api.example.com", "ports", {},
        ("PORT_NO_LONGER_OPEN", "api.example.com", "5432"),
    )

    # Case A: unreversed (port remains closed at scan 1)
    noisy_unreversed = [
        {},  # scan 0
        {"portscan": {"results": [{"subdomain": "api.example.com", "open_ports": []}]}},  # scan 1
    ]
    assert not _is_state_reversed(noisy_unreversed, 0, 1, ev.key)
    assert _matches_event(ev, ev.key, 0, noisy_unreversed)

    # Case B: reversed (port reopened at scan 1)
    port_open_res = [{"port": 5432, "state": "OPEN"}]
    noisy_reversed = [
        {},  # scan 0
        {"portscan": {"results": [{"subdomain": "api.example.com", "open_ports": port_open_res}]}},
    ]
    assert _is_state_reversed(noisy_reversed, 0, 1, ev.key)
    assert not _matches_event(ev, ev.key, 0, noisy_reversed)

    # Case C: 2 scans early (scan 0 for event at scan 2) -> never matches
    ev2 = Event(
        2, "port_closed", "api.example.com", "ports", {},
        ("PORT_NO_LONGER_OPEN", "api.example.com", "5432"),
    )
    assert not _matches_event(ev2, ev2.key, 0, noisy_unreversed)



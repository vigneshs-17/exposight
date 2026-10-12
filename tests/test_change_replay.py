"""E-1a replay harness: pins P0's actual behaviour under each noise class (no DB, no network).

Each noise test injects one transient at probability 1 in scan 3 only (before the first
labelled event at scan 5), so scan 3 compares clean->noisy and scan 4 noisy->clean.
"""

from __future__ import annotations

import inspect
from collections import Counter

import pytest

import asm.changes
from experiments.change_replay import harness
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
    src = inspect.getsource(harness)
    assert "def detect_changes" not in src and "def evaluate_removal_eligibility" not in src

    calls = []

    def spy_detect(baseline, new, allow_removal=True):
        calls.append(allow_removal)
        return asm.changes.detect_changes(baseline, new, allow_removal=allow_removal)

    monkeypatch.setattr(harness, "detect_changes", spy_detect)
    clean = harness.Noise({}, 1)
    base = harness.observe(harness.truth_at(0), 0, clean)
    truncated = harness.observe(harness.truth_at(1), 1, harness.Noise({"ct_truncated": 1.0}, 1))
    harness.p0_compare(base, harness.observe(harness.truth_at(1), 1, clean))
    harness.p0_compare(base, truncated)
    # allow_removal comes from evaluate_removal_eligibility, as in the worker
    assert calls == [True, False]


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

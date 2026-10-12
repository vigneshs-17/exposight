"""Ground truth, noise model, report builder and P0 runner for the change-detection replay.

Reports are built with the production report dataclasses (asm.models) and their to_dict(),
in the order and shape asm/worker/runner.py::DirectScannerRunner produces them:
probe and portscan only receive hosts that resolved in discover, inspect walks the probe
results, and the score report is score_domain_payloads(...).to_dict().

P0 is production change detection, called exactly as
asm/worker/worker.py::Worker._perform_change_detection does (see p0_compare).
"""

from __future__ import annotations

import copy
import hashlib
import json
import random
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from asm.changes import detect_changes, evaluate_removal_eligibility
from asm.headers_inspect import extract_header_info
from asm.models import (
    CertInfo,
    DiscoveryReport,
    HostInspectResult,
    HostPortScanResult,
    HostProbeResult,
    InspectReport,
    PortResult,
    PortScanReport,
    ProbeReport,
    SubdomainResult,
    UrlProbeResult,
)
from asm.portscan import DEFAULT_PORTS, PORT_SERVICES, compute_risk_flags
from asm.scoring import TIER_RANK, score_domain_payloads

DOMAIN = "example.com"
N_SCANS = 30
START = datetime(2026, 1, 1, tzinfo=UTC)

NOISE_CLASSES = (
    "dns_timeout",  # a: resolver times out for one host in one scan
    "dns_nxdomain",  # a: transient NXDOMAIN for one host in one scan
    "ct_partial",  # b: CT answers with fewer names, report not marked truncated
    "ct_truncated",  # b: crt.sh fails, Cert Spotter fallback is capped (truncated=True)
    "port_flap_filtered",  # c: an open port times out (packet loss) in one scan
    "port_flap_closed",  # c: an open port answers RST (rate-limit reset) in one scan
    "cdn_edge",  # d: CDN host answers from another edge: other IP, other valid cert
    "probe_https_fail",  # e: HTTPS connect error for one host (HTTP still answers)
    "inspect_timeout",  # e: probe saw HTTPS, the inspect connection then timed out
)

# Fixed in STATUS.md (E-1a plan) before any result was produced. Priors, not measurements.
REALISTIC: dict[str, float] = {
    "dns_timeout": 0.01,
    "dns_nxdomain": 0.002,
    "ct_partial": 0.02,
    "ct_truncated": 0.02,
    "port_flap_filtered": 0.01,
    "port_flap_closed": 0.005,
    "cdn_edge": 0.10,
    "probe_https_fail": 0.005,
    "inspect_timeout": 0.005,
}

ALL_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
    "Content-Security-Policy": "default-src 'self'",
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "strict-origin-when-cross-origin",
    "Permissions-Policy": "geolocation=()",
}
CDN_ALT_IP = "198.51.100.77"
CDN_ALT_CERT = ("Google Trust Services WE1", "2027-02-15T00:00:00+00:00")
WEB = {80: None, 443: None}
SSH = "SSH-2.0-OpenSSH_9.6"


def _without(headers: dict[str, str], name: str) -> dict[str, str]:
    return {k: v for k, v in headers.items() if k != name}


@dataclass
class Host:
    """Ground-truth state of one name at one scan."""

    name: str
    ip: str
    in_ct: bool = True
    resolves: bool = True
    cdn: bool = False
    https: bool = True
    http: bool = True
    ports: dict[int, str | None] = field(default_factory=lambda: dict(WEB))  # open -> banner
    issuer: str = "Let's Encrypt R11"
    not_after: str = "2027-03-01T00:00:00+00:00"
    headers: dict[str, str] = field(default_factory=lambda: dict(ALL_HEADERS))


def initial_hosts() -> dict[str, Host]:
    hosts = [
        Host("example.com", "203.0.113.10"),
        Host("www.example.com", "203.0.113.11", cdn=True),
        Host("api.example.com", "203.0.113.12", ports={22: SSH, **WEB},
             headers=_without(ALL_HEADERS, "Content-Security-Policy")),
        Host("app.example.com", "203.0.113.13"),
        Host("shop.example.com", "203.0.113.14", cdn=True,
             headers=_without(ALL_HEADERS, "Strict-Transport-Security")),
        Host("static.example.com", "203.0.113.15", cdn=True),
        Host("mail.example.com", "203.0.113.16", http=False,
             ports={25: "220 mail.example.com ESMTP", 143: "* OK IMAP4 ready", 443: None}),
        Host("db.example.com", "203.0.113.17", https=False, http=False,
             ports={3306: "5.7.42-log"}),
        Host("vpn.example.com", "203.0.113.18", http=False, ports={22: SSH, 443: None}),
        Host("dev.example.com", "203.0.113.19", ports={22: SSH, **WEB}),
        Host("staging.example.com", "203.0.113.20"),
        Host("legacy.example.com", "203.0.113.21", resolves=False),
        Host("beta.example.com", "203.0.113.22", in_ct=False),
    ]
    return {h.name: h for h in hosts}


@dataclass(frozen=True)
class Event:
    """A labelled real change: from `scan` on, `host.attr == value`; P0 must emit `key`."""

    scan: int
    name: str
    host: str
    attr: str
    value: Any
    key: tuple[str, str, str]  # (change_type, asset, detail)


EVENTS: tuple[Event, ...] = (
    Event(5, "subdomain_added", "beta.example.com", "in_ct", True,
          ("NEW_SUBDOMAIN", "beta.example.com", "")),
    Event(8, "port_opened", "api.example.com", "ports", {22: SSH, **WEB, 5432: None},
          ("PORT_NEWLY_OPEN", "api.example.com", "5432")),
    Event(11, "subdomain_removed", "staging.example.com", "in_ct", False,
          ("REMOVED_SUBDOMAIN", "staging.example.com", "")),
    Event(14, "cert_rotated", "www.example.com", "not_after", "2027-06-01T00:00:00+00:00",
          ("CERTIFICATE_CHANGED", "www.example.com", "not_after")),
    Event(17, "header_removed", "app.example.com", "headers",
          _without(ALL_HEADERS, "Content-Security-Policy"),
          ("SECURITY_HEADER_REMOVED", "app.example.com", "Content-Security-Policy")),
    Event(20, "port_closed", "api.example.com", "ports", {22: SSH, **WEB},
          ("PORT_NO_LONGER_OPEN", "api.example.com", "5432")),
    Event(22, "header_added", "shop.example.com", "headers", dict(ALL_HEADERS),
          ("SECURITY_HEADER_ADDED", "shop.example.com", "Strict-Transport-Security")),
    Event(25, "stopped_resolving", "dev.example.com", "resolves", False,
          ("STOPPED_RESOLVING", "dev.example.com", "")),
    Event(27, "cert_issuer_changed", "vpn.example.com", "issuer",
          "DigiCert Global G2 TLS RSA SHA256 2020 CA1",
          ("CERTIFICATE_CHANGED", "vpn.example.com", "issuer")),
)


def truth_at(t: int) -> dict[str, Host]:
    hosts = initial_hosts()
    for ev in EVENTS:
        if ev.scan <= t:
            setattr(hosts[ev.host], ev.attr, copy.deepcopy(ev.value))
    return hosts


class Noise:
    """Independent seeded stream per noise class, so one class never shifts another's draws."""

    def __init__(self, probs: dict[str, float], seed: int) -> None:
        unknown = set(probs) - set(NOISE_CLASSES)
        if unknown:
            raise ValueError(f"unknown noise classes: {sorted(unknown)}")
        self.probs = {c: probs.get(c, 0.0) for c in NOISE_CLASSES}
        # str seeds are hashed with SHA-512 by random.seed: stable across runs and platforms
        self.rngs = {c: random.Random(f"{seed}:{c}") for c in NOISE_CLASSES}
        self.fired: Counter[str] = Counter()

    def fires(self, cls: str) -> bool:
        p = self.probs[cls]
        if p <= 0:
            return False
        hit = self.rngs[cls].random() < p
        if hit:
            self.fired[cls] += 1
        return hit

    def subset(self, cls: str, names: list[str]) -> list[str]:
        rng = self.rngs[cls]
        k = max(1, round(len(names) * rng.uniform(0.7, 0.9)))
        return sorted(rng.sample(names, k))


def _ts(t: int, minute: int = 0) -> str:
    return (START + timedelta(days=t, minutes=minute)).isoformat()


def _cert(name: str, issuer: str, not_after: str, t: int) -> CertInfo:
    days = (datetime.fromisoformat(not_after) - (START + timedelta(days=t))).days
    serial = hashlib.sha256(f"{issuer}|{not_after}".encode()).hexdigest()[:16]
    return CertInfo(
        subject_cn=name, sans=[name], issuer=issuer, not_before="2026-01-01T00:00:00+00:00",
        not_after=not_after, days_until_expiry=float(days), serial_hex=serial,
        tls_version="TLSv1.3", hostname_matches=True, is_trusted=True, source="from_response",
        expiring_soon=days <= 30,
    )


def observe(truth: dict[str, Host], t: int, noise: Noise) -> dict[str, dict[str, Any]]:
    """Build the five stage reports one scan would store, with noise applied."""
    # discover
    names = sorted(n for n, h in truth.items() if h.in_ct)
    source, fallback, truncated = "crt.sh", None, False
    if noise.fires("ct_partial"):
        names = noise.subset("ct_partial", names)
    if noise.fires("ct_truncated"):
        names = noise.subset("ct_truncated", names)
        source, fallback, truncated = "certspotter", "crt.sh returned HTTP 502", True
    subs: list[SubdomainResult] = []
    edge: set[str] = set()
    for n in names:
        h = truth[n]
        status, ips = ("RESOLVED", [h.ip]) if h.resolves else ("NXDOMAIN", [])
        if h.resolves:
            if noise.fires("dns_timeout"):
                status, ips = "TIMEOUT", []
            elif noise.fires("dns_nxdomain"):
                status, ips = "NXDOMAIN", []
            elif h.cdn and noise.fires("cdn_edge"):
                edge.add(n)
                ips = [CDN_ALT_IP]
        subs.append(SubdomainResult(subdomain=n, ip_addresses=ips, status=status,
                                    resolved=bool(ips)))
    resolved = sum(s.resolved for s in subs)
    discover = DiscoveryReport(
        domain=DOMAIN, scan_started_utc=_ts(t), scan_finished_utc=_ts(t, 1), source=source,
        fallback_reason=fallback, truncated=truncated,
        counts={"total_discovered": len(subs), "resolved": resolved,
                "unresolved": len(subs) - resolved},
        results=subs,
    ).to_dict()

    # probe and portscan: only hosts that resolved in discover (runner.run_probe/run_portscan)
    live_names = [s.subdomain for s in subs if s.resolved]
    probes: list[HostProbeResult] = []
    scans: list[HostPortScanResult] = []
    for n in live_names:
        h = truth[n]
        https_ok = h.https and not noise.fires("probe_https_fail")
        https = (UrlProbeResult(url=f"https://{n}/", reachable=True, status_code=200,
                                final_url=f"https://{n}/", response_time_ms=40.0, tls_valid=True)
                 if https_ok else
                 UrlProbeResult(url=f"https://{n}/", error_type="CONNECT_ERROR",
                                error_message="Connection refused"))
        http = (UrlProbeResult(url=f"http://{n}/", reachable=True, status_code=200,
                               final_url=f"http://{n}/", response_time_ms=30.0)
                if h.http else
                UrlProbeResult(url=f"http://{n}/", error_type="CONNECT_ERROR",
                               error_message="Connection refused"))
        probes.append(HostProbeResult(
            subdomain=n, https=https, http=http, live=https_ok or h.http,
            preferred_url=https.url if https_ok else (http.url if h.http else None),
        ))
        open_ports: list[PortResult] = []
        closed: list[int] = []
        filtered: list[int] = []
        for port in DEFAULT_PORTS:
            if port not in h.ports:
                closed.append(port)
            elif noise.fires("port_flap_filtered"):
                filtered.append(port)
            elif noise.fires("port_flap_closed"):
                closed.append(port)
            else:
                open_ports.append(PortResult(
                    port=port, state="OPEN",
                    service_guess=f"{PORT_SERVICES.get(port, 'unknown')} (guess by port)",
                    banner=h.ports[port], risk_flags=compute_risk_flags(port),
                    response_time_ms=12.0,
                ))
        scans.append(HostPortScanResult(
            subdomain=n, open_ports=open_ports, closed_ports=closed, filtered_ports=filtered,
            risk_flags=sorted({f for p in open_ports for f in p.risk_flags}),
        ))
    probe = ProbeReport(domain=DOMAIN, source_report="discover_report",
                        probe_started_utc=_ts(t, 1), probe_finished_utc=_ts(t, 2),
                        results=probes).to_dict()
    portscan = PortScanReport(domain=DOMAIN, source_report="discover_report",
                              scan_started_utc=_ts(t, 2), scan_finished_utc=_ts(t, 3),
                              port_list_used=DEFAULT_PORTS, results=scans).to_dict()

    # inspect: walks the probe results (headers_inspect.run_inspection)
    inspected: list[HostInspectResult] = []
    for p in probes:
        h = truth[p.subdomain]
        if p.https is None or not p.https.reachable:
            inspected.append(HostInspectResult(
                subdomain=p.subdomain, status="SKIPPED_NOT_HTTPS",
                skip_reason="Host was not reachable over HTTPS in probe report"))
        elif noise.fires("inspect_timeout"):
            inspected.append(HostInspectResult(
                subdomain=p.subdomain,
                skip_reason="Port 443 / HTTPS unreachable or connection timed out"))
        else:
            issuer, not_after = CDN_ALT_CERT if p.subdomain in edge else (h.issuer, h.not_after)
            inspected.append(HostInspectResult(
                subdomain=p.subdomain, cert=_cert(p.subdomain, issuer, not_after, t),
                headers=extract_header_info(dict(h.headers))))
    inspect = InspectReport(domain=DOMAIN, source_report="probe_report",
                            inspect_started_utc=_ts(t, 3), inspect_finished_utc=_ts(t, 4),
                            results=inspected).to_dict()

    score = score_domain_payloads(
        target_domain=DOMAIN, disc_results=discover["results"], probe_results=probe["results"],
        portscan_results=portscan["results"], inspect_results=inspect["results"],
    ).to_dict()
    score["generated_utc"] = _ts(t, 5)  # pinned: production uses now()
    return {"discover": discover, "probe": probe, "portscan": portscan, "inspect": inspect,
            "score": score}


def p0_compare(
    baseline_reports: dict[str, dict[str, Any]], new_reports: dict[str, dict[str, Any]]
) -> list[dict[str, Any]]:
    """P0: asm/worker/worker.py Worker._perform_change_detection, lines 1135-1142."""
    # The worker reads the baseline back from scan_results (JSONB); new_reports is in memory.
    baseline_reports = json.loads(json.dumps(baseline_reports))
    base_disc = baseline_reports.get("discover") or {}
    new_disc = new_reports.get("discover") or {}
    allow_removal, _skip_reason = evaluate_removal_eligibility(base_disc, new_disc)
    return detect_changes(baseline_reports, new_reports, allow_removal=allow_removal)


def change_key(c: dict[str, Any]) -> tuple[str, str, str]:
    return (c["change_type"], c["asset"], c["detail"])


def alert_eligible(c: dict[str, Any]) -> bool:
    """Would trigger an alert at the default alert_min_severity (MEDIUM), per alerts/rules.py."""
    return c["category"] == "exposure" and TIER_RANK.get(c["severity"], 0) >= TIER_RANK["MEDIUM"]


@dataclass
class RunResult:
    seed: int
    asset_scans: int
    false_changes: list[dict[str, Any]]
    detected: dict[str, int | None]  # event name -> scan it was detected in (None = missed)
    noise_fired: Counter[str]


def replay(
    probs: dict[str, float],
    seed: int,
    n_scans: int = N_SCANS,
    noise_scans: set[int] | None = None,
) -> RunResult:
    """Replay n_scans consecutive scans; classify every P0 change as true or false.

    A change is true when its key is in the noise-free diff of the same scan pair, or it
    is the first sighting of a labelled event that has happened and is not yet detected
    (delayed detection). Everything else is false. noise_scans limits noise to those
    scans (None = every scan); the tests use it to inject exactly one transient.
    """
    noise = Noise(probs, seed)
    truths = [truth_at(t) for t in range(n_scans)]
    clean = [observe(truths[t], t, Noise({}, seed)) for t in range(n_scans)]
    quiet = Noise({}, seed)
    noisy = [observe(truths[t], t, noise if noise_scans is None or t in noise_scans else quiet)
             for t in range(n_scans)]
    detected: dict[str, int | None] = {ev.name: None for ev in EVENTS if ev.scan < n_scans}
    false_changes: list[dict[str, Any]] = []
    asset_scans = 0
    for t in range(1, n_scans):
        asset_scans += sum(h.in_ct for h in truths[t].values())
        clean_keys = {change_key(c) for c in p0_compare(clean[t - 1], clean[t])}
        for c in p0_compare(noisy[t - 1], noisy[t]):
            k = change_key(c)
            ev = next((e for e in EVENTS if e.key == k and e.scan <= t
                       and e.name in detected and detected[e.name] is None), None)
            if ev is not None:
                detected[ev.name] = t
            elif k not in clean_keys:
                false_changes.append({"scan": t, "change_type": c["change_type"],
                                      "asset": c["asset"], "detail": c["detail"],
                                      "severity": c["severity"], "category": c["category"],
                                      "alert_eligible": alert_eligible(c)})
    # detect_changes walks a set of host names (changes.py:304), so its output order varies
    # with PYTHONHASHSEED; sort to keep results byte-identical across processes.
    false_changes.sort(key=lambda c: (c["scan"], c["change_type"], c["asset"], c["detail"]))
    return RunResult(seed, asset_scans, false_changes, detected, noise.fired)

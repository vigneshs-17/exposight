"""Disposable-PostgreSQL regression tests for persistent discovery inventory (v3.7).

Covers:
- Seed-43 recovery
- Prolonged unknown coverage
- Source changes
- Partial positive observations
- Removal and reappearance
- Duplicate processing & idempotency
- Rollback on failure
- Tenant isolation
- Bootstrap / no NEW_SUBDOMAIN flood
- Retention / scan deletion safety (SET NULL)
- Capacity boundaries & tombstone pruning
"""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from asm.db.models import Domain, DomainSubdomain, Organization, ScanChange, ScanRun, ScanStage
from asm.worker.worker import ASMWorker, LostLeaseError

pytestmark = pytest.mark.db


def _make_report(
    subs: list[dict[str, Any]], source: str = "crt.sh", truncated: bool = False
) -> dict[str, Any]:
    return {
        "discover": {
            "domain": "example.com",
            "source": source,
            "truncated": truncated,
            "results": subs,
        },
        "probe": {"results": []},
        "portscan": {"results": []},
        "inspect": {"results": []},
        "score": {
            "domain": "example.com",
            "domain_band": "LOW",
            "domain_score": 0,
            "generated_utc": "2026-10-17T12:00:00Z",
        },
    }


def _setup_domain(
    session: Session, name: str = "inv-test.example.com", org_name: str = "Inv Org"
) -> tuple[int, int]:
    org = session.query(Organization).filter_by(name=org_name).first()
    if not org:
        org = Organization(name=org_name)
        session.add(org)
        session.flush()

    domain = session.query(Domain).filter_by(name=name).first()
    if not domain:
        domain = Domain(org_id=org.id, name=name, verification_status="verified")
        session.add(domain)
        session.flush()

    session.commit()
    return org.id, domain.id


def _queue_scan(session: Session, domain_id: int) -> int:
    run = ScanRun(domain_id=domain_id, status="queued")
    session.add(run)
    session.flush()
    for st in ("discover", "probe", "portscan", "inspect", "score"):
        session.add(ScanStage(scan_run_id=run.id, stage=st, status="pending"))
    session.commit()
    return run.id


class ScriptedRunner:
    def __init__(self, reports_list: list[dict[str, Any]]) -> None:
        self.reports_list = reports_list
        self.idx = 0

    def _next(self) -> dict[str, Any]:
        rep = self.reports_list[min(self.idx, len(self.reports_list) - 1)]
        self.idx += 1
        return rep

    def run_discover(self, domain: str) -> dict[str, Any]:
        return self._next()["discover"]

    def run_probe(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return {"results": []}

    def run_portscan(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return {"results": []}

    def run_inspect(
        self, domain: str, probe_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return {"results": []}

    def run_score(self, domain: str, **kwargs: Any) -> dict[str, Any]:
        return {
            "domain": domain,
            "domain_band": "LOW",
            "domain_score": 0,
            "generated_utc": "2026-10-17T12:00:00Z",
        }


def test_seed_43_recovery_db(clean_db, db_engine):
    """Demonstrate exact Seed 43 recovery in PostgreSQL.

    Scan 10: crt.sh (clean). staging.example.com present.
    Scan 11: certspotter (truncated). Inconclusive.
    Scan 12: certspotter (truncated). Inconclusive.
    Scan 13: crt.sh (clean). Absence 1.
    Scan 14: crt.sh (clean). Absence 2 -> REMOVED_SUBDOMAIN emitted!
    """
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "seed43-db.example.com")

    p_staging = {"subdomain": "staging.example.com", "status": "RESOLVED", "resolved": True}
    p_api = {"subdomain": "api.example.com", "status": "RESOLVED", "resolved": True}

    rep_10 = _make_report([p_staging, p_api], source="crt.sh", truncated=False)
    rep_11 = _make_report([p_api], source="certspotter", truncated=True)
    rep_12 = _make_report([p_api], source="certspotter", truncated=True)
    rep_13 = _make_report([p_api], source="crt.sh", truncated=False)
    rep_14 = _make_report([p_api], source="crt.sh", truncated=False)

    runner = ScriptedRunner([rep_10, rep_11, rep_12, rep_13, rep_14])
    worker = ASMWorker(db_engine, runner=runner)

    # Execute Scans 10-14
    run_ids = []
    for _ in range(5):
        with Session(db_engine) as session:
            r_id = _queue_scan(session, domain_id)
            run_ids.append(r_id)
        worker.run_poll_cycle()

    with Session(db_engine) as session:
        # Scan 14 (run_ids[4]) must have emitted REMOVED_SUBDOMAIN for staging.example.com
        changes = session.query(ScanChange).filter_by(scan_run_id=run_ids[4]).all()
        removals = [
            c
            for c in changes
            if c.change_type == "REMOVED_SUBDOMAIN" and c.asset == "staging.example.com"
        ]
        assert len(removals) == 1, "Seed 43 recovery: REMOVED_SUBDOMAIN emitted at Scan 14"
        assert removals[0].baseline_scan_run_id == run_ids[0]

        # Verify persistent inventory table state
        sub_row = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="staging.example.com")
            .first()
        )
        assert sub_row is not None
        assert sub_row.status == "removed"
        assert sub_row.removed_at_scan_run_id == run_ids[4]
        assert sub_row.consecutive_qualifying_absences == 2


def test_prolonged_unknown_coverage_db(clean_db, db_engine):
    """5 consecutive truncated fallback scans do not lose anchor presence."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "prolonged-unknown.example.com")

    p_target = {"subdomain": "target.example.com", "status": "RESOLVED", "resolved": True}
    p_anchor = {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}

    rep_pres = _make_report([p_target, p_anchor], source="crt.sh", truncated=False)
    rep_trunc = _make_report([p_anchor], source="certspotter", truncated=True)
    rep_abs = _make_report([p_anchor], source="crt.sh", truncated=False)

    reports = [rep_pres] + [rep_trunc] * 5 + [rep_abs, rep_abs]
    runner = ScriptedRunner(reports)
    worker = ASMWorker(db_engine, runner=runner)

    run_ids = []
    for _ in range(len(reports)):
        with Session(db_engine) as session:
            r_id = _queue_scan(session, domain_id)
            run_ids.append(r_id)
        worker.run_poll_cycle()

    with Session(db_engine) as session:
        final_run_id = run_ids[-1]
        changes = session.query(ScanChange).filter_by(scan_run_id=final_run_id).all()
        removals = [
            c
            for c in changes
            if c.change_type == "REMOVED_SUBDOMAIN" and c.asset == "target.example.com"
        ]
        assert len(removals) == 1
        assert removals[0].baseline_scan_run_id == run_ids[0]


def test_source_changes_db(clean_db, db_engine):
    """Absence from an incomparable provider does not increment absence counter."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "source-change.example.com")

    p1 = {"subdomain": "sub.example.com", "status": "RESOLVED", "resolved": True}
    p_anchor = {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}

    rep_crt = _make_report([p1, p_anchor], source="crt.sh", truncated=False)
    rep_cs_abs = _make_report([p_anchor], source="certspotter", truncated=False)

    runner = ScriptedRunner([rep_crt, rep_cs_abs])
    worker = ASMWorker(db_engine, runner=runner)

    with Session(db_engine) as session:
        _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        r2 = _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        sub_row = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="sub.example.com")
            .first()
        )
        assert sub_row.status == "active"
        assert sub_row.consecutive_qualifying_absences == 0
        changes = session.query(ScanChange).filter_by(scan_run_id=r2).all()
        assert not any(c.change_type == "REMOVED_SUBDOMAIN" for c in changes)


def test_partial_positive_observations_db(clean_db, db_engine):
    """Positive observation in a truncated scan resets absence counter and maintains presence."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "partial-pos.example.com")

    p1 = {"subdomain": "live.example.com", "status": "RESOLVED", "resolved": True}
    p_anchor = {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}

    rep1 = _make_report([p1, p_anchor], source="crt.sh", truncated=False)
    rep2_abs1 = _make_report([p_anchor], source="crt.sh", truncated=False)
    # Scan 3: truncated certspotter, but live.example.com IS returned in the partial list!
    rep3_trunc_pres = _make_report([p1], source="certspotter", truncated=True)
    # Scan 4: crt.sh absent again -> should be absence 1, not absence 2!
    rep4_abs = _make_report([p_anchor], source="crt.sh", truncated=False)

    runner = ScriptedRunner([rep1, rep2_abs1, rep3_trunc_pres, rep4_abs])
    worker = ASMWorker(db_engine, runner=runner)

    run_ids = []
    for _ in range(4):
        with Session(db_engine) as session:
            run_ids.append(_queue_scan(session, domain_id))
        worker.run_poll_cycle()

    with Session(db_engine) as session:
        sub_row = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="live.example.com")
            .first()
        )
        assert sub_row.status == "active"
        # Absence was reset on scan 3, so scan 4 is absence 1
        assert sub_row.consecutive_qualifying_absences == 1
        changes_4 = session.query(ScanChange).filter_by(scan_run_id=run_ids[3]).all()
        assert not any(c.change_type == "REMOVED_SUBDOMAIN" for c in changes_4)


def test_removal_and_reappearance_db(clean_db, db_engine):
    """Confirmed removal emits REMOVED_SUBDOMAIN; later observation emits NEW_SUBDOMAIN."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "reappear.example.com")

    p_re = {"subdomain": "reappear.example.com", "status": "RESOLVED", "resolved": True}
    p_anchor = {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}

    rep1_pres = _make_report([p_re, p_anchor], source="crt.sh", truncated=False)
    rep2_abs1 = _make_report([p_anchor], source="crt.sh", truncated=False)
    rep3_abs2 = _make_report([p_anchor], source="crt.sh", truncated=False)
    rep4_reappear = _make_report([p_re, p_anchor], source="crt.sh", truncated=False)

    runner = ScriptedRunner([rep1_pres, rep2_abs1, rep3_abs2, rep4_reappear])
    worker = ASMWorker(db_engine, runner=runner)

    run_ids = []
    for _ in range(4):
        with Session(db_engine) as session:
            run_ids.append(_queue_scan(session, domain_id))
        worker.run_poll_cycle()

    with Session(db_engine) as session:
        # Scan 3: removal
        ch_3 = session.query(ScanChange).filter_by(scan_run_id=run_ids[2]).all()
        assert any(
            c.change_type == "REMOVED_SUBDOMAIN" and c.asset == "reappear.example.com" for c in ch_3
        )

        # Scan 4: reappearance emits NEW_SUBDOMAIN
        ch_4 = session.query(ScanChange).filter_by(scan_run_id=run_ids[3]).all()
        assert any(
            c.change_type == "NEW_SUBDOMAIN" and c.asset == "reappear.example.com" for c in ch_4
        )

        sub_row = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="reappear.example.com")
            .first()
        )
        assert sub_row.status == "active"
        assert sub_row.consecutive_qualifying_absences == 0
        assert sub_row.removed_at_scan_run_id is None


def test_duplicate_processing_and_idempotency_db(clean_db, db_engine):
    """Duplicate evaluation for same scan run does not double-increment absence counter."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "idempotent.example.com")

    p_anchor = {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}
    rep1 = _make_report(
        [{"subdomain": "sub1.example.com", "status": "RESOLVED", "resolved": True}, p_anchor]
    )
    rep2 = _make_report([p_anchor])

    runner = ScriptedRunner([rep1, rep2])
    worker = ASMWorker(db_engine, runner=runner)

    with Session(db_engine) as session:
        _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        r2 = _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        sub_row = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="sub1.example.com")
            .first()
        )
        assert sub_row.consecutive_qualifying_absences == 1
        assert sub_row.last_qualifying_absence_scan_run_id == r2

    # Re-running change detection for r2 manually does not increment to 2
    summary, changes, _ = worker._perform_change_detection(r2, domain_id, rep2)
    inv = summary["_inventory_updates"]
    assert inv["sub1.example.com"]["consecutive_qualifying_absences"] == 1


def test_rollback_on_failure_db(clean_db, db_engine):
    """Worker transaction failure rolls back domain_subdomains updates."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "rollback.example.com")
        _queue_scan(session, domain_id)

    rep = _make_report(
        [{"subdomain": "uncommitted.example.com", "status": "RESOLVED", "resolved": True}]
    )
    worker = ASMWorker(db_engine, runner=ScriptedRunner([rep]))

    # Claim job and simulate fenced finalization failure
    claimed = worker.claim_next_job()
    assert claimed is not None
    run_id, claimed_domain_id, claim_token, _, _ = claimed

    with pytest.raises(LostLeaseError):
        invalid_token = uuid.uuid4()
        worker._mark_run_final(
            run_id,
            invalid_token,
            status="succeeded",
            error_msg=None,
            change_detection={
                "_inventory_updates": {
                    "uncommitted.example.com": {
                        "status": "active",
                        "anchor_source": "crt.sh",
                        "consecutive_qualifying_absences": 0,
                    }
                }
            },
            domain_id=claimed_domain_id,
        )

    with Session(db_engine) as session:
        count = session.query(DomainSubdomain).filter_by(domain_id=domain_id).count()
        assert count == 0


def test_tenant_isolation_db(clean_db, db_engine):
    """Subdomains cannot be shared or cross-associated between different tenant organizations."""
    with Session(db_engine) as session:
        org1_id, dom1_id = _setup_domain(session, "tenant1.example.com", org_name="Org 1")
        org2_id, dom2_id = _setup_domain(session, "tenant2.example.com", org_name="Org 2")

    rep1 = _make_report(
        [{"subdomain": "shared-name.example.com", "status": "RESOLVED", "resolved": True}]
    )
    rep2 = _make_report(
        [{"subdomain": "shared-name.example.com", "status": "RESOLVED", "resolved": True}]
    )

    worker1 = ASMWorker(db_engine, runner=ScriptedRunner([rep1]))
    worker2 = ASMWorker(db_engine, runner=ScriptedRunner([rep2]))

    with Session(db_engine) as session:
        _queue_scan(session, dom1_id)
    worker1.run_poll_cycle()

    with Session(db_engine) as session:
        _queue_scan(session, dom2_id)
    worker2.run_poll_cycle()

    with Session(db_engine) as session:
        dom1_subs = session.query(DomainSubdomain).filter_by(domain_id=dom1_id).all()
        dom2_subs = session.query(DomainSubdomain).filter_by(domain_id=dom2_id).all()
        assert len(dom1_subs) == 1
        assert len(dom2_subs) == 1
        assert dom1_subs[0].domain.org_id == org1_id
        assert dom2_subs[0].domain.org_id == org2_id


def test_bootstrap_no_flood_db(clean_db, db_engine):
    """Initial baseline or upgrading domain with prior scans does not flood NEW_SUBDOMAIN."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "bootstrap-noflood.example.com")

    subs = [
        {"subdomain": f"sub{i}.example.com", "status": "RESOLVED", "resolved": True}
        for i in range(5)
    ]
    rep1 = _make_report(subs, source="crt.sh", truncated=False)
    rep2 = _make_report(subs, source="crt.sh", truncated=False)

    runner = ScriptedRunner([rep1, rep2])
    worker = ASMWorker(db_engine, runner=runner)

    with Session(db_engine) as session:
        _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        r2 = _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        ch_2 = session.query(ScanChange).filter_by(scan_run_id=r2).all()
        new_sub_changes = [c for c in ch_2 if c.change_type == "NEW_SUBDOMAIN"]
        assert len(new_sub_changes) == 0

        rows = session.query(DomainSubdomain).filter_by(domain_id=domain_id, status="active").all()
        assert len(rows) == 5


def test_retention_scan_deletion_safety_db(clean_db, db_engine):
    """Purging historical scans sets scan_run_id to NULL without deleting live inventory rows."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "retention-safety.example.com")

    rep = _make_report(
        [{"subdomain": "durable.example.com", "status": "RESOLVED", "resolved": True}]
    )
    worker = ASMWorker(db_engine, runner=ScriptedRunner([rep]))

    with Session(db_engine) as session:
        r1 = _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        sub_row = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="durable.example.com")
            .first()
        )
        assert sub_row.first_seen_scan_run_id == r1
        assert sub_row.last_seen_scan_run_id == r1

        # Delete the scan run
        run_obj = session.get(ScanRun, r1)
        session.delete(run_obj)
        session.commit()

    with Session(db_engine) as session:
        # Inventory row still exists!
        sub_row = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="durable.example.com")
            .first()
        )
        assert sub_row is not None
        assert sub_row.status == "active"
        # Foreign key was safely set to NULL
        assert sub_row.first_seen_scan_run_id is None
        assert sub_row.last_seen_scan_run_id is None


def test_capacity_boundaries_and_tombstones_db(clean_db, db_engine):
    """Tombstone count is bounded and excess removed records are pruned."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "tombstone-prune.example.com")
        _queue_scan(session, domain_id)

    rep = _make_report(
        [{"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}]
    )
    worker = ASMWorker(db_engine, runner=ScriptedRunner([rep]))
    worker.run_poll_cycle()

    # Pre-seed 1005 removed tombstones
    with Session(db_engine) as session:
        for i in range(1005):
            session.add(
                DomainSubdomain(
                    domain_id=domain_id,
                    subdomain=f"old-{i:04d}.example.com",
                    status="removed",
                    anchor_source="crt.sh",
                    consecutive_qualifying_absences=2,
                )
            )
        session.commit()

    # Run another scan
    with Session(db_engine) as session:
        _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        tombstones = (
            session.query(DomainSubdomain).filter_by(domain_id=domain_id, status="removed").all()
        )
        # Bound of 1000 enforced
        assert len(tombstones) <= 1000


def test_p_a_unknown_a_resets_absence_streak_db(clean_db, db_engine):
    """P -> A -> UNKNOWN -> A: unknown resets consecutive absence streak; requires 2 consecutive."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "p-a-unk-a.example.com")

    p_target = {"subdomain": "target.example.com", "status": "RESOLVED", "resolved": True}
    p_anchor = {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}

    # Scan 1: P
    rep1_p = _make_report([p_target, p_anchor], source="crt.sh", truncated=False)
    # Scan 2: A (absence 1)
    rep2_a1 = _make_report([p_anchor], source="crt.sh", truncated=False)
    # Scan 3: UNKNOWN (truncated crt.sh)
    rep3_unk = _make_report([p_anchor], source="crt.sh", truncated=True)
    # Scan 4: A (absence 1 again, not 2!)
    rep4_a1_again = _make_report([p_anchor], source="crt.sh", truncated=False)
    # Scan 5: A (absence 2 -> confirms removal)
    rep5_a2 = _make_report([p_anchor], source="crt.sh", truncated=False)

    runner = ScriptedRunner([rep1_p, rep2_a1, rep3_unk, rep4_a1_again, rep5_a2])
    worker = ASMWorker(db_engine, runner=runner)

    run_ids = []
    # Scans 1-3
    for _ in range(3):
        with Session(db_engine) as session:
            run_ids.append(_queue_scan(session, domain_id))
        worker.run_poll_cycle()

    with Session(db_engine) as session:
        # After Scan 3 (UNKNOWN): presence anchor retained, but absence streak reset to 0
        sub_row_3 = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="target.example.com")
            .first()
        )
        assert sub_row_3.status == "active"
        assert sub_row_3.consecutive_qualifying_absences == 0

    # Scan 4 (A): streak is 1, NOT 2 -> NO removal emitted!
    with Session(db_engine) as session:
        run_ids.append(_queue_scan(session, domain_id))
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        sub_row_4 = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="target.example.com")
            .first()
        )
        assert sub_row_4.status == "active"
        assert sub_row_4.consecutive_qualifying_absences == 1
        ch_4 = session.query(ScanChange).filter_by(scan_run_id=run_ids[3]).all()
        assert not any(c.change_type == "REMOVED_SUBDOMAIN" for c in ch_4)

    # Scan 5 (A): consecutive streak is 2 -> REMOVED_SUBDOMAIN emitted!
    with Session(db_engine) as session:
        run_ids.append(_queue_scan(session, domain_id))
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        sub_row_5 = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="target.example.com")
            .first()
        )
        assert sub_row_5.status == "removed"
        assert sub_row_5.consecutive_qualifying_absences == 2
        ch_5 = session.query(ScanChange).filter_by(scan_run_id=run_ids[4]).all()
        removals = [
            c
            for c in ch_5
            if c.change_type == "REMOVED_SUBDOMAIN" and c.asset == "target.example.com"
        ]
        assert len(removals) == 1
        assert removals[0].baseline_scan_run_id == run_ids[0]


def test_active_host_capacity_boundary_and_reporting_db(clean_db, db_engine):
    """When active host capacity is reached, untracked hosts are excluded without phantom events."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "capacity-active.example.com")

    from asm.changes import detect_changes

    # Set up inventory already at capacity (e.g. 5 hosts)
    inv: dict[str, dict[str, Any]] = {
        f"host{i}.example.com": {
            "subdomain": f"host{i}.example.com",
            "status": "active",
            "anchor_source": "crt.sh",
            "consecutive_qualifying_absences": 0,
            "first_seen_scan_run_id": 1,
            "last_seen_scan_run_id": 1,
            "last_status": "RESOLVED",
            "last_resolved": True,
        }
        for i in range(5)
    }

    # New scan discovers existing 5 hosts + 2 new hosts beyond capacity
    all_hosts = [
        {"subdomain": f"host{i}.example.com", "status": "RESOLVED", "resolved": True}
        for i in range(7)
    ]
    rep = _make_report(all_hosts, source="crt.sh", truncated=False)

    changes = detect_changes(
        {},
        rep,
        persisted_inventory=inv,
        current_scan_run_id=2,
        max_active_subdomains=5,
    )

    # 1. New hosts beyond capacity were NOT admitted to inventory
    assert "host5.example.com" not in inv
    assert "host6.example.com" not in inv
    assert sum(1 for v in inv.values() if v["status"] == "active") == 5

    # 2. No NEW_SUBDOMAIN changes were emitted for untracked hosts
    assert not any(c["asset"] in ("host5.example.com", "host6.example.com") for c in changes)

    # 3. Report exposes the coverage limitation accurately
    disc = rep["discover"]
    assert disc["truncated"] is True
    assert disc["truncation_reason"] == "inventory_capacity_exceeded"
    assert disc["untracked_subdomains_count"] == 2

    # 4. Subsequent scan where untracked host disappears: NO REMOVED_SUBDOMAIN fabricated
    rep_next = _make_report(all_hosts[:5], source="crt.sh", truncated=False)
    changes_next = detect_changes(
        rep,
        rep_next,
        persisted_inventory=inv,
        current_scan_run_id=3,
        max_active_subdomains=5,
    )
    assert not any(c["change_type"] == "REMOVED_SUBDOMAIN" for c in changes_next)


def test_reappearance_after_tombstone_pruning_db(clean_db, db_engine):
    """When a tombstone is pruned, subsequent observation is treated as a new asset."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "tombstone-reappear.example.com")

    from asm.changes import detect_changes

    inv: dict[str, dict[str, Any]] = {}
    host = "ephemeral.example.com"

    # Scan 1: host present
    rep1 = _make_report([{"subdomain": host, "status": "RESOLVED", "resolved": True}])
    detect_changes({}, rep1, persisted_inventory=inv, current_scan_run_id=1, is_first_baseline=True)
    assert inv[host]["status"] == "active"

    # Scans 2 & 3: qualifying absences confirm removal
    rep_empty = _make_report(
        [{"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}]
    )
    detect_changes(rep1, rep_empty, persisted_inventory=inv, current_scan_run_id=2)
    ch_rem = detect_changes(rep_empty, rep_empty, persisted_inventory=inv, current_scan_run_id=3)
    assert any(c["change_type"] == "REMOVED_SUBDOMAIN" and c["asset"] == host for c in ch_rem)
    assert inv[host]["status"] == "removed"

    # Prune tombstone (simulating 1000+ tombstones evicted)
    del inv[host]

    # Scan 4: host reappears after tombstone pruning
    ch_reappear = detect_changes(
        rep_empty,
        _make_report([{"subdomain": host, "status": "RESOLVED", "resolved": True}]),
        persisted_inventory=inv,
        current_scan_run_id=4,
    )
    # Resulting limitation: treated as NEW_SUBDOMAIN without previous lineage link
    new_sub = next(
        c for c in ch_reappear if c["change_type"] == "NEW_SUBDOMAIN" and c["asset"] == host
    )
    assert new_sub["previous_state"] is None
    assert inv[host]["first_seen_scan_run_id"] == 4


def test_scan_deletion_preserves_absence_counting_and_idempotency_db(clean_db, db_engine):
    """Deleting referenced scan_runs preserves absence counting and duplicate protection."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "deletion-safety-absences.example.com")

    p_target = {"subdomain": "target.example.com", "status": "RESOLVED", "resolved": True}
    p_anchor = {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}

    rep1 = _make_report([p_target, p_anchor])
    rep2 = _make_report([p_anchor])
    rep3 = _make_report([p_anchor])

    runner = ScriptedRunner([rep1, rep2, rep3])
    worker = ASMWorker(db_engine, runner=runner)

    # Scan 1: initial presence
    with Session(db_engine) as session:
        r1 = _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    # Scan 2: qualifying absence 1
    with Session(db_engine) as session:
        _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    # Purge oldest scan (Scan 1) via retention policy
    with Session(db_engine) as session:
        session.delete(session.get(ScanRun, r1))
        session.commit()

    with Session(db_engine) as session:
        sub_row = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="target.example.com")
            .first()
        )
        # Scan 1 reference safely set to NULL by ondelete='SET NULL'
        assert sub_row.first_seen_scan_run_id is None
        # Absence count is preserved
        assert sub_row.consecutive_qualifying_absences == 1

        # Scan 3: qualifying absence 2 -> confirms removal despite deleted Scan 1!
        r3 = _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        sub_row = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="target.example.com")
            .first()
        )
        assert sub_row.status == "removed"
        assert sub_row.consecutive_qualifying_absences == 2

        # Re-evaluating Scan 3 does NOT double increment
        summary, _, _ = worker._perform_change_detection(r3, domain_id, rep3)
        assert (
            summary["_inventory_updates"]["target.example.com"]["consecutive_qualifying_absences"]
            == 2
        )


def test_older_scan_finalizing_after_newer_scan_db(clean_db, db_engine):
    """An older scan finalizing after a newer scan is superseded and cannot corrupt inventory."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "ordering-superseded.example.com")
        _queue_scan(session, domain_id)

    worker = ASMWorker(db_engine)

    # Claim older scan
    claimed_old = worker.claim_next_job()
    assert claimed_old is not None
    old_run_id, _, old_token, _, _ = claimed_old

    # Allow queuing newer scan by setting r_old status to 'failed' (simulating lease reaper)
    with Session(db_engine) as session:
        session.execute(
            text("UPDATE scan_runs SET status = 'failed' WHERE id = :id"), {"id": old_run_id}
        )
        session.commit()
        _queue_scan(session, domain_id)

    claimed_new = worker.claim_next_job()
    assert claimed_new is not None
    new_run_id, _, new_token, _, _ = claimed_new

    # Newer scan finalizes first
    worker._mark_run_final(
        new_run_id,
        new_token,
        status="succeeded",
        error_msg=None,
        change_detection={
            "_inventory_updates": {
                "newer.example.com": {
                    "subdomain": "newer.example.com",
                    "status": "active",
                    "anchor_source": "crt.sh",
                    "consecutive_qualifying_absences": 0,
                    "first_seen_scan_run_id": new_run_id,
                    "last_seen_scan_run_id": new_run_id,
                }
            }
        },
        domain_id=domain_id,
    )

    # Now older scan attempts late finalization (reset to running with valid token)
    with Session(db_engine) as session:
        session.execute(
            text("UPDATE scan_runs SET status = 'running', claim_token = :token WHERE id = :id"),
            {"token": old_token, "id": old_run_id},
        )
        session.commit()

    worker._mark_run_final(
        old_run_id,
        old_token,
        status="succeeded",
        error_msg=None,
        change_detection={
            "_inventory_updates": {
                "older.example.com": {
                    "subdomain": "older.example.com",
                    "status": "active",
                    "anchor_source": "crt.sh",
                    "consecutive_qualifying_absences": 0,
                    "first_seen_scan_run_id": old_run_id,
                    "last_seen_scan_run_id": old_run_id,
                }
            }
        },
        domain_id=domain_id,
    )

    with Session(db_engine) as session:
        # Older inventory update discarded: newer.example.com present, older.example.com NOT
        newer_row = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="newer.example.com")
            .first()
        )
        older_row = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="older.example.com")
            .first()
        )
        assert newer_row is not None
        assert older_row is None

        # Older scan run records that it was superseded
        old_run = session.get(ScanRun, old_run_id)
        assert old_run.change_detection.get("superseded_by") == new_run_id


def test_two_workers_finalizing_same_scan_db(clean_db, db_engine):
    """Two workers attempting to finalize same scan run: second rejected with LostLeaseError."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "concurrency-final.example.com")
        _queue_scan(session, domain_id)

    worker1 = ASMWorker(db_engine, worker_id="worker-1")
    worker2 = ASMWorker(db_engine, worker_id="worker-2")

    claimed = worker1.claim_next_job()
    assert claimed is not None
    run_id, _, claim_token, _, _ = claimed

    # Worker 1 finalizes
    worker1._mark_run_final(
        run_id, claim_token, status="succeeded", error_msg=None, domain_id=domain_id
    )

    # Worker 2 attempts to finalize same scan run
    with pytest.raises(LostLeaseError):
        worker2._mark_run_final(
            run_id, claim_token, status="succeeded", error_msg=None, domain_id=domain_id
        )


def test_stale_claim_token_inventory_update_db(clean_db, db_engine):
    """Stale claim token cannot commit inventory updates."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "stale-token.example.com")
        _queue_scan(session, domain_id)

    worker = ASMWorker(db_engine)
    claimed = worker.claim_next_job()
    assert claimed is not None
    run_id, _, original_token, _, _ = claimed

    # Another process or lease recovery assigns a new token
    reassigned_token = uuid.uuid4()
    with Session(db_engine) as session:
        session.execute(
            text("UPDATE scan_runs SET claim_token = :token WHERE id = :id"),
            {"token": reassigned_token, "id": run_id},
        )
        session.commit()

    # Original worker attempts _mark_run_final with original stale token
    with pytest.raises(LostLeaseError):
        worker._mark_run_final(
            run_id,
            original_token,
            status="succeeded",
            error_msg=None,
            change_detection={
                "_inventory_updates": {
                    "stale.example.com": {
                        "status": "active",
                        "anchor_source": "crt.sh",
                        "consecutive_qualifying_absences": 0,
                    }
                }
            },
            domain_id=domain_id,
        )

    with Session(db_engine) as session:
        count = session.query(DomainSubdomain).filter_by(domain_id=domain_id).count()
        assert count == 0


def test_tombstone_pruning_retains_newest_with_tiebreaker_db(clean_db, db_engine):
    """Tombstone pruning retains newest tombstones by updated_at DESC with tie-breaker."""
    from datetime import datetime

    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "tombstone-prune-test.example.com")

        # 1. Distinct timestamps: 5 removed rows with t1 < t2 < t3 < t4 < t5
        for i in range(1, 6):
            session.add(
                DomainSubdomain(
                    domain_id=domain_id,
                    subdomain=f"distinct-{i}.example.com",
                    status="removed",
                    anchor_source="crt.sh",
                    consecutive_qualifying_absences=2,
                    updated_at=datetime(2026, 1, 1, 10, i),
                )
            )
        session.commit()

        # Prune with cap=3: must retain the 3 newest (i=3, 4, 5) and delete (i=1, 2)
        session.execute(
            text(
                """
                DELETE FROM domain_subdomains
                WHERE id IN (
                    SELECT id FROM domain_subdomains
                    WHERE domain_id = :domain_id AND status = 'removed'
                    ORDER BY updated_at DESC, id DESC
                    OFFSET :max_tombstones
                )
                """
            ),
            {"domain_id": domain_id, "max_tombstones": 3},
        )
        session.commit()

        surviving = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, status="removed")
            .order_by(DomainSubdomain.updated_at.asc())
            .all()
        )
        assert [r.subdomain for r in surviving] == [
            "distinct-3.example.com",
            "distinct-4.example.com",
            "distinct-5.example.com",
        ]

        # Clean up for tied timestamp test
        session.query(DomainSubdomain).filter_by(domain_id=domain_id).delete()
        session.commit()

        # 2. Tied timestamps: 4 removed rows with exact same updated_at
        tied_time = datetime(2026, 1, 1, 12, 0)
        row_ids = []
        for i in range(1, 5):
            ds = DomainSubdomain(
                domain_id=domain_id,
                subdomain=f"tied-{i}.example.com",
                status="removed",
                anchor_source="crt.sh",
                consecutive_qualifying_absences=2,
                updated_at=tied_time,
            )
            session.add(ds)
            session.flush()
            row_ids.append(ds.id)
        session.commit()

        # Prune with cap=2: retain newest 2 by deterministic id DESC tie-breaker
        session.execute(
            text(
                """
                DELETE FROM domain_subdomains
                WHERE id IN (
                    SELECT id FROM domain_subdomains
                    WHERE domain_id = :domain_id AND status = 'removed'
                    ORDER BY updated_at DESC, id DESC
                    OFFSET :max_tombstones
                )
                """
            ),
            {"domain_id": domain_id, "max_tombstones": 2},
        )
        session.commit()

        surviving_tied = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, status="removed")
            .order_by(DomainSubdomain.id.asc())
            .all()
        )
        assert [r.id for r in surviving_tied] == [row_ids[2], row_ids[3]]
        assert [r.subdomain for r in surviving_tied] == [
            "tied-3.example.com",
            "tied-4.example.com",
        ]


def test_stale_inventory_calculation_recomputed_under_lock_db(clean_db, db_engine):
    """Sequential finalization calculates under domain lock without losing transitions."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "seq-finalization.example.com")

    p_target = {"subdomain": "target.example.com", "status": "RESOLVED", "resolved": True}
    p_anchor = {"subdomain": "anchor.example.com", "status": "RESOLVED", "resolved": True}

    # Baseline: both target and anchor present
    rep_baseline = _make_report([p_target, p_anchor], source="crt.sh")
    # Scan 2: target missing (qualifying absence 1)
    rep_scan2 = _make_report([p_anchor], source="crt.sh")
    # Scan 3: target missing (qualifying absence 2 -> removal)
    rep_scan3 = _make_report([p_anchor], source="crt.sh")

    runner = ScriptedRunner([rep_baseline, rep_scan2, rep_scan3])
    worker = ASMWorker(db_engine, runner=runner)

    # 1. Run baseline scan to completion
    with Session(db_engine) as session:
        r1_id = _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        sub_row = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="target.example.com")
            .first()
        )
        assert sub_row.status == "active"
        assert sub_row.consecutive_qualifying_absences == 0

    # 2. Simulate two concurrent scans both reading the same initial inventory
    # Queue and claim Scan 2
    with Session(db_engine) as session:
        _queue_scan(session, domain_id)
    claimed_2 = worker.claim_next_job()
    assert claimed_2 is not None
    run_2_id, _, token_2, _, _ = claimed_2

    # Allow queuing Scan 3 by temporarily marking Scan 2 failed (simulating lease reaper)
    with Session(db_engine) as session:
        session.execute(
            text("UPDATE scan_runs SET status = 'failed' WHERE id = :id"), {"id": run_2_id}
        )
        session.commit()
        _queue_scan(session, domain_id)

    claimed_3 = worker.claim_next_job()
    assert claimed_3 is not None
    run_3_id, _, token_3, _, _ = claimed_3

    # Set Scan 3 temporarily to 'failed' so Scan 2 can be restored to 'running' to finalize first
    with Session(db_engine) as session:
        session.execute(
            text("UPDATE scan_runs SET status = 'failed' WHERE id = :id"), {"id": run_3_id}
        )
        session.execute(
            text("UPDATE scan_runs SET status = 'running', claim_token = :token WHERE id = :id"),
            {"token": token_2, "id": run_2_id},
        )
        session.commit()

    # Scan 2 finalizes in sequence
    worker._mark_run_final(
        run_2_id, token_2, "succeeded", None, domain_id=domain_id, reports=rep_scan2
    )

    # Now restore Scan 3 to 'running' with its valid claim token to finalize in sequence
    with Session(db_engine) as session:
        session.execute(
            text("UPDATE scan_runs SET status = 'running', claim_token = :token WHERE id = :id"),
            {"token": token_3, "id": run_3_id},
        )
        session.commit()

    # Scan 3 finalizes in sequence: recomputes under domain lock against committed Scan 2 inventory
    worker._mark_run_final(
        run_3_id, token_3, "succeeded", None, domain_id=domain_id, reports=rep_scan3
    )

    with Session(db_engine) as session:
        # Scan 2 emitted 0 removals (absence progressed 0 -> 1)
        ch_2 = session.query(ScanChange).filter_by(scan_run_id=run_2_id).all()
        assert not any(c.change_type == "REMOVED_SUBDOMAIN" for c in ch_2)

        # Scan 3 calculated under lock against committed Scan 2 inventory (streak 2 -> removal)
        ch_3 = session.query(ScanChange).filter_by(scan_run_id=run_3_id).all()
        removals = [
            c
            for c in ch_3
            if c.change_type == "REMOVED_SUBDOMAIN" and c.asset == "target.example.com"
        ]
        assert len(removals) == 1
        assert removals[0].baseline_scan_run_id == r1_id

        # Inventory correctly transitioned to removed with consecutive_qualifying_absences=2
        final_row = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="target.example.com")
            .first()
        )
        assert final_row.status == "removed"
        assert final_row.consecutive_qualifying_absences == 2
        assert final_row.removed_at_scan_run_id == run_3_id


def test_last_applied_scan_run_id_monotonicity_and_retention_purge_db(clean_db, db_engine):
    """Monotonic updates via last_applied_scan_run_id are immune to scan retention purges."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "monotonic-retention.example.com")
        _queue_scan(session, domain_id)

    # Seed row with applied version = 20
    with Session(db_engine) as session:
        session.add(
            DomainSubdomain(
                domain_id=domain_id,
                subdomain="host.example.com",
                status="active",
                anchor_source="crt.sh",
                consecutive_qualifying_absences=1,
                last_applied_scan_run_id=20,
            )
        )
        session.commit()

    # Worker finalization upsert with stale scan_run_id = 15
    with Session(db_engine) as session:
        session.execute(
            text(
                """
                INSERT INTO domain_subdomains (
                    domain_id, subdomain, status, anchor_source,
                    consecutive_qualifying_absences, last_applied_scan_run_id,
                    created_at, updated_at
                ) VALUES (
                    :domain_id, :subdomain, :status, :anchor_source,
                    :consecutive_qualifying_absences, :last_applied_scan_run_id,
                    now(), now()
                )
                ON CONFLICT (domain_id, subdomain) DO UPDATE SET
                    status = EXCLUDED.status,
                    consecutive_qualifying_absences = EXCLUDED.consecutive_qualifying_absences,
                    last_applied_scan_run_id = EXCLUDED.last_applied_scan_run_id,
                    updated_at = now()
                WHERE (
                    domain_subdomains.last_applied_scan_run_id IS NULL
                    OR domain_subdomains.last_applied_scan_run_id <= :scan_run_id
                )
                """
            ),
            {
                "domain_id": domain_id,
                "subdomain": "host.example.com",
                "status": "removed",
                "anchor_source": "crt.sh",
                "consecutive_qualifying_absences": 5,
                "last_applied_scan_run_id": 15,
                "scan_run_id": 15,
            },
        )
        session.commit()

    with Session(db_engine) as session:
        row = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="host.example.com")
            .one()
        )
        # Update rejected: status remains active and absences remains 1
        assert row.status == "active"
        assert row.consecutive_qualifying_absences == 1
        assert row.last_applied_scan_run_id == 20

    # Simulate data retention purge: all scan_runs deleted
    with Session(db_engine) as session:
        session.execute(text("DELETE FROM scan_runs"))
        session.commit()

    # last_applied_scan_run_id is preserved because it has no FK constraint
    with Session(db_engine) as session:
        row_after_purge = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="host.example.com")
            .one()
        )
        assert row_after_purge.last_applied_scan_run_id == 20

        # Monotonic guard STILL protects against stale updates after retention purge
        session.execute(
            text(
                """
                INSERT INTO domain_subdomains (
                    domain_id, subdomain, status, anchor_source,
                    consecutive_qualifying_absences, last_applied_scan_run_id,
                    created_at, updated_at
                ) VALUES (
                    :domain_id, :subdomain, :status, :anchor_source,
                    :consecutive_qualifying_absences, :last_applied_scan_run_id,
                    now(), now()
                )
                ON CONFLICT (domain_id, subdomain) DO UPDATE SET
                    status = EXCLUDED.status,
                    consecutive_qualifying_absences = EXCLUDED.consecutive_qualifying_absences,
                    last_applied_scan_run_id = EXCLUDED.last_applied_scan_run_id,
                    updated_at = now()
                WHERE (
                    domain_subdomains.last_applied_scan_run_id IS NULL
                    OR domain_subdomains.last_applied_scan_run_id <= :scan_run_id
                )
                """
            ),
            {
                "domain_id": domain_id,
                "subdomain": "host.example.com",
                "status": "removed",
                "anchor_source": "crt.sh",
                "consecutive_qualifying_absences": 9,
                "last_applied_scan_run_id": 15,
                "scan_run_id": 15,
            },
        )
        session.commit()

        row_still_protected = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="host.example.com")
            .one()
        )
        assert row_still_protected.status == "active"
        assert row_still_protected.consecutive_qualifying_absences == 1
        assert row_still_protected.last_applied_scan_run_id == 20


def test_capacity_limit_persisted_to_scan_results_and_rendered_in_html_db(clean_db, db_engine):
    """Capacity limit metadata is persisted to scan_results and rendered in scan detail HTML."""
    from fastapi.testclient import TestClient

    from asm.api.deps import get_current_user, get_db
    from asm.api.main import app
    from asm.db.models import Membership, ScanResult, User

    with Session(db_engine) as session:
        org_id, domain_id = _setup_domain(session, "cap-notice.example.com")
        user = User(id=uuid.uuid4(), email="owner@cap-notice.example.com")
        session.add(user)
        session.flush()
        session.add(Membership(org_id=org_id, user_id=user.id, role="owner"))

        # Pre-seed 5000 active subdomains
        for i in range(5000):
            session.add(
                DomainSubdomain(
                    domain_id=domain_id,
                    subdomain=f"h{i:04d}.example.com",
                    status="active",
                    anchor_source="crt.sh",
                    consecutive_qualifying_absences=0,
                )
            )
        session.commit()

        # Discover reports 5001 subdomains (1 beyond active cap)
        observed = [
            {"subdomain": f"h{i:04d}.example.com", "status": "RESOLVED", "resolved": True}
            for i in range(5000)
        ]
        observed.append(
            {"subdomain": "overflow.example.com", "status": "RESOLVED", "resolved": True}
        )
        rep_discover = _make_report(observed, source="crt.sh")

        runner = ScriptedRunner([rep_discover])
        worker = ASMWorker(db_engine, runner=runner)

        run_id = _queue_scan(session, domain_id)
        worker.run_poll_cycle()

        # 1. Assert metadata persisted to scan_results under the lock
        sr = session.query(ScanResult).filter_by(scan_run_id=run_id, stage="discover").first()
        assert sr is not None
        assert sr.report.get("truncated") is True
        assert sr.report.get("truncation_reason") == "inventory_capacity_exceeded"
        assert sr.report.get("untracked_subdomains_count") == 1

        # 2. Assert HTML rendering via TestClient with session dependency override
        def _override_user():
            return user

        def _override_db():
            yield session

        app.dependency_overrides[get_current_user] = _override_user
        app.dependency_overrides[get_db] = _override_db
        try:
            client = TestClient(app)
            res = client.get(f"/ui/orgs/{org_id}/scans/{run_id}")
            assert res.status_code == 200
            assert (
                "Active inventory cap reached. 1 observed subdomain(s) could not be retained "
                "in discovery inventory." in res.text
            )
        finally:
            app.dependency_overrides.clear()


def test_tombstone_at_capacity_newly_removed_host_persisted_and_retained_db(
    clean_db, db_engine
):
    """G3.1 regression: when tombstones are at capacity and an earlier-inserted active host
    reaches its 2nd qualifying absence, finalization must persist active->removed, retain the
    newest tombstone, and never emit duplicate REMOVED_SUBDOMAIN on subsequent scans.
    """
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "g31-cap.example.com")

    p_victim = {"subdomain": "victim.g31-cap.example.com", "status": "RESOLVED", "resolved": True}
    p_anchor = {"subdomain": "anchor.g31-cap.example.com", "status": "RESOLVED", "resolved": True}

    rep_1 = _make_report([p_victim, p_anchor], source="crt.sh", truncated=False)
    rep_2 = _make_report([p_anchor], source="crt.sh", truncated=False)
    rep_3 = _make_report([p_anchor], source="crt.sh", truncated=False)
    rep_4 = _make_report([p_anchor], source="crt.sh", truncated=False)

    runner = ScriptedRunner([rep_1, rep_2, rep_3, rep_4])
    worker = ASMWorker(db_engine, runner=runner)

    # Scan 1: victim and anchor discovered (victim inserted first in domain_subdomains)
    with Session(db_engine) as session:
        r1 = _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    # Scan 2: victim reaches 1st qualifying absence
    with Session(db_engine) as session:
        r2 = _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    # Seed 1,000 existing tombstones AFTER victim so victim is first in table scan order
    with Session(db_engine) as session:
        for i in range(1000):
            session.add(
                DomainSubdomain(
                    domain_id=domain_id,
                    subdomain=f"tomb-{i:04d}.g31-cap.example.com",
                    status="removed",
                    anchor_source="crt.sh",
                    consecutive_qualifying_absences=2,
                    first_seen_scan_run_id=r1,
                    last_seen_scan_run_id=r1,
                    removed_at_scan_run_id=r2,
                    last_applied_scan_run_id=r2,
                )
            )
        session.commit()

    # Scan 3: victim reaches 2nd qualifying absence -> REMOVED_SUBDOMAIN
    with Session(db_engine) as session:
        r3 = _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        changes_r3 = session.query(ScanChange).filter_by(scan_run_id=r3).all()
        removals_r3 = [
            c
            for c in changes_r3
            if c.change_type == "REMOVED_SUBDOMAIN" and c.asset == "victim.g31-cap.example.com"
        ]
        assert len(removals_r3) == 1

        victim_row = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="victim.g31-cap.example.com")
            .first()
        )
        assert victim_row is not None, "Newly removed host must be retained as newest tombstone"
        assert victim_row.status == "removed", "Removed host must not remain active in PostgreSQL"
        assert victim_row.removed_at_scan_run_id == r3
        assert victim_row.last_applied_scan_run_id == r3

        tombstone_count = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, status="removed")
            .count()
        )
        assert tombstone_count == 1000

    # Scan 4: subsequent qualifying-absence scan must NOT emit duplicate REMOVED_SUBDOMAIN
    with Session(db_engine) as session:
        r4 = _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        changes_r4 = session.query(ScanChange).filter_by(scan_run_id=r4).all()
        removals_r4 = [c for c in changes_r4 if c.change_type == "REMOVED_SUBDOMAIN"]
        assert removals_r4 == [], (
            f"Expected 0 duplicate REMOVED_SUBDOMAIN events on Scan 4, got {len(removals_r4)}"
        )


def test_tombstone_pruning_independent_of_row_return_order_and_ties_db(clean_db, db_engine):
    """Tombstone pruning and active->removed persistence produce identical results
    regardless of database row-return order and under tied retention timestamps.
    """
    with Session(db_engine) as session:
        _, dom_a = _setup_domain(session, "order-a.example.com")
        _, dom_b = _setup_domain(session, "order-b.example.com")

    def _run_scenario(
        domain_id: int, dom_name: str, reverse_seed_order: bool
    ) -> tuple[list[str], dict[str, str]]:
        p_anchor = {"subdomain": f"anchor.{dom_name}", "status": "RESOLVED", "resolved": True}
        p_v1 = {"subdomain": f"victim-1.{dom_name}", "status": "RESOLVED", "resolved": True}
        p_v2 = {"subdomain": f"victim-2.{dom_name}", "status": "RESOLVED", "resolved": True}

        rep_1 = _make_report([p_anchor, p_v1, p_v2], source="crt.sh", truncated=False)
        rep_2 = _make_report([p_anchor], source="crt.sh", truncated=False)
        rep_3 = _make_report([p_anchor], source="crt.sh", truncated=False)

        runner = ScriptedRunner([rep_1, rep_2, rep_3])
        worker = ASMWorker(db_engine, runner=runner)
        worker.max_tombstones = 3

        with Session(db_engine) as session:
            r1 = _queue_scan(session, domain_id)
        worker.run_poll_cycle()

        with Session(db_engine) as session:
            r2 = _queue_scan(session, domain_id)
        worker.run_poll_cycle()

        # Rewrite domain_subdomains rows in explicit forward vs reverse insertion order
        # with identical timestamps to verify row-order independence and tie-breaking.
        with Session(db_engine) as session:
            session.query(DomainSubdomain).filter_by(domain_id=domain_id).delete()
            session.flush()

            seed_specs = [
                (f"victim-1.{dom_name}", "active", 1, r1, r1, None, r2),
                (f"victim-2.{dom_name}", "active", 1, r1, r1, None, r2),
                (f"anchor.{dom_name}", "active", 0, r1, r2, None, r2),
                (f"tomb-a.{dom_name}", "removed", 2, r1, r1, r2, r2),
                (f"tomb-b.{dom_name}", "removed", 2, r1, r1, r2, r2),
                (f"tomb-c.{dom_name}", "removed", 2, r1, r1, r2, r2),
            ]
            if reverse_seed_order:
                seed_specs = list(reversed(seed_specs))

            for sub, st, abs_cnt, fs, ls, rem_id, app_id in seed_specs:
                session.add(
                    DomainSubdomain(
                        domain_id=domain_id,
                        subdomain=sub,
                        status=st,
                        anchor_source="crt.sh",
                        consecutive_qualifying_absences=abs_cnt,
                        first_seen_scan_run_id=fs,
                        last_seen_scan_run_id=ls,
                        removed_at_scan_run_id=rem_id,
                        last_applied_scan_run_id=app_id,
                    )
                )
            session.commit()
            session.execute(
                text(
                    "UPDATE domain_subdomains SET updated_at = '2026-10-17 00:00:00+00' "
                    "WHERE domain_id = :d"
                ),
                {"d": domain_id},
            )
            session.commit()

        with Session(db_engine) as session:
            r3 = _queue_scan(session, domain_id)
        worker.run_poll_cycle()

        with Session(db_engine) as session:
            changes = (
                session.query(ScanChange)
                .filter_by(scan_run_id=r3, change_type="REMOVED_SUBDOMAIN")
                .all()
            )
            emitted = sorted(c.asset.removesuffix(f".{dom_name}") for c in changes)
            rows = session.query(DomainSubdomain).filter_by(domain_id=domain_id).all()
            persisted = {
                r.subdomain.removesuffix(f".{dom_name}"): r.status for r in rows
            }
            return emitted, persisted

    emitted_a, persisted_a = _run_scenario(dom_a, "order-a.example.com", reverse_seed_order=False)
    emitted_b, persisted_b = _run_scenario(dom_b, "order-b.example.com", reverse_seed_order=True)

    assert emitted_a == ["victim-1", "victim-2"]
    assert emitted_b == ["victim-1", "victim-2"]
    assert persisted_a == persisted_b
    # Both newly-removed victims (r3) plus the highest tie-breaker from r2 (tomb-c) are retained
    assert persisted_a == {
        "anchor": "active",
        "victim-1": "removed",
        "victim-2": "removed",
        "tomb-c": "removed",
    }


def test_multiple_simultaneous_removals_exceeding_tombstone_cap_db(clean_db, db_engine):
    """When more active hosts transition to removed in a single scan than max_tombstones,
    every removed host must transition out of active status (never remain active in DB),
    only max_tombstones newest tombstones are retained, and the next scan emits no duplicates.
    """
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "multi-rem.example.com")

    p_anchor = {"subdomain": "anchor.multi-rem.example.com", "status": "RESOLVED", "resolved": True}
    victims = [
        {"subdomain": f"rem-{ch}.multi-rem.example.com", "status": "RESOLVED", "resolved": True}
        for ch in ("a", "b", "c", "d", "e")
    ]

    rep_1 = _make_report([p_anchor, *victims], source="crt.sh", truncated=False)
    rep_2 = _make_report([p_anchor], source="crt.sh", truncated=False)
    rep_3 = _make_report([p_anchor], source="crt.sh", truncated=False)
    rep_4 = _make_report([p_anchor], source="crt.sh", truncated=False)

    runner = ScriptedRunner([rep_1, rep_2, rep_3, rep_4])
    worker = ASMWorker(db_engine, runner=runner)
    worker.max_tombstones = 3

    # Scan 1 (present), Scan 2 (1st absence), Scan 3 (2nd absence -> 5 simultaneous removals)
    for _ in range(3):
        with Session(db_engine) as session:
            r_id = _queue_scan(session, domain_id)
        worker.run_poll_cycle()

    with Session(db_engine) as session:
        changes_r3 = (
            session.query(ScanChange)
            .filter_by(scan_run_id=r_id, change_type="REMOVED_SUBDOMAIN")
            .all()
        )
        assert sorted(c.asset for c in changes_r3) == [
            f"rem-{ch}.multi-rem.example.com" for ch in ("a", "b", "c", "d", "e")
        ]

        rows = session.query(DomainSubdomain).filter_by(domain_id=domain_id).all()
        active_subs = [r.subdomain for r in rows if r.status == "active"]
        removed_subs = sorted(r.subdomain for r in rows if r.status == "removed")

        # Only anchor may remain active! None of the 5 removed hosts may stay active.
        assert active_subs == ["anchor.multi-rem.example.com"]
        assert len(removed_subs) == 3
        assert removed_subs == [
            "rem-c.multi-rem.example.com",
            "rem-d.multi-rem.example.com",
            "rem-e.multi-rem.example.com",
        ]

    # Scan 4: next qualifying-absence scan must emit 0 REMOVED_SUBDOMAIN events
    with Session(db_engine) as session:
        r4 = _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        changes_r4 = (
            session.query(ScanChange)
            .filter_by(scan_run_id=r4, change_type="REMOVED_SUBDOMAIN")
            .all()
        )
        assert changes_r4 == []


def test_tombstone_pruning_rollback_and_repeated_finalization_db(
    clean_db, db_engine, monkeypatch
):
    """Transaction rollback during finalization leaves pre-existing active rows and tombstones
    untouched; subsequent retry succeeds cleanly and repeated finalization is rejected.
    """
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "rollback-g31.example.com")

    p_anchor = {
        "subdomain": "anchor.rollback-g31.example.com",
        "status": "RESOLVED",
        "resolved": True,
    }
    p_victim = {
        "subdomain": "victim.rollback-g31.example.com",
        "status": "RESOLVED",
        "resolved": True,
    }

    rep_1 = _make_report([p_victim, p_anchor], source="crt.sh", truncated=False)
    rep_2 = _make_report([p_anchor], source="crt.sh", truncated=False)
    rep_3 = _make_report([p_anchor], source="crt.sh", truncated=False)

    runner = ScriptedRunner([rep_1, rep_2, rep_3])
    worker = ASMWorker(db_engine, runner=runner)
    worker.max_tombstones = 2

    with Session(db_engine) as session:
        r1 = _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        r2 = _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        for i in range(2):
            session.add(
                DomainSubdomain(
                    domain_id=domain_id,
                    subdomain=f"tomb-{i}.rollback-g31.example.com",
                    status="removed",
                    anchor_source="crt.sh",
                    consecutive_qualifying_absences=2,
                    first_seen_scan_run_id=r1,
                    last_seen_scan_run_id=r1,
                    removed_at_scan_run_id=r2,
                    last_applied_scan_run_id=r2,
                )
            )
        session.commit()

    # Queue Scan 3 and inject a failure right after inventory updates/pruning inside _mark_run_final
    with Session(db_engine) as session:
        r3 = _queue_scan(session, domain_id)

    orig_perform = worker._perform_change_detection

    def _corrupt_changes_after_inventory(*args: Any, **kwargs: Any) -> Any:
        summary, changes, baseline_id = orig_perform(*args, **kwargs)
        # Append a malformed change entry so _mark_run_final fails AFTER executing
        # the domain_subdomains upserts and tombstone DELETE statements.
        changes = [*changes, {"change_type": "BROKEN_FOR_ROLLBACK_TEST"}]
        return summary, changes, baseline_id

    monkeypatch.setattr(worker, "_perform_change_detection", _corrupt_changes_after_inventory)
    worker.run_poll_cycle()

    # Verify rollback: victim is still active with absences=1, both tombstones still exist
    with Session(db_engine) as session:
        victim = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="victim.rollback-g31.example.com")
            .one()
        )
        assert victim.status == "active"
        assert victim.consecutive_qualifying_absences == 1
        tombs = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, status="removed")
            .all()
        )
        assert sorted(t.subdomain for t in tombs) == [
            "tomb-0.rollback-g31.example.com",
            "tomb-1.rollback-g31.example.com",
        ]

    # Restore change detection and allow immediate retry of Scan 3
    monkeypatch.undo()
    with Session(db_engine) as session:
        run_row = session.get(ScanRun, r3)
        assert run_row is not None
        assert run_row.status == "queued"
        run_row.next_attempt_at = None
        session.commit()

    worker.run_poll_cycle()

    with Session(db_engine) as session:
        victim_after = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="victim.rollback-g31.example.com")
            .one()
        )
        assert victim_after.status == "removed"
        assert victim_after.removed_at_scan_run_id == r3

    # Repeated finalization attempt must raise LostLeaseError and not alter inventory
    with pytest.raises(LostLeaseError):
        worker._mark_run_final(
            r3,
            uuid.uuid4(),
            status="succeeded",
            error_msg=None,
            change_detection={"total_changes": 0, "_inventory_transitions": {}},
            domain_id=domain_id,
        )


def test_reappearance_after_retained_or_evicted_tombstone_db(clean_db, db_engine):
    """Both a host with a retained tombstone and a host whose tombstone was evicted
    by capacity pruning cleanly return to active status and emit NEW_SUBDOMAIN on reappearance.
    """
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "reappear-g31.example.com")

    p_anchor = {
        "subdomain": "anchor.reappear-g31.example.com",
        "status": "RESOLVED",
        "resolved": True,
    }
    p_evicted = {
        "subdomain": "a-evicted.reappear-g31.example.com",
        "status": "RESOLVED",
        "resolved": True,
    }
    p_retained = {
        "subdomain": "z-retained.reappear-g31.example.com",
        "status": "RESOLVED",
        "resolved": True,
    }

    rep_1 = _make_report([p_anchor, p_evicted, p_retained], source="crt.sh", truncated=False)
    rep_2 = _make_report([p_anchor], source="crt.sh", truncated=False)
    rep_3 = _make_report([p_anchor], source="crt.sh", truncated=False)
    rep_4 = _make_report([p_anchor, p_evicted, p_retained], source="crt.sh", truncated=False)

    runner = ScriptedRunner([rep_1, rep_2, rep_3, rep_4])
    worker = ASMWorker(db_engine, runner=runner)
    worker.max_tombstones = 1

    # Scan 1 (present), Scan 2 (1st absence),
    # Scan 3 (both removed, max_tombstones=1 retains z-retained)
    for _ in range(3):
        with Session(db_engine) as session:
            _queue_scan(session, domain_id)
        worker.run_poll_cycle()

    with Session(db_engine) as session:
        rows_after_r3 = session.query(DomainSubdomain).filter_by(domain_id=domain_id).all()
        by_sub = {r.subdomain: r.status for r in rows_after_r3}
        assert by_sub == {
            "anchor.reappear-g31.example.com": "active",
            "z-retained.reappear-g31.example.com": "removed",
        }

    # Scan 4: both a-evicted and z-retained reappear
    with Session(db_engine) as session:
        r4 = _queue_scan(session, domain_id)
    worker.run_poll_cycle()

    with Session(db_engine) as session:
        changes_r4 = (
            session.query(ScanChange)
            .filter_by(scan_run_id=r4, change_type="NEW_SUBDOMAIN")
            .all()
        )
        assert sorted(c.asset for c in changes_r4) == [
            "a-evicted.reappear-g31.example.com",
            "z-retained.reappear-g31.example.com",
        ]
        for sub_name in (
            "a-evicted.reappear-g31.example.com",
            "z-retained.reappear-g31.example.com",
        ):
            row = (
                session.query(DomainSubdomain)
                .filter_by(domain_id=domain_id, subdomain=sub_name)
                .one()
            )
            assert row.status == "active"
            assert row.consecutive_qualifying_absences == 0
            assert row.removed_at_scan_run_id is None
            assert row.last_seen_scan_run_id == r4


def test_worker_persistent_inventory_definite_dns_preservation_db(clean_db, db_engine):
    """G3.2: Worker preserves definite DNS state in PostgreSQL across sessions and timeouts."""
    with Session(db_engine) as session:
        _, domain_id = _setup_domain(session, "dns-preservation-db.example.com")

    h_res = {
        "subdomain": "api.dns-preservation-db.example.com",
        "status": "RESOLVED",
        "resolved": True,
        "ip_addresses": ["203.0.113.50"],
    }
    h_timeout = {
        "subdomain": "api.dns-preservation-db.example.com",
        "status": "TIMEOUT",
        "resolved": False,
        "ip_addresses": [],
    }
    h_nx = {
        "subdomain": "api.dns-preservation-db.example.com",
        "status": "NXDOMAIN",
        "resolved": False,
        "ip_addresses": [],
    }

    rep_1 = _make_report([h_res], source="crt.sh", truncated=False)
    rep_2 = _make_report([h_timeout], source="crt.sh", truncated=False)
    rep_3 = _make_report([h_nx], source="crt.sh", truncated=False)
    rep_4 = _make_report([h_nx], source="crt.sh", truncated=False)

    runner = ScriptedRunner([rep_1, rep_2, rep_3, rep_4])

    # Scan 1: RESOLVED baseline
    worker1 = ASMWorker(db_engine, runner=runner)
    with Session(db_engine) as session:
        r1 = _queue_scan(session, domain_id)
    worker1.run_poll_cycle()

    with Session(db_engine) as session:
        row1 = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="api.dns-preservation-db.example.com")
            .one()
        )
        assert row1.status == "active"
        assert row1.last_status == "RESOLVED"
        assert row1.last_resolved is True
        assert row1.last_seen_scan_run_id == r1

    # Scan 2: TIMEOUT (fresh worker session simulating process restart)
    worker2 = ASMWorker(db_engine, runner=runner)
    with Session(db_engine) as session:
        r2 = _queue_scan(session, domain_id)
    worker2.run_poll_cycle()

    with Session(db_engine) as session:
        row2 = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="api.dns-preservation-db.example.com")
            .one()
        )
        assert row2.status == "active"
        # Preserved definite state in PostgreSQL despite transient timeout
        assert row2.last_status == "RESOLVED"
        assert row2.last_resolved is True
        assert row2.last_seen_scan_run_id == r2

        ch2 = (
            session.query(ScanChange)
            .filter_by(scan_run_id=r2, change_type="STOPPED_RESOLVING")
            .all()
        )
        assert len(ch2) == 0

    # Scan 3: NXDOMAIN (another fresh worker session)
    worker3 = ASMWorker(db_engine, runner=runner)
    with Session(db_engine) as session:
        r3 = _queue_scan(session, domain_id)
    worker3.run_poll_cycle()

    with Session(db_engine) as session:
        row3 = (
            session.query(DomainSubdomain)
            .filter_by(domain_id=domain_id, subdomain="api.dns-preservation-db.example.com")
            .one()
        )
        assert row3.status == "active"
        assert row3.last_status == "NXDOMAIN"
        assert row3.last_resolved is False
        assert row3.last_seen_scan_run_id == r3

        ch3 = (
            session.query(ScanChange)
            .filter_by(scan_run_id=r3, change_type="STOPPED_RESOLVING")
            .all()
        )
        assert len(ch3) == 1
        assert ch3[0].asset == "api.dns-preservation-db.example.com"
        assert ch3[0].previous_state == {"status": "RESOLVED", "resolved": True}
        assert ch3[0].new_state == {"status": "NXDOMAIN", "resolved": False}

    # Scan 4: Repeated NXDOMAIN (no duplicate change)
    worker4 = ASMWorker(db_engine, runner=runner)
    with Session(db_engine) as session:
        r4 = _queue_scan(session, domain_id)
    worker4.run_poll_cycle()

    with Session(db_engine) as session:
        ch4 = (
            session.query(ScanChange)
            .filter_by(scan_run_id=r4, change_type="STOPPED_RESOLVING")
            .all()
        )
        assert len(ch4) == 0

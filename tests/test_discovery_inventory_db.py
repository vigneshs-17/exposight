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

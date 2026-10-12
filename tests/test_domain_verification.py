"""Comprehensive tests for v3.2 Domain Ownership Verification via DNS TXT.

All tests adhere to zero-network, PostgreSQL-only database testing, and cover:
- DNS TXT record parsing, exact matching, string concatenation, and failure modes
- Unknown vs Absent DNS failure taxonomy
- Per-domain cooldown (30s) under DB row lock
- Continuous re-verification: 2 misses -> lapsed; timeouts never lapse; 1h fast retry
- Pipeline enforcement: API/scheduler/worker gating on verification_status == 'verified'
- Multi-tenant token isolation
- Operator overrides with expiration (1..90d), revocation, and outbox alert notifications
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch
from uuid import UUID

import dns.exception
import dns.flags
import dns.resolver
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select, text
from sqlalchemy.orm import Session, sessionmaker

from asm.admin import revoke_verification, verify_domain
from asm.cli import main as cli_main
from asm.db.models import AlertNotification, Domain, Membership, Organization, ScanRun
from asm.db.scans import UnverifiedDomainError, enqueue_scan
from asm.verification import (
    VERIFICATION_CHECK_COOLDOWN_SECONDS,
    VerificationOutcome,
    apply_check_outcome,
    build_validating_resolver,
    check_dns_txt_verification,
    generate_verification_token,
    get_expected_record_value,
    get_verification_record_name,
    queue_domain_alert,
)
from asm.worker.worker import ASMWorker

# ==============================================================================
# 1. DNS TXT Resolution & Parsing Unit Tests (Mocked, Zero-Network)
# ==============================================================================


class _MockRdata:
    """Mock dnspython TXT rdata object."""

    def __init__(self, strings: list[bytes]) -> None:
        self.strings = strings


class _MockAnswer:
    """Mock dnspython resolver answer; `ad` sets the AD bit on the response."""

    def __init__(self, rdatas: list[_MockRdata], ad: bool = False) -> None:
        self._rdatas = rdatas
        self.response = SimpleNamespace(flags=dns.flags.AD if ad else 0)

    def __iter__(self):
        return iter(self._rdatas)


class _FakeResolver:
    """Resolver stand-in: label -> list of TXT chunk lists, or an exception; else NXDOMAIN."""

    def __init__(self, ip: str, records: dict[str, Any] | None = None, ad: bool = False) -> None:
        self.nameservers = [ip]
        self.records = records or {}
        self.ad = ad
        self.queries: list[str] = []

    def resolve(self, name: str, rdtype: str) -> _MockAnswer:
        assert rdtype == "TXT"
        self.queries.append(name)
        value = self.records.get(name)
        if value is None:
            raise dns.resolver.NXDOMAIN()
        if isinstance(value, BaseException):
            raise value
        return _MockAnswer([_MockRdata(chunks) for chunks in value], ad=self.ad)


NEW_LABEL = "_exposight-challenge.example.com"
OLD_LABEL = "_asm-verify.example.com"


def _pair(records: dict[str, Any], ad: bool = False) -> list[_FakeResolver]:
    """Two resolvers returning the same records."""
    return [_FakeResolver("1.1.1.1", records, ad), _FakeResolver("9.9.9.9", records, ad)]


def test_record_name_and_value_use_the_new_label() -> None:
    assert get_verification_record_name("example.com.") == NEW_LABEL
    assert get_expected_record_value(" tok ") == "exposight-verify=tok"


def test_dns_check_new_label_match() -> None:
    """exposight-verify=<token> at _exposight-challenge.<domain> on both resolvers -> MATCH."""
    token = generate_verification_token()
    resolvers = _pair({NEW_LABEL: [[f"exposight-verify={token}".encode()]]})
    outcome, _ = check_dns_txt_verification("example.com", token, resolvers=resolvers)
    assert outcome == VerificationOutcome.MATCH
    assert resolvers[0].queries == [NEW_LABEL]


def test_dns_check_legacy_label_still_matches() -> None:
    """Backward compat: asm-verify=<token> at _asm-verify.<domain> still verifies."""
    token = generate_verification_token()
    resolvers = _pair({OLD_LABEL: [[f"asm-verify={token}".encode()]]})
    outcome, detail = check_dns_txt_verification("example.com", token, resolvers=resolvers)
    assert outcome == VerificationOutcome.MATCH
    assert OLD_LABEL in (detail or "")
    assert resolvers[0].queries == [NEW_LABEL, OLD_LABEL]


def test_dns_check_values_are_not_interchangeable_between_labels() -> None:
    """The legacy value at the new label (and vice versa) is not a match."""
    token = generate_verification_token()
    resolvers = _pair(
        {
            NEW_LABEL: [[f"asm-verify={token}".encode()]],
            OLD_LABEL: [[f"exposight-verify={token}".encode()]],
        }
    )
    outcome, _ = check_dns_txt_verification("example.com", token, resolvers=resolvers)
    assert outcome == VerificationOutcome.ABSENT


def test_dns_check_ad_match_from_one_resolver_is_enough() -> None:
    """A DNSSEC-validated (AD) match from one resolver -> MATCH even if the other times out."""
    token = generate_verification_token()
    resolvers = [
        _FakeResolver("1.1.1.1", {NEW_LABEL: [[f"exposight-verify={token}".encode()]]}, ad=True),
        _FakeResolver("9.9.9.9", {NEW_LABEL: dns.exception.Timeout()}),
    ]
    outcome, detail = check_dns_txt_verification("example.com", token, resolvers=resolvers)
    assert outcome == VerificationOutcome.MATCH
    assert "DNSSEC" in (detail or "")


def test_dns_check_without_ad_requires_both_resolvers() -> None:
    """Unsigned zone: one resolver matching and the other timing out is not enough."""
    token = generate_verification_token()
    resolvers = [
        _FakeResolver("1.1.1.1", {NEW_LABEL: [[f"exposight-verify={token}".encode()]]}),
        _FakeResolver("9.9.9.9", {NEW_LABEL: dns.exception.Timeout()}),
    ]
    outcome, _ = check_dns_txt_verification("example.com", token, resolvers=resolvers)
    assert outcome == VerificationOutcome.UNKNOWN


def test_dns_check_disagreement_is_unknown() -> None:
    """One resolver matches, the other definitively has no record -> UNKNOWN, not ABSENT."""
    token = generate_verification_token()
    resolvers = [
        _FakeResolver("1.1.1.1", {NEW_LABEL: [[f"exposight-verify={token}".encode()]]}),
        _FakeResolver("9.9.9.9", {}),
    ]
    outcome, detail = check_dns_txt_verification("example.com", token, resolvers=resolvers)
    assert outcome == VerificationOutcome.UNKNOWN
    assert "disagree" in (detail or "")


def test_dns_check_both_absent_is_absent() -> None:
    token = generate_verification_token()
    outcome, _ = check_dns_txt_verification("example.com", token, resolvers=_pair({}))
    assert outcome == VerificationOutcome.ABSENT


def test_dns_check_missing_record() -> None:
    """TXT records present but none is a verification value -> ABSENT."""
    token = generate_verification_token()
    resolvers = _pair({NEW_LABEL: [[b"v=spf1 include:_spf.google.com ~all"]]})
    outcome, _ = check_dns_txt_verification("example.com", token, resolvers=resolvers)
    assert outcome == VerificationOutcome.ABSENT


def test_dns_check_wrong_token() -> None:
    """exposight-verify= with a mismatched token -> ABSENT."""
    token = generate_verification_token()
    other = generate_verification_token()
    resolvers = _pair({NEW_LABEL: [[f"exposight-verify={other}".encode()]]})
    outcome, _ = check_dns_txt_verification("example.com", token, resolvers=resolvers)
    assert outcome == VerificationOutcome.ABSENT


def test_dns_check_split_txt_strings() -> None:
    """RFC 1035 multi-chunk TXT records are joined before comparing."""
    token = generate_verification_token()
    chunks = [b"exposight-verify=", token[:10].encode(), token[10:].encode()]
    resolvers = _pair({NEW_LABEL: [chunks]})
    outcome, _ = check_dns_txt_verification("example.com", token, resolvers=resolvers)
    assert outcome == VerificationOutcome.MATCH


def test_dns_check_noanswer_is_absent() -> None:
    token = generate_verification_token()
    resolvers = _pair({NEW_LABEL: dns.resolver.NoAnswer(), OLD_LABEL: dns.resolver.NoAnswer()})
    outcome, _ = check_dns_txt_verification("example.com", token, resolvers=resolvers)
    assert outcome == VerificationOutcome.ABSENT


def test_dns_check_timeout_and_servfail_returns_unknown() -> None:
    """Timeouts, SERVFAIL, and network drops are transient -> UNKNOWN."""
    token = generate_verification_token()
    for exc in (
        dns.exception.Timeout(),
        dns.resolver.LifetimeTimeout(timeout=3.0, errors=[]),
        dns.resolver.NoNameservers(),
    ):
        resolvers = _pair({NEW_LABEL: exc})
        outcome, _ = check_dns_txt_verification("example.com", token, resolvers=resolvers)
        assert outcome == VerificationOutcome.UNKNOWN


def test_validating_resolver_uses_explicit_server_and_dnssec_flags() -> None:
    resolver = build_validating_resolver("9.9.9.9")
    assert resolver.nameservers == ["9.9.9.9"]
    assert resolver.flags is not None and resolver.flags & dns.flags.AD
    assert resolver.ednsflags & dns.flags.DO


def _fail_default_resolver(*args: Any, **kwargs: Any) -> Any:
    raise AssertionError("default (system) resolver used in the verification path")


def test_production_path_never_constructs_system_resolver(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Default path: one resolver per configured IP; a configured (system) one is never built."""
    queried: list[tuple[str, ...]] = []
    real_init = dns.resolver.Resolver.__init__

    def _init(self: dns.resolver.Resolver, *args: Any, **kwargs: Any) -> None:
        configure = kwargs.get("configure", args[1] if len(args) > 1 else True)
        if configure:
            raise AssertionError("system resolver constructed in the verification path")
        real_init(self, *args, **kwargs)

    def _resolve(self: dns.resolver.Resolver, name: str, rdtype: str) -> Any:
        queried.append(tuple(str(ns) for ns in self.nameservers))
        raise dns.resolver.NXDOMAIN()

    monkeypatch.setattr(dns.resolver.Resolver, "__init__", _init)
    monkeypatch.setattr(dns.resolver.Resolver, "resolve", _resolve)
    monkeypatch.setattr(dns.resolver, "get_default_resolver", _fail_default_resolver)
    monkeypatch.setattr(
        "asm.verification.get_settings",
        lambda: SimpleNamespace(verification_resolvers=["1.1.1.1", "9.9.9.9"]),
    )

    outcome, _ = check_dns_txt_verification("example.com", "tok")
    assert outcome == VerificationOutcome.ABSENT
    assert set(queried) == {("1.1.1.1",), ("9.9.9.9",)}


def test_verification_resolvers_setting_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    from asm.config import Settings

    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5432/x")
    monkeypatch.delenv("VERIFICATION_RESOLVERS", raising=False)
    assert Settings(_env_file=None).verification_resolvers == ["1.1.1.1", "9.9.9.9"]
    for bad in ('["1.1.1.1"]', '["1.1.1.1", "10.0.0.2"]', '["168.63.129.16", "1.1.1.1"]'):
        monkeypatch.setenv("VERIFICATION_RESOLVERS", bad)
        with pytest.raises(ValidationError):
            Settings(_env_file=None)


# ==============================================================================
# 2. apply_check_outcome Pure Unit Tests (Zero-Network, Zero-DB)
# ==============================================================================


def test_apply_check_outcome_match_pending_domain() -> None:
    """Rule 1: MATCH on pending domain transitions to verified, dns_txt, verified_at=now."""
    now = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
    domain = Domain(name="test.com", verification_status="pending")
    lapsed = apply_check_outcome(domain, VerificationOutcome.MATCH, now)
    assert lapsed is False
    assert domain.verification_status == "verified"
    assert domain.verification_method == "dns_txt"
    assert domain.verification_expires_at is None
    assert domain.verification_reason is None
    assert domain.consecutive_misses == 0
    assert domain.verified_at == now
    assert domain.next_reverification_at is not None
    lower_bound = now + timedelta(hours=24) - timedelta(minutes=30)
    upper_bound = now + timedelta(hours=24) + timedelta(minutes=30)
    assert lower_bound <= domain.next_reverification_at <= upper_bound


def test_apply_check_outcome_match_operator_domain() -> None:
    """Rule 1: MATCH on operator domain transitions to dns_txt, clears expires_at & reason."""
    now = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
    domain = Domain(
        name="test.com",
        verification_status="verified",
        verification_method="operator",
        verification_expires_at=now + timedelta(days=30),
        verification_reason="Emergency override",
    )
    lapsed = apply_check_outcome(domain, VerificationOutcome.MATCH, now)
    assert lapsed is False
    assert domain.verification_status == "verified"
    assert domain.verification_method == "dns_txt"
    assert domain.verification_expires_at is None
    assert domain.verification_reason is None
    assert domain.consecutive_misses == 0
    assert domain.verified_at == now
    assert domain.next_reverification_at is not None


def test_apply_check_outcome_match_already_verified_dns_txt() -> None:
    """Rule 1: MATCH on already verified dns_txt domain preserves original verified_at."""
    original_verified_at = datetime(2026, 10, 1, 10, 0, 0, tzinfo=UTC)
    now = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
    domain = Domain(
        name="test.com",
        verification_status="verified",
        verification_method="dns_txt",
        verified_at=original_verified_at,
        consecutive_misses=1,
    )
    lapsed = apply_check_outcome(domain, VerificationOutcome.MATCH, now)
    assert lapsed is False
    assert domain.verification_status == "verified"
    assert domain.verified_at == original_verified_at  # Preserved!
    assert domain.consecutive_misses == 0
    assert domain.next_reverification_at is not None


def test_apply_check_outcome_absent_verified_dns_txt_first_miss() -> None:
    """Rule 2: ABSENT on verified dns_txt with misses=0 increments misses and sets fast retry."""
    now = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
    domain = Domain(
        name="test.com",
        verification_status="verified",
        verification_method="dns_txt",
        consecutive_misses=0,
    )
    lapsed = apply_check_outcome(domain, VerificationOutcome.ABSENT, now)
    assert lapsed is False
    assert domain.verification_status == "verified"
    assert domain.consecutive_misses == 1
    assert domain.next_reverification_at is not None
    assert (
        now + timedelta(hours=1)
        <= domain.next_reverification_at
        <= now + timedelta(hours=1, minutes=5)
    )


def test_apply_check_outcome_absent_verified_dns_txt_second_miss_lapses() -> None:
    """Rule 2: ABSENT on verified dns_txt with misses=1 increments to 2 and lapses (True)."""
    now = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
    domain = Domain(
        name="test.com",
        verification_status="verified",
        verification_method="dns_txt",
        consecutive_misses=1,
    )
    lapsed = apply_check_outcome(domain, VerificationOutcome.ABSENT, now)
    assert lapsed is True
    assert domain.verification_status == "lapsed"
    assert domain.consecutive_misses == 2
    assert domain.next_reverification_at is None


def test_apply_check_outcome_absent_operator_domain_no_change() -> None:
    """Rule 3: ABSENT on operator domain leaves state completely unchanged."""
    now = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
    exp = now + timedelta(days=20)
    domain = Domain(
        name="test.com",
        verification_status="verified",
        verification_method="operator",
        verification_expires_at=exp,
        consecutive_misses=0,
    )
    lapsed = apply_check_outcome(domain, VerificationOutcome.ABSENT, now)
    assert lapsed is False
    assert domain.verification_status == "verified"
    assert domain.verification_method == "operator"
    assert domain.consecutive_misses == 0
    assert domain.verification_expires_at == exp


def test_apply_check_outcome_absent_pending_or_lapsed_no_change() -> None:
    """Rule 4: ABSENT on pending or lapsed domain causes no change."""
    now = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
    p_dom = Domain(name="p.com", verification_status="pending", consecutive_misses=0)
    assert apply_check_outcome(p_dom, VerificationOutcome.ABSENT, now) is False
    assert p_dom.verification_status == "pending"
    assert p_dom.consecutive_misses == 0

    l_dom = Domain(name="l.com", verification_status="lapsed", consecutive_misses=2)
    assert apply_check_outcome(l_dom, VerificationOutcome.ABSENT, now) is False
    assert l_dom.verification_status == "lapsed"
    assert l_dom.consecutive_misses == 2


def test_apply_check_outcome_unknown_verified_dns_txt() -> None:
    """Rule 5: UNKNOWN on verified dns_txt keeps status and misses, sets fast retry."""
    now = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
    domain = Domain(
        name="test.com",
        verification_status="verified",
        verification_method="dns_txt",
        consecutive_misses=1,
    )
    lapsed = apply_check_outcome(domain, VerificationOutcome.UNKNOWN, now)
    assert lapsed is False
    assert domain.verification_status == "verified"
    assert domain.consecutive_misses == 1  # Not incremented
    assert domain.next_reverification_at is not None
    assert (
        now + timedelta(hours=1)
        <= domain.next_reverification_at
        <= now + timedelta(hours=1, minutes=5)
    )


def test_apply_check_outcome_unknown_operator_pending_lapsed_no_change() -> None:
    """Rule 5: UNKNOWN on operator, pending, or lapsed domain causes no change."""
    now = datetime(2026, 10, 2, 12, 0, 0, tzinfo=UTC)
    op_dom = Domain(
        name="op.com",
        verification_status="verified",
        verification_method="operator",
        consecutive_misses=0,
    )
    assert apply_check_outcome(op_dom, VerificationOutcome.UNKNOWN, now) is False
    assert op_dom.verification_status == "verified"
    assert op_dom.consecutive_misses == 0
    assert op_dom.next_reverification_at is None


# ==============================================================================
# 3. Verification API Endpoints (GET, POST check, POST rotate)
# ==============================================================================


@pytest.mark.db
def test_verification_get_instructions(client: TestClient, test_org: Organization) -> None:
    """GET /domains/{id}/verification returns verification record instructions."""
    create_res = client.post(f"/orgs/{test_org.id}/domains", json={"name": "instructions.com"})
    assert create_res.status_code == 201
    domain_id = create_res.json()["id"]

    res = client.get(f"/orgs/{test_org.id}/domains/{domain_id}/verification")
    assert res.status_code == 200
    data = res.json()
    assert data["domain_id"] == domain_id
    assert data["domain_name"] == "instructions.com"
    assert data["status"] == "pending"
    assert data["record_name"] == "_exposight-challenge.instructions.com"
    assert data["record_type"] == "TXT"
    assert data["record_value"].startswith("exposight-verify=")
    assert data["consecutive_misses"] == 0
    assert data["is_verified"] is False


@pytest.mark.db
def test_verification_check_endpoint_match_and_absent(
    client: TestClient, test_org: Organization, db_session: Session
) -> None:
    """POST /domains/{id}/verification/check transitions to verified on MATCH."""
    create_res = client.post(f"/orgs/{test_org.id}/domains", json={"name": "check-endpoint.com"})
    domain_id = create_res.json()["id"]

    # 1. ABSENT -> stays pending
    with patch(
        "asm.api.routes.check_dns_txt_verification",
        return_value=(VerificationOutcome.ABSENT, "Record not found"),
    ):
        res_absent = client.post(f"/orgs/{test_org.id}/domains/{domain_id}/verification/check")
        assert res_absent.status_code == 200
        data_absent = res_absent.json()
        assert data_absent["status"] == "pending"
        assert data_absent["is_verified"] is False
        assert data_absent["check_outcome"] == "absent"

    # 2. MATCH -> transitions to verified
    with patch(
        "asm.api.routes.check_dns_txt_verification",
        return_value=(VerificationOutcome.MATCH, "Exact match verified"),
    ):
        dom = db_session.get(Domain, domain_id)
        assert dom is not None
        dom.last_checked_at = datetime.now(UTC) - timedelta(seconds=35)
        db_session.commit()

        res_match = client.post(f"/orgs/{test_org.id}/domains/{domain_id}/verification/check")
        assert res_match.status_code == 200
        data_match = res_match.json()
        assert data_match["status"] == "verified"
        assert data_match["is_verified"] is True
        assert data_match["verified_at"] is not None
        assert data_match["check_outcome"] == "match"


@pytest.mark.db
def test_verification_check_cooldown_429(client: TestClient, test_org: Organization) -> None:
    """Calling verification check twice within 30s returns 429 Too Many Requests."""
    create_res = client.post(f"/orgs/{test_org.id}/domains", json={"name": "cooldown.com"})
    domain_id = create_res.json()["id"]

    with patch(
        "asm.api.routes.check_dns_txt_verification",
        return_value=(VerificationOutcome.ABSENT, "Missing"),
    ):
        res1 = client.post(f"/orgs/{test_org.id}/domains/{domain_id}/verification/check")
        assert res1.status_code == 200

        # Immediate second call -> 429
        res2 = client.post(f"/orgs/{test_org.id}/domains/{domain_id}/verification/check")
        assert res2.status_code == 429
        assert "cooldown" in res2.json()["detail"].lower()


@pytest.mark.db
def test_cooldown_holds_across_two_sessions(db_engine, clean_db: None) -> None:
    """Cooldown is enforced via last_checked_at under row-lock across separate DB sessions."""
    session_factory = sessionmaker(bind=db_engine)

    # 1. Setup domain
    with session_factory() as session1:
        org = Organization(name="Cooldown Org")
        session1.add(org)
        session1.flush()
        domain = Domain(org_id=org.id, name="db-cooldown.com")
        session1.add(domain)
        session1.commit()
        domain_id = domain.id

    # 2. Session 1 performs check and sets last_checked_at = now()
    now_ts = datetime.now(UTC)
    with session_factory() as session1:
        dom1 = session1.get(Domain, domain_id)
        assert dom1 is not None
        dom1.last_checked_at = now_ts
        session1.commit()

    # 3. Session 2 inspects under row lock and confirms cooldown condition holds
    with session_factory() as session2:
        dom2 = (
            session2.execute(
                select(Domain).where(Domain.id == domain_id).with_for_update()
            )
            .scalars()
            .first()
        )
        assert dom2 is not None
        assert dom2.last_checked_at is not None
        elapsed = (datetime.now(UTC) - dom2.last_checked_at).total_seconds()
        assert elapsed < VERIFICATION_CHECK_COOLDOWN_SECONDS


@pytest.mark.db
def test_rotate_invalidates_old_token(client: TestClient, test_org: Organization) -> None:
    """Rotating verification token generates a new token and resets status to pending."""
    create_res = client.post(f"/orgs/{test_org.id}/domains", json={"name": "rotate.com"})
    domain_id = create_res.json()["id"]
    old_token = create_res.json()["verification_token"]

    # First verify it
    with patch(
        "asm.api.routes.check_dns_txt_verification",
        return_value=(VerificationOutcome.MATCH, "Verified"),
    ):
        check_res = client.post(f"/orgs/{test_org.id}/domains/{domain_id}/verification/check")
        assert check_res.status_code == 200
        assert check_res.json()["status"] == "verified"

    # Rotate token
    rotate_res = client.post(f"/orgs/{test_org.id}/domains/{domain_id}/verification/rotate")
    assert rotate_res.status_code == 200
    data = rotate_res.json()
    new_token = data["token"]
    assert new_token != old_token
    assert data["status"] == "pending"
    assert data["is_verified"] is False
    assert data["consecutive_misses"] == 0


@pytest.mark.db
def test_cross_org_token_isolation(client: TestClient, db_session: Session) -> None:
    """Org A and Org B both create example.com; Org A's DNS token never verifies Org B."""
    test_user_id = UUID("00000000-0000-0000-0000-000000000001")
    org_a = Organization(name="Tenant Alpha")
    org_b = Organization(name="Tenant Beta")
    db_session.add_all([org_a, org_b])
    db_session.flush()

    mem_a = Membership(org_id=org_a.id, user_id=test_user_id, role="owner")
    mem_b = Membership(org_id=org_b.id, user_id=test_user_id, role="owner")
    db_session.add_all([mem_a, mem_b])
    db_session.flush()

    res_a = client.post(f"/orgs/{org_a.id}/domains", json={"name": "shared-tenant.com"})
    res_b = client.post(f"/orgs/{org_b.id}/domains", json={"name": "shared-tenant.com"})
    assert res_a.status_code == 201
    assert res_b.status_code == 201

    token_a = res_a.json()["verification_token"]
    token_b = res_b.json()["verification_token"]
    assert token_a != token_b
    domain_a_id = res_a.json()["id"]
    domain_b_id = res_b.json()["id"]

    # DNS publishes Org A's token
    def _mock_dns(domain_name: str, expected_token: str) -> tuple[VerificationOutcome, str]:
        if expected_token == token_a:
            return (VerificationOutcome.MATCH, "Match")
        return (VerificationOutcome.ABSENT, "No match")

    with patch("asm.api.routes.check_dns_txt_verification", side_effect=_mock_dns):
        check_a = client.post(f"/orgs/{org_a.id}/domains/{domain_a_id}/verification/check")
        assert check_a.status_code == 200
        assert check_a.json()["status"] == "verified"

        check_b = client.post(f"/orgs/{org_b.id}/domains/{domain_b_id}/verification/check")
        assert check_b.status_code == 200
        assert check_b.json()["status"] == "pending"


# ==============================================================================
# 3. Continuous Re-verification Worker Tests (Misses, Lapses, Outbox Alerts)
# ==============================================================================


@pytest.mark.db
def test_reverification_two_definite_misses_lapses(db_engine, clean_db: None) -> None:
    """Verified domain lapses after 2 consecutive definite misses; fast 1h retry on 1st miss."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="Reverify Org")
        session.add(org)
        session.flush()
        domain = Domain(
            org_id=org.id,
            name="lapse-test.com",
            verification_status="verified",
            next_reverification_at=datetime.now(UTC) - timedelta(minutes=5),
            consecutive_misses=0,
            alerts_enabled=True,
            alert_emails=["ops@lapse-test.com"],
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id

    worker = ASMWorker(engine=db_engine)

    # Cycle 1: First definite miss (ABSENT) -> misses=1, remains verified, fast retry ~1h
    with patch(
        "asm.worker.worker.check_dns_txt_verification",
        return_value=(VerificationOutcome.ABSENT, "Missing"),
    ):
        count = worker.reverify_due_domains(batch_limit=10)
        assert count == 1

    with session_factory() as session:
        d1 = session.get(Domain, domain_id)
        assert d1 is not None
        assert d1.verification_status == "verified"
        assert d1.consecutive_misses == 1
        assert d1.next_reverification_at is not None
        # Fast retry scheduled roughly 1 hour in the future (+ jitter up to 300s)
        diff = (d1.next_reverification_at - datetime.now(UTC)).total_seconds()
        assert 3500 <= diff <= 4000

        # No outbox alert on first miss
        stmt = select(AlertNotification).where(AlertNotification.domain_id == domain_id)
        outbox = session.scalars(stmt).all()
        assert len(outbox) == 0

        # Backdate next_reverification_at for cycle 2
        d1.next_reverification_at = datetime.now(UTC) - timedelta(minutes=5)
        session.commit()

    # Cycle 2: Second definite miss (ABSENT) -> misses=2, status=lapsed, outbox alert!
    with patch(
        "asm.worker.worker.check_dns_txt_verification",
        return_value=(VerificationOutcome.ABSENT, "Missing"),
    ):
        count = worker.reverify_due_domains(batch_limit=10)
        assert count == 1

    with session_factory() as session:
        d2 = session.get(Domain, domain_id)
        assert d2 is not None
        assert d2.verification_status == "lapsed"
        assert d2.consecutive_misses == 2
        # Polling stopped for lapsed domains
        assert d2.next_reverification_at is None

        # Outbox alert written atomically
        stmt = select(AlertNotification).where(AlertNotification.domain_id == domain_id)
        outbox = session.scalars(stmt).all()
        assert len(outbox) == 1
        assert outbox[0].recipient == "ops@lapse-test.com"
        assert "Domain verification lapsed: monitoring paused" in outbox[0].subject


@pytest.mark.db
def test_reverification_timeouts_never_lapse(db_engine, clean_db: None) -> None:
    """DNS UNKNOWN outcomes (timeouts) never count as misses and never cause a lapse."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="Timeout Org")
        session.add(org)
        session.flush()
        domain = Domain(
            org_id=org.id,
            name="timeout-safe.com",
            verification_status="verified",
            next_reverification_at=datetime.now(UTC) - timedelta(minutes=5),
            consecutive_misses=1,  # Already at 1 miss!
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id

    worker = ASMWorker(engine=db_engine)

    # UNKNOWN outcome
    with patch(
        "asm.worker.worker.check_dns_txt_verification",
        return_value=(VerificationOutcome.UNKNOWN, "Timeout"),
    ):
        count = worker.reverify_due_domains(batch_limit=10)
        assert count == 1

    with session_factory() as session:
        dom = session.get(Domain, domain_id)
        assert dom is not None
        # Must still be verified and misses unchanged at 1
        assert dom.verification_status == "verified"
        assert dom.consecutive_misses == 1


# ==============================================================================
# 4. Scanning & Pipeline Gating Tests
# ==============================================================================


@pytest.mark.db
def test_enqueue_blocked_unless_verified(db_engine, clean_db: None) -> None:
    """enqueue_scan strictly raises UnverifiedDomainError for pending and lapsed domains."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="Gate Org")
        session.add(org)
        session.flush()

        d_pending = Domain(org_id=org.id, name="pending.com", verification_status="pending")
        d_lapsed = Domain(org_id=org.id, name="lapsed.com", verification_status="lapsed")
        d_verified = Domain(org_id=org.id, name="verified.com", verification_status="verified")
        session.add_all([d_pending, d_lapsed, d_verified])
        session.commit()

        # Pending -> rejected
        with pytest.raises(UnverifiedDomainError, match="not verified"):
            enqueue_scan(session, d_pending.id, trigger="manual")

        # Lapsed -> rejected
        with pytest.raises(UnverifiedDomainError, match="not verified"):
            enqueue_scan(session, d_lapsed.id, trigger="manual")

        # Verified -> accepted
        run = enqueue_scan(session, d_verified.id, trigger="manual")
        assert run.id > 0


# ==============================================================================
# 5. Operator Override CLI, Expiration, and Revocation Tests
# ==============================================================================


@pytest.mark.db
def test_operator_override_requires_reason(db_engine, clean_db: None) -> None:
    """asm admin verify-domain requires a non-empty reason and enforces 1..90 day expiry."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="Override Org")
        session.add(org)
        session.flush()
        domain = Domain(org_id=org.id, name="override-test.com")
        session.add(domain)
        session.commit()
        domain_id = domain.id

    # 1. Empty reason rejected
    with session_factory() as session:
        res_empty = verify_domain(
            session, domain_id=domain_id, reason="", expires_in_days=30
        )
        assert res_empty == 1

    # 2. Expiry > 90 rejected
    with session_factory() as session:
        res_high = verify_domain(
            session, domain_id=domain_id, reason="Valid reason", expires_in_days=95
        )
        assert res_high == 1

    # 3. Valid invocation
    with session_factory() as session:
        res_ok = verify_domain(
            session,
            domain_id=domain_id,
            reason="Manual customer onboarding contract",
            expires_in_days=45,
        )
        assert res_ok == 0

    with session_factory() as session:
        dom = session.get(Domain, domain_id)
        assert dom is not None
        assert dom.verification_status == "verified"
        assert dom.verification_method == "operator"
        assert dom.verification_reason == "Manual customer onboarding contract"
        assert dom.verification_expires_at is not None
        exp_diff = (dom.verification_expires_at - datetime.now(UTC)).days
        assert 44 <= exp_diff <= 45


@pytest.mark.db
def test_operator_override_expiry_to_pending(db_engine, clean_db: None) -> None:
    """Expired operator overrides are transitioned to pending and alert outbox is written."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="Expiry Org")
        session.add(org)
        session.flush()
        domain = Domain(
            org_id=org.id,
            name="expiring-override.com",
            verification_status="verified",
            verification_method="operator",
            verification_reason="Short trial",
            verification_expires_at=datetime.now(UTC) - timedelta(hours=1),
            alerts_enabled=True,
            alert_emails=["admin@expiring-override.com"],
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id

    worker = ASMWorker(engine=db_engine)
    expired_count = worker.expire_operator_overrides(batch_limit=10)
    assert expired_count == 1

    with session_factory() as session:
        dom = session.get(Domain, domain_id)
        assert dom is not None
        assert dom.verification_status == "pending"

        # Outbox notification written
        stmt = select(AlertNotification).where(AlertNotification.domain_id == domain_id)
        outbox = session.scalars(stmt).all()
        assert len(outbox) == 1
        assert outbox[0].recipient == "admin@expiring-override.com"
        assert "Domain verification lapsed: monitoring paused" in outbox[0].subject


@pytest.mark.db
def test_operator_revoke_requires_reason_and_resets_pending(db_engine, clean_db: None) -> None:
    """asm admin revoke-verification requires non-empty reason and resets status to pending."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="Revoke Org")
        session.add(org)
        session.flush()
        domain = Domain(
            org_id=org.id,
            name="revoke-me.com",
            verification_status="verified",
            alerts_enabled=True,
            alert_emails=["team@revoke-me.com"],
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id

    # 1. Empty reason rejected
    with session_factory() as session:
        assert revoke_verification(session, domain_id=domain_id, reason="") == 1

    # 2. Valid revoke
    with session_factory() as session:
        assert (
            revoke_verification(
                session, domain_id=domain_id, reason="Customer churned and deleted asset"
            )
            == 0
        )

    with session_factory() as session:
        dom = session.get(Domain, domain_id)
        assert dom is not None
        assert dom.verification_status == "pending"
        assert "Customer churned" in (dom.verification_reason or "")

        # Outbox notification recorded
        stmt = select(AlertNotification).where(AlertNotification.domain_id == domain_id)
        outbox = session.scalars(stmt).all()
        assert len(outbox) == 1
        assert "Domain verification lapsed: monitoring paused" in outbox[0].subject


class _LapsingMockRunner:
    """Mock runner that lapses the domain in the DB during discover stage."""

    def __init__(self, db_engine, domain_id: int) -> None:
        self.db_engine = db_engine
        self.domain_id = domain_id

    def run_discover(self, domain: str) -> dict[str, Any]:
        # Lapsed mid-scan after discover
        with self.db_engine.begin() as conn:
            conn.execute(
                text("UPDATE domains SET verification_status = 'lapsed' WHERE id = :id"),
                {"id": self.domain_id},
            )
        return {"domain": domain, "results": [{"subdomain": f"api.{domain}"}]}

    def run_probe(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return {"domain": domain, "results": []}

    def run_portscan(
        self, domain: str, discover_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return {"domain": domain, "results": []}

    def run_inspect(
        self, domain: str, probe_report: dict[str, Any], authorized: bool
    ) -> dict[str, Any]:
        return {"domain": domain, "results": []}

    def run_score(self, domain: str, **kwargs) -> dict[str, Any]:
        return {"domain": domain, "domain_score": 10, "counts": {}}


@pytest.mark.db
def test_worker_stops_mid_scan_when_lapsed(db_engine, clean_db: None) -> None:
    """Worker checks domain verification before every stage and halts mid-scan if lapsed."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="Midscan Org")
        session.add(org)
        session.flush()
        domain = Domain(
            org_id=org.id,
            name="midscan-lapse.com",
            verification_status="verified",
        )
        session.add(domain)
        session.flush()
        domain_id = domain.id

        run = enqueue_scan(session, domain_id, trigger="manual")
        session.commit()
        scan_id = run.id

    runner = _LapsingMockRunner(db_engine=db_engine, domain_id=domain_id)
    worker = ASMWorker(engine=db_engine, runner=runner)
    claimed = worker.run_poll_cycle()
    assert claimed is True

    with session_factory() as session:
        run_record = session.get(ScanRun, scan_id)
        assert run_record is not None
        assert run_record.status == "failed"
        assert "verification lapsed/revoked" in (run_record.error or "").lower()


@pytest.mark.db
def test_cli_admin_verify_and_revoke(db_engine, clean_db: None, monkeypatch) -> None:
    """Test CLI dispatch for 'asm admin verify-domain' and 'asm admin revoke-verification'."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="CLI Admin Org")
        session.add(org)
        session.flush()
        domain = Domain(org_id=org.id, name="cli-admin.com")
        session.add(domain)
        session.commit()
        domain_id = domain.id

    # Mock get_session_factory in asm.db.session to use test session_factory
    monkeypatch.setattr("asm.db.session.get_session_factory", lambda: session_factory)

    # 1. verify-domain via CLI without reason fails (argparse raises SystemExit)
    with pytest.raises(SystemExit):
        cli_main(["admin", "verify-domain", "--domain-id", str(domain_id)])

    # verify-domain with empty/whitespace reason fails with exit code 1
    exit_empty_reason = cli_main([
        "admin",
        "verify-domain",
        "--domain-id",
        str(domain_id),
        "--reason",
        "   ",
    ])
    assert exit_empty_reason == 1

    # 2. verify-domain via CLI with valid reason succeeds
    exit_ok = cli_main([
        "admin",
        "verify-domain",
        "--domain-id",
        str(domain_id),
        "--reason",
        "CLI approval",
        "--expires-in-days",
        "15",
    ])
    assert exit_ok == 0

    with session_factory() as session:
        dom = session.get(Domain, domain_id)
        assert dom is not None
        assert dom.verification_status == "verified"
        assert dom.verification_method == "operator"

    # 3. revoke-verification via CLI without reason fails
    with pytest.raises(SystemExit):
        cli_main(["admin", "revoke-verification", "--domain-id", str(domain_id)])

    exit_empty_revoke = cli_main([
        "admin",
        "revoke-verification",
        "--domain-id",
        str(domain_id),
        "--reason",
        "   ",
    ])
    assert exit_empty_revoke == 1

    # revoke-verification with valid reason succeeds
    exit_revoke = cli_main([
        "admin",
        "revoke-verification",
        "--domain-id",
        str(domain_id),
        "--reason",
        "CLI revocation",
    ])
    assert exit_revoke == 0

    with session_factory() as session:
        dom = session.get(Domain, domain_id)
        assert dom is not None
        assert dom.verification_status == "pending"


# ==============================================================================
# 6. Additional DB Invariant Tests (Remediation & Review Suite)
# ==============================================================================


@pytest.mark.db
def test_operator_domain_match_transitions_to_dns_txt_and_reverified_by_worker(
    lifecycle_client: TestClient, lifecycle_org: Organization, db_engine, clean_db: None
) -> None:
    """Operator domain verified via DNS MATCH switches to dns_txt and worker reverifies."""
    session_factory = sessionmaker(bind=db_engine)
    now = datetime.now(UTC)
    with session_factory() as session:
        dom = Domain(
            org_id=lifecycle_org.id,
            name="op-to-dns.com",
            verification_status="verified",
            verification_method="operator",
            verification_expires_at=now + timedelta(days=30),
            verification_reason="Manual test override",
            consecutive_misses=0,
        )
        session.add(dom)
        session.commit()
        domain_id = dom.id

    # POST /verification/check with MATCH
    with patch(
        "asm.api.routes.check_dns_txt_verification",
        return_value=(VerificationOutcome.MATCH, "Exact match verified"),
    ):
        res = lifecycle_client.post(
            f"/orgs/{lifecycle_org.id}/domains/{domain_id}/verification/check"
        )
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "verified"
        assert data["method"] == "dns_txt"
        assert data["check_outcome"] == "match"

    with session_factory() as session:
        reloaded = session.get(Domain, domain_id)
        assert reloaded is not None
        assert reloaded.verification_method == "dns_txt"
        assert reloaded.verification_expires_at is None
        assert reloaded.verification_reason is None
        assert reloaded.next_reverification_at is not None

        # Backdate next_reverification_at and verify worker reverify processes it when due
        reloaded.next_reverification_at = now - timedelta(minutes=5)
        session.commit()

    worker = ASMWorker(engine=db_engine)
    with patch(
        "asm.worker.worker.check_dns_txt_verification",
        return_value=(VerificationOutcome.MATCH, "Re-verification match"),
    ):
        count = worker.reverify_due_domains(batch_limit=10)
        assert count == 1

    with session_factory() as session:
        re_checked = session.get(Domain, domain_id)
        assert re_checked is not None
        assert re_checked.verification_status == "verified"
        assert re_checked.verification_method == "dns_txt"
        assert re_checked.consecutive_misses == 0


@pytest.mark.db
def test_full_broken_path_operator_expiry_match_two_misses_lapsed_alerts(
    db_engine, clean_db: None
) -> None:
    """Full broken path: operator expires -> pending -> MATCH -> 2 misses -> lapsed + alerts."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="Broken Path Org")
        session.add(org)
        session.flush()
        domain = Domain(
            org_id=org.id,
            name="broken-path.com",
            verification_status="verified",
            verification_method="operator",
            verification_reason="Temporary contract",
            verification_expires_at=datetime.now(UTC) - timedelta(hours=2),
            alerts_enabled=True,
            alert_emails=["ops1@broken-path.com", "ops2@broken-path.com"],
        )
        session.add(domain)
        session.commit()
        domain_id = domain.id

    worker = ASMWorker(engine=db_engine)

    # 1. Operator override expires -> pending + dns_txt + 1 alert row per email
    expired = worker.expire_operator_overrides(batch_limit=10)
    assert expired == 1

    with session_factory() as session:
        d = session.get(Domain, domain_id)
        assert d is not None
        assert d.verification_status == "pending"
        assert d.verification_method == "dns_txt"

        alerts = session.scalars(
            select(AlertNotification).where(AlertNotification.domain_id == domain_id)
        ).all()
        assert len(alerts) == 2
        assert {a.recipient for a in alerts} == {"ops1@broken-path.com", "ops2@broken-path.com"}
        assert "Domain verification lapsed: monitoring paused" in alerts[0].subject

    # 2. Check MATCH -> verified + dns_txt, misses=0
    with session_factory() as session:
        d = session.get(Domain, domain_id)
        assert d is not None
        apply_check_outcome(d, VerificationOutcome.MATCH, datetime.now(UTC))
        session.commit()

    with session_factory() as session:
        d = session.get(Domain, domain_id)
        assert d is not None
        assert d.verification_status == "verified"
        assert d.consecutive_misses == 0
        assert d.next_reverification_at is not None

        # Backdate next_reverification_at for Miss 1
        d.next_reverification_at = datetime.now(UTC) - timedelta(minutes=5)
        session.commit()

    # 3. Re-verify Miss 1 (ABSENT) -> misses=1, still verified, no new alert
    with patch(
        "asm.worker.worker.check_dns_txt_verification",
        return_value=(VerificationOutcome.ABSENT, "Missing"),
    ):
        worker.reverify_due_domains(batch_limit=10)

    with session_factory() as session:
        d = session.get(Domain, domain_id)
        assert d is not None
        assert d.verification_status == "verified"
        assert d.consecutive_misses == 1

        alerts_after_m1 = session.scalars(
            select(AlertNotification).where(AlertNotification.domain_id == domain_id)
        ).all()
        assert len(alerts_after_m1) == 2

        # Backdate next_reverification_at for Miss 2
        d.next_reverification_at = datetime.now(UTC) - timedelta(minutes=5)
        session.commit()

    # 4. Re-verify Miss 2 (ABSENT) -> misses=2, status=lapsed, outbox alerts written!
    with patch(
        "asm.worker.worker.check_dns_txt_verification",
        return_value=(VerificationOutcome.ABSENT, "Missing"),
    ):
        worker.reverify_due_domains(batch_limit=10)

    with session_factory() as session:
        d = session.get(Domain, domain_id)
        assert d is not None
        assert d.verification_status == "lapsed"
        assert d.consecutive_misses == 2
        assert d.next_reverification_at is None

        all_alerts = session.scalars(
            select(AlertNotification).where(AlertNotification.domain_id == domain_id)
        ).all()
        # 2 alerts from expiry + 2 alerts from lapse = 4 total
        assert len(all_alerts) == 4


@pytest.mark.db
def test_operator_domain_two_absent_checks_stays_verified_misses_zero(
    client: TestClient, test_org: Organization, db_session: Session
) -> None:
    """Operator-verified domain subjected to 2 ABSENT checks remains verified with misses 0."""
    now = datetime.now(UTC)
    domain = Domain(
        org_id=test_org.id,
        name="op-absent-safe.com",
        verification_status="verified",
        verification_method="operator",
        verification_expires_at=now + timedelta(days=30),
        verification_reason="Authorized exception",
        consecutive_misses=0,
    )
    db_session.add(domain)
    db_session.commit()
    domain_id = domain.id

    with patch(
        "asm.api.routes.check_dns_txt_verification",
        return_value=(VerificationOutcome.ABSENT, "No record found"),
    ):
        # Check 1
        res1 = client.post(f"/orgs/{test_org.id}/domains/{domain_id}/verification/check")
        assert res1.status_code == 200
        assert res1.json()["status"] == "verified"
        assert res1.json()["consecutive_misses"] == 0
        assert res1.json()["check_outcome"] == "absent"

        # Reset last_checked_at to 35 seconds ago to bypass cooldown
        db_session.expire_all()
        d1 = db_session.get(Domain, domain_id)
        assert d1 is not None
        d1.last_checked_at = datetime.now(UTC) - timedelta(seconds=35)
        db_session.commit()

        # Check 2
        res2 = client.post(f"/orgs/{test_org.id}/domains/{domain_id}/verification/check")
        assert res2.status_code == 200
        assert res2.json()["status"] == "verified"
        assert res2.json()["consecutive_misses"] == 0
        assert res2.json()["check_outcome"] == "absent"

    db_session.expire_all()
    dom = db_session.get(Domain, domain_id)
    assert dom is not None
    assert dom.verification_status == "verified"
    assert dom.verification_method == "operator"
    assert dom.consecutive_misses == 0


@pytest.mark.db
def test_viewer_role_forbidden_on_check_and_rotate_allowed_on_get(
    client: TestClient, test_org: Organization, db_session: Session
) -> None:
    """Viewer role receives 403 on POST check and rotate, but 200 on GET verification."""
    create_res = client.post(f"/orgs/{test_org.id}/domains", json={"name": "viewer-role.com"})
    assert create_res.status_code == 201
    domain_id = create_res.json()["id"]

    # Demote user's membership to 'viewer'
    test_user_id = UUID("00000000-0000-0000-0000-000000000001")
    membership = (
        db_session.execute(
            select(Membership).where(
                Membership.org_id == test_org.id, Membership.user_id == test_user_id
            )
        )
        .scalars()
        .first()
    )
    assert membership is not None
    membership.role = "viewer"
    db_session.commit()

    # 1. GET /verification -> 200 OK
    get_res = client.get(f"/orgs/{test_org.id}/domains/{domain_id}/verification")
    assert get_res.status_code == 200
    assert get_res.json()["domain_id"] == domain_id

    # 2. POST /verification/check -> 403 Forbidden
    check_res = client.post(f"/orgs/{test_org.id}/domains/{domain_id}/verification/check")
    assert check_res.status_code == 403
    assert "insufficient organization permissions" in check_res.json()["detail"].lower()

    # 3. POST /verification/rotate -> 403 Forbidden
    rotate_res = client.post(f"/orgs/{test_org.id}/domains/{domain_id}/verification/rotate")
    assert rotate_res.status_code == 403
    assert "insufficient organization permissions" in rotate_res.json()["detail"].lower()


@pytest.mark.db
def test_check_response_carries_outcome_and_detail(
    client: TestClient, test_org: Organization, db_session: Session
) -> None:
    """POST /verification/check returns check_outcome and check_detail for all outcomes."""
    create_res = client.post(f"/orgs/{test_org.id}/domains", json={"name": "outcome-detail.com"})
    domain_id = create_res.json()["id"]

    # 1. MATCH
    with patch(
        "asm.api.routes.check_dns_txt_verification",
        return_value=(VerificationOutcome.MATCH, "Exact TXT match verified"),
    ):
        res_m = client.post(f"/orgs/{test_org.id}/domains/{domain_id}/verification/check")
        assert res_m.status_code == 200
        data_m = res_m.json()
        assert data_m["check_outcome"] == "match"
        assert data_m["check_detail"] == "Exact TXT match verified"

    # Reset cooldown
    db_session.expire_all()
    dom = db_session.get(Domain, domain_id)
    assert dom is not None
    dom.last_checked_at = datetime.now(UTC) - timedelta(seconds=35)
    db_session.commit()

    # 2. ABSENT
    with patch(
        "asm.api.routes.check_dns_txt_verification",
        return_value=(VerificationOutcome.ABSENT, "No TXT record found"),
    ):
        res_a = client.post(f"/orgs/{test_org.id}/domains/{domain_id}/verification/check")
        assert res_a.status_code == 200
        data_a = res_a.json()
        assert data_a["check_outcome"] == "absent"
        assert data_a["check_detail"] == "No TXT record found"

    # Reset cooldown
    db_session.expire_all()
    dom = db_session.get(Domain, domain_id)
    assert dom is not None
    dom.last_checked_at = datetime.now(UTC) - timedelta(seconds=35)
    db_session.commit()

    # 3. UNKNOWN
    with patch(
        "asm.api.routes.check_dns_txt_verification",
        return_value=(VerificationOutcome.UNKNOWN, "DNS resolver timed out"),
    ):
        res_u = client.post(f"/orgs/{test_org.id}/domains/{domain_id}/verification/check")
        assert res_u.status_code == 200
        data_u = res_u.json()
        assert data_u["check_outcome"] == "unknown"
        assert data_u["check_detail"] == "DNS resolver timed out"

    # GET /verification does NOT carry check_outcome or check_detail
    get_res = client.get(f"/orgs/{test_org.id}/domains/{domain_id}/verification")
    assert get_res.status_code == 200
    assert get_res.json()["check_outcome"] is None
    assert get_res.json()["check_detail"] is None


@pytest.mark.db
def test_domain_level_alert_delivered_by_worker(db_engine, clean_db: None) -> None:
    """A domain-level alert (scan_run_id is None) is delivered by worker and marked sent."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="Alert Delivery Org")
        session.add(org)
        session.flush()
        domain = Domain(
            org_id=org.id,
            name="alert-delivery.com",
            verification_status="verified",
            alerts_enabled=True,
            alert_emails=["ops@alert-delivery.com"],
        )
        session.add(domain)
        session.flush()

        queued = queue_domain_alert(
            session=session,
            domain=domain,
            subject="Domain verification lapsed: monitoring paused",
            body="Your domain has lapsed due to missing DNS TXT records.",
        )
        assert queued == 1
        session.commit()
        domain_id = domain.id

    with session_factory() as session:
        notif = session.scalars(
            select(AlertNotification).where(AlertNotification.domain_id == domain_id)
        ).first()
        assert notif is not None
        assert notif.scan_run_id is None
        assert notif.status == "pending"
        notif_id = notif.id

    worker = ASMWorker(engine=db_engine, smtp_host="mock-smtp.local")
    with patch("asm.worker.worker.send_smtp_email") as mock_send:
        delivered = worker.deliver_pending_alerts()
        assert delivered == 1
        assert mock_send.call_count == 1

    with session_factory() as session:
        sent_notif = session.get(AlertNotification, notif_id)
        assert sent_notif is not None
        assert sent_notif.status == "sent"
        assert sent_notif.sent_at is not None
        assert sent_notif.attempts == 1
        assert sent_notif.scan_run_id is None


@pytest.mark.db
def test_verify_domain_expires_in_days_validation(db_engine, clean_db: None) -> None:
    """verify_domain rejects --expires-in-days 0 and 91, accepts 1 and 90."""
    session_factory = sessionmaker(bind=db_engine)
    with session_factory() as session:
        org = Organization(name="Expiry Val Org")
        session.add(org)
        session.flush()
        domain = Domain(org_id=org.id, name="expiry-val.com")
        session.add(domain)
        session.commit()
        domain_id = domain.id

    # 1. 0 days -> rejected (exit code 1)
    with session_factory() as session:
        res_0 = verify_domain(session, domain_id=domain_id, reason="Reason", expires_in_days=0)
        assert res_0 == 1

    # 2. 91 days -> rejected (exit code 1)
    with session_factory() as session:
        res_91 = verify_domain(session, domain_id=domain_id, reason="Reason", expires_in_days=91)
        assert res_91 == 1

    # 3. 1 day -> accepted (exit code 0)
    with session_factory() as session:
        res_1 = verify_domain(session, domain_id=domain_id, reason="Reason", expires_in_days=1)
        assert res_1 == 0

    with session_factory() as session:
        d1 = session.get(Domain, domain_id)
        assert d1 is not None
        assert d1.verification_status == "verified"
        assert d1.verification_expires_at is not None
        diff1 = (d1.verification_expires_at - datetime.now(UTC)).total_seconds()
        assert 80000 <= diff1 <= 86500

    # 4. 90 days -> accepted (exit code 0)
    with session_factory() as session:
        res_90 = verify_domain(session, domain_id=domain_id, reason="Reason", expires_in_days=90)
        assert res_90 == 0

    with session_factory() as session:
        d90 = session.get(Domain, domain_id)
        assert d90 is not None
        assert d90.verification_status == "verified"
        assert d90.verification_expires_at is not None
        diff90 = (d90.verification_expires_at - datetime.now(UTC)).days
        assert 89 <= diff90 <= 90


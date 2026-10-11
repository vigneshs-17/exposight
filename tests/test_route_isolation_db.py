"""Route-complete tenant isolation oracle (review item E-3, checkpoint R-1).

Every route in ``app.routes`` is listed in ROUTES with a class:

- TENANT_SCOPED: carries an org/domain/scan/invite/user id that belongs to a tenant.
- LIST_SCOPED: returns a list that must contain only the caller's tenant's data
  (those with an org id in the path also get the TENANT_SCOPED checks).
- PUBLIC_OR_SELF: no tenant data, or acts only on the caller; each has a reason.

User B (owner of org B) calls every tenant route with org A's real ids and must get
404 (403 only where CROSS_TENANT_403 documents it), no org-A data in the body, and,
for writes, no change to org A's rows.
"""

import re
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from asm.api.main import app
from asm.api.routes_orgs import hash_invite_token
from asm.audit import record_event
from asm.db.models import Membership, OrgInvite, User
from tests.test_tenant_isolation import make_authenticated_client, two_tenants  # noqa: F401

pytestmark = pytest.mark.db

TENANT, LIST, PUBLIC = "TENANT_SCOPED", "LIST_SCOPED", "PUBLIC_OR_SELF"

# (method, path) -> (class, reason). PUBLIC_OR_SELF entries must give a reason.
ROUTES: dict[tuple[str, str], tuple[str, str]] = {
    # FastAPI built-ins (absent in production, see main.docs_urls).
    ("GET", "/openapi.json"): (PUBLIC, "API schema, no tenant data; disabled in production"),
    ("HEAD", "/openapi.json"): (PUBLIC, "API schema, no tenant data; disabled in production"),
    ("GET", "/docs"): (PUBLIC, "Swagger UI page, no tenant data; disabled in production"),
    ("HEAD", "/docs"): (PUBLIC, "Swagger UI page, no tenant data; disabled in production"),
    ("GET", "/docs/oauth2-redirect"): (PUBLIC, "static Swagger helper page, no tenant data"),
    ("HEAD", "/docs/oauth2-redirect"): (PUBLIC, "static Swagger helper page, no tenant data"),
    ("GET", "/redoc"): (PUBLIC, "ReDoc page, no tenant data; disabled in production"),
    ("HEAD", "/redoc"): (PUBLIC, "ReDoc page, no tenant data; disabled in production"),
    ("MOUNT", "/static"): (PUBLIC, "static CSS/JS files shipped with the app"),
    # routes_ui.py
    ("GET", "/"): (PUBLIC, "public landing page, static content"),
    ("GET", "/terms"): (PUBLIC, "public terms page, static content"),
    ("GET", "/app"): (PUBLIC, "dashboard shell; only public Supabase URL and publishable key"),
    ("GET", "/ui/empty-org"): (PUBLIC, "create-organization form, no data"),
    ("GET", "/ui/orgs/{org_id}/domains"): (LIST, ""),
    ("GET", "/ui/orgs/{org_id}/domains/{domain_id}"): (TENANT, ""),
    ("GET", "/ui/orgs/{org_id}/domains/{domain_id}/scans"): (LIST, ""),
    ("GET", "/ui/orgs/{org_id}/scans/{scan_id}"): (TENANT, ""),
    ("GET", "/ui/orgs/{org_id}/domains/{domain_id}/alert-notifications"): (LIST, ""),
    ("GET", "/ui/orgs/{org_id}/audit-events"): (LIST, ""),
    # routes.py
    ("GET", "/health"): (PUBLIC, "database liveness only"),
    ("POST", "/orgs/{org_id}/domains"): (TENANT, ""),
    ("GET", "/orgs/{org_id}/domains"): (LIST, ""),
    ("GET", "/orgs/{org_id}/domains/{domain_id}"): (TENANT, ""),
    ("GET", "/orgs/{org_id}/domains/{domain_id}/verification"): (TENANT, ""),
    ("POST", "/orgs/{org_id}/domains/{domain_id}/verification/check"): (TENANT, ""),
    ("POST", "/orgs/{org_id}/domains/{domain_id}/verification/rotate"): (TENANT, ""),
    ("POST", "/orgs/{org_id}/domains/{domain_id}/scans"): (TENANT, ""),
    ("GET", "/orgs/{org_id}/domains/{domain_id}/scans"): (LIST, ""),
    ("GET", "/orgs/{org_id}/scans"): (LIST, ""),
    ("GET", "/orgs/{org_id}/scans/{scan_id}"): (TENANT, ""),
    ("GET", "/orgs/{org_id}/scans/{scan_id}/results/{stage}"): (TENANT, ""),
    ("GET", "/orgs/{org_id}/scans/{scan_id}/changes"): (LIST, ""),
    ("GET", "/orgs/{org_id}/domains/{domain_id}/changes"): (LIST, ""),
    ("PUT", "/orgs/{org_id}/domains/{domain_id}/schedule"): (TENANT, ""),
    ("PUT", "/orgs/{org_id}/domains/{domain_id}/alerts"): (TENANT, ""),
    ("GET", "/orgs/{org_id}/domains/{domain_id}/alert-notifications"): (LIST, ""),
    ("GET", "/orgs/{org_id}/audit-events"): (LIST, ""),
    # routes_orgs.py
    ("POST", "/orgs"): (PUBLIC, "creates a new org owned by the caller"),
    ("GET", "/orgs"): (LIST, ""),
    ("DELETE", "/orgs/{org_id}"): (TENANT, ""),
    ("GET", "/orgs/{org_id}/members"): (LIST, ""),
    ("POST", "/orgs/{org_id}/members"): (TENANT, ""),
    ("POST", "/orgs/{org_id}/invites"): (TENANT, ""),
    ("GET", "/orgs/{org_id}/invites"): (LIST, ""),
    ("DELETE", "/orgs/{org_id}/invites/{invite_id}"): (TENANT, ""),
    ("PATCH", "/orgs/{org_id}/members/{user_id}"): (TENANT, ""),
    ("DELETE", "/orgs/{org_id}/members/{user_id}"): (TENANT, ""),
    ("POST", "/invites/accept"): (
        PUBLIC,
        "joins only the caller; the token is bound to the invitee's email (see 403 below)",
    ),
    ("DELETE", "/me"): (PUBLIC, "deletes only the caller's own account"),
}

# Routes where the cross-tenant answer is 403, not 404, and why.
CROSS_TENANT_403 = {
    ("POST", "/invites/accept"): (
        "B holding org A's invite token (issued to another email) gets 403 'issued to a "
        "different email address'; the token itself is the secret, so no enumeration"
    ),
}

ALPHA_TOKEN = "alpha-invite-token-0123456789"
BETA_TOKEN = "beta-invite-token-0123456789"

# Valid bodies, so a 422 can never stand in for the tenant check.
BODIES = {
    ("POST", "/orgs"): {"name": "Beta Second Org"},
    ("POST", "/orgs/{org_id}/domains"): {"name": "hijack-example.com"},
    ("PUT", "/orgs/{org_id}/domains/{domain_id}/schedule"): {"interval_hours": 48},
    ("PUT", "/orgs/{org_id}/domains/{domain_id}/alerts"): {
        "alerts_enabled": True,
        "alert_emails": ["attacker@tenant-b.com"],
    },
    ("POST", "/orgs/{org_id}/invites"): {"email": "attacker@tenant-b.com", "role": "owner"},
    ("PATCH", "/orgs/{org_id}/members/{user_id}"): {"role": "owner"},
    ("POST", "/invites/accept"): {"token": ALPHA_TOKEN},
}

# Strings that exist only in org A's seeded data.
ALPHA_MARKERS = (
    "alpha-target.com",
    "alpha_internal_subdomains",
    "Organization Alpha",
    "tenant-a.com",
    "Alert Alpha",
    "Secret details Alpha",
)

# List routes that accept a tenant id as a query parameter.
LIST_QUERY_PARAMS = {
    ("GET", "/orgs/{org_id}/audit-events"): "domain_id",
    ("GET", "/ui/orgs/{org_id}/audit-events"): "domain_id",
}

# JSON list routes: which object the "id" key names, so org A's id can be looked for.
LIST_ID_KIND = {
    "/orgs": "org",
    "/orgs/{org_id}/domains": "domain",
    "/orgs/{org_id}/domains/{domain_id}/scans": "scan",
    "/orgs/{org_id}/scans": "scan",
    "/orgs/{org_id}/scans/{scan_id}/changes": "change",
    "/orgs/{org_id}/domains/{domain_id}/changes": "change",
    "/orgs/{org_id}/domains/{domain_id}/alert-notifications": "notification",
    "/orgs/{org_id}/audit-events": "audit",
    "/orgs/{org_id}/members": "member",
    "/orgs/{org_id}/invites": "invite",
}

# Org A's rows, read straight from the tables after every cross-tenant write attempt.
ORG_A_ROWS = {
    "organizations": "SELECT * FROM organizations WHERE id = :org",
    "memberships": "SELECT * FROM memberships WHERE org_id = :org",
    "org_invites": "SELECT * FROM org_invites WHERE org_id = :org",
    "domains": "SELECT * FROM domains WHERE org_id = :org",
    "scan_runs": "SELECT s.* FROM scan_runs s JOIN domains d ON d.id = s.domain_id "
    "WHERE d.org_id = :org",
    "scan_changes": "SELECT c.* FROM scan_changes c JOIN domains d ON d.id = c.domain_id "
    "WHERE d.org_id = :org",
    "alert_notifications": "SELECT n.* FROM alert_notifications n "
    "JOIN domains d ON d.id = n.domain_id WHERE d.org_id = :org",
    "audit_events": "SELECT * FROM audit_events WHERE org_id = :org",
}


def app_route_keys() -> set[tuple[str, str]]:
    """Every (method, full path) served by the app, included routers expanded."""
    found = set()
    for route in app.routes:
        prefix = getattr(getattr(route, "include_context", None), "prefix", "")
        for sub in getattr(getattr(route, "original_router", None), "routes", [route]):
            methods = getattr(sub, "methods", None) or {"MOUNT"}
            found |= {(m, prefix + sub.path) for m in methods}
    return found


def placeholders(path: str) -> set[str]:
    return set(re.findall(r"{(\w+)}", path))


def cross_tenant_cases():
    """B calls each tenant-id route with org A's org id, and with its own org id plus
    org A's domain/scan/invite/user id."""
    for (method, path), (cls, _) in sorted(ROUTES.items()):
        if cls == PUBLIC or "org_id" not in placeholders(path):
            continue
        yield pytest.param(method, path, "a", id=f"{method} {path} [org A]")
        if placeholders(path) - {"org_id", "stage"}:
            yield pytest.param(method, path, "b", id=f"{method} {path} [org B + A ids]")


def list_cases():
    for (method, path), (cls, _) in sorted(ROUTES.items()):
        if cls != LIST:
            continue
        yield pytest.param(method, path, None, id=f"{method} {path}")
        if (method, path) in LIST_QUERY_PARAMS:
            param = LIST_QUERY_PARAMS[(method, path)]
            yield pytest.param(method, path, param, id=f"{method} {path} ?{param}=<org A>")


def public_cases():
    for (method, path), (cls, _) in sorted(ROUTES.items()):
        if cls == PUBLIC and method != "MOUNT":
            yield pytest.param(method, path, id=f"{method} {path}")


@pytest.fixture
def tenants(two_tenants, db_session: Session):  # noqa: F811
    """two_tenants plus a non-owner member, a pending invite and an audit event per org."""
    ctx = dict(two_tenants)
    viewer_a = User(id=uuid.uuid4(), email="viewer_a@tenant-a.com")
    db_session.add(viewer_a)
    db_session.flush()
    db_session.add(Membership(org_id=ctx["org_a"].id, user_id=viewer_a.id, role="viewer"))

    expires = datetime.now(UTC) + timedelta(days=7)
    for key, org, owner, email, token in (
        ("invite_a", ctx["org_a"], ctx["user_a"], "invitee@tenant-a.com", ALPHA_TOKEN),
        ("invite_b", ctx["org_b"], ctx["user_b"], "invitee@tenant-b.com", BETA_TOKEN),
    ):
        ctx[key] = OrgInvite(
            org_id=org.id,
            email=email,
            role="viewer",
            token_hash=hash_invite_token(token),
            invited_by_user_id=owner.id,
            expires_at=expires,
        )
        db_session.add(ctx[key])

    for key, org, owner, dom in (
        ("audit_a", ctx["org_a"], ctx["user_a"], ctx["dom_a"]),
        ("audit_b", ctx["org_b"], ctx["user_b"], ctx["dom_b"]),
    ):
        ctx[key] = record_event(
            db_session,
            org_id=org.id,
            actor_type="user",
            actor_user_id=owner.id,
            action="domain.created",
            target_type="domain",
            target_id=dom.id,
            metadata={"name": dom.name},
        )
    db_session.commit()
    ctx["viewer_a"] = viewer_a
    return ctx


@pytest.fixture
def client_b(tenants, db_session: Session):
    client = make_authenticated_client(db_session, tenants["user_b"])
    # get_current_user is overridden; the header only keeps the per-IP limit for
    # unauthenticated requests (20/min) out of the way.
    client.headers["Authorization"] = "Bearer test"
    yield client
    app.dependency_overrides.clear()


def ids_for(ctx, org_key: str) -> dict:
    return {
        "org_id": ctx[org_key].id,
        "domain_id": ctx["dom_a"].id,
        "scan_id": ctx["scan_a"].id,
        "invite_id": ctx["invite_a"].id,
        "user_id": ctx["viewer_a"].id,
        "stage": "discover",
    }


def own_ids(ctx) -> dict:
    return {
        "org_id": ctx["org_b"].id,
        "domain_id": ctx["dom_b"].id,
        "scan_id": ctx["scan_b"].id,
        "stage": "discover",
    }


def org_a_rows(db_session: Session, org_id: int) -> dict:
    db_session.expire_all()
    return {
        table: [tuple(r) for r in db_session.execute(text(sql + " ORDER BY 1"), {"org": org_id})]
        for table, sql in ORG_A_ROWS.items()
    }


def assert_no_alpha_markers(body: str, label: str) -> None:
    leaked = [m for m in ALPHA_MARKERS if m in body]
    assert not leaked, f"{label}: org A data in response: {leaked}"


def call(client, method: str, path: str, url: str, params=None):
    return client.request(method, url, json=BODIES.get((method, path)), params=params)


def json_pairs(value, key=None):
    """Yield (key, str(value)) for every scalar in a JSON document."""
    if isinstance(value, dict):
        for k, v in value.items():
            yield from json_pairs(v, k)
    elif isinstance(value, list):
        for v in value:
            yield from json_pairs(v, key)
    else:
        yield key, str(value)


def test_registry_matches_app_routes():
    """Every served route is classified, and every classified route is served."""
    served = app_route_keys()
    missing = sorted(served - ROUTES.keys())
    stale = sorted(ROUTES.keys() - served)
    assert not missing, f"routes missing from the isolation registry: {missing}"
    assert not stale, f"registry lists routes that no longer exist: {stale}"
    for key, (cls, reason) in ROUTES.items():
        assert cls in (TENANT, LIST, PUBLIC), key
        if cls == PUBLIC:
            assert reason.strip(), f"PUBLIC_OR_SELF route without a reason: {key}"
    assert set(CROSS_TENANT_403) <= ROUTES.keys()


@pytest.mark.parametrize(("method", "path", "vector"), list(cross_tenant_cases()))
def test_cross_tenant_ids_get_404(method, path, vector, tenants, client_b, db_session):
    """B using org A's ids: 404 (or documented 403), no org-A data, no write to org A."""
    org_a_id = tenants["org_a"].id
    before = org_a_rows(db_session, org_a_id)
    url = path.format(**ids_for(tenants, "org_a" if vector == "a" else "org_b"))

    response = call(client_b, method, path, url)

    expected = 403 if (method, path) in CROSS_TENANT_403 else 404
    assert response.status_code == expected, (
        f"{method} {url}: expected {expected}, got {response.status_code}: {response.text[:300]}"
    )
    assert_no_alpha_markers(response.text, f"{method} {url}")
    if method != "GET":
        assert org_a_rows(db_session, org_a_id) == before, f"{method} {url} changed org A rows"


@pytest.mark.parametrize(("method", "path", "query_param"), list(list_cases()))
def test_list_routes_return_only_own_tenant(method, path, query_param, tenants, client_b):
    """B's own lists contain zero org-A ids or data, even when B names org A's ids."""
    url = path.format(**own_ids(tenants))
    params = {query_param: tenants["dom_a"].id} if query_param else None

    response = call(client_b, method, path, url, params=params)

    assert response.status_code == 200, f"{method} {url}: {response.status_code} {response.text}"
    assert_no_alpha_markers(response.text, f"{method} {url} {params or ''}")
    if path.startswith("/ui/"):
        assert "beta-target.com" in response.text  # B's own data rendered: the list is real
        return

    t = tenants
    kind = LIST_ID_KIND[path]
    a_id, b_id = {
        "org": (t["org_a"].id, t["org_b"].id),
        "domain": (t["dom_a"].id, t["dom_b"].id),
        "scan": (t["scan_a"].id, t["scan_b"].id),
        "change": (t["change_a"].id, t["change_b"].id),
        "notification": (t["notif_a"].id, t["notif_b"].id),
        "audit": (t["audit_a"].id, t["audit_b"].id),
        "invite": (t["invite_a"].id, t["invite_b"].id),
        "member": (None, None),
    }[kind]
    body = response.json()
    top_ids = {str(item.get("id")) for item in body}
    pairs = set(json_pairs(body))
    forbidden = {
        ("org_id", str(t["org_a"].id)),
        ("domain_id", str(t["dom_a"].id)),
        ("scan_run_id", str(t["scan_a"].id)),
        ("user_id", str(t["user_a"].id)),
        ("user_id", str(t["viewer_a"].id)),
    }
    assert not pairs & forbidden, f"{method} {url}: org A ids in response: {pairs & forbidden}"
    if a_id is not None:
        assert str(a_id) not in top_ids, f"{method} {url}: org A {kind} {a_id} listed"
        if not params:
            assert str(b_id) in top_ids, f"{method} {url}: B's own {kind} missing"
    else:
        assert ("user_id", str(t["user_b"].id)) in pairs


@pytest.mark.parametrize(("method", "path"), list(public_cases()))
def test_public_or_self_routes_expose_no_tenant_a_data(
    method, path, tenants, client_b, db_session
):
    """Public and self-only routes, called by B, show nothing of org A and change nothing."""
    org_a_id = tenants["org_a"].id
    before = org_a_rows(db_session, org_a_id)

    response = call(client_b, method, path, path)

    expected = 403 if (method, path) in CROSS_TENANT_403 else None
    if expected:
        assert response.status_code == expected, response.text
    else:
        assert response.status_code < 500, response.text
    assert_no_alpha_markers(response.text, f"{method} {path}")
    assert org_a_rows(db_session, org_a_id) == before, f"{method} {path} changed org A rows"
    if (method, path) == ("POST", "/invites/accept"):
        joined = db_session.scalar(
            text("SELECT count(*) FROM memberships WHERE org_id = :o AND user_id = :u"),
            {"o": org_a_id, "u": tenants["user_b"].id},
        )
        assert joined == 0


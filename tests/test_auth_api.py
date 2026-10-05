"""API integration tests for authentication gates and organization endpoints."""

import logging
import time
import uuid
from unittest.mock import MagicMock

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from asm.api.deps import get_current_auth_settings, get_current_jwks_manager, get_current_user
from asm.api.main import app
from asm.auth.config import AuthSettings
from asm.auth.jwks import JWKSManager

pytestmark = pytest.mark.db

SUPABASE_URL = "https://mockproject.supabase.co"
AUDIENCE = "authenticated"


@pytest.fixture(scope="module")
def api_ec_key_pair():
    """Module-level EC key pair for API tests."""
    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()
    jwk_dict = jwt.algorithms.ECAlgorithm.to_jwk(public_key, as_dict=True)
    jwk_dict["kid"] = "api-ec-kid"
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "ES256"
    return private_key, public_key, jwk_dict


def make_token(
    private_key,
    sub: str,
    email: str = "test@example.com",
    is_anonymous: bool = False,
    exp_offset: int = 3600,
) -> str:
    now = int(time.time())
    payload = {
        "sub": sub,
        "email": email,
        "iss": f"{SUPABASE_URL}/auth/v1",
        "aud": AUDIENCE,
        "exp": now + exp_offset,
        "iat": now,
    }
    if is_anonymous:
        payload["is_anonymous"] = True
    return jwt.encode(
        payload,
        private_key,
        algorithm="ES256",
        headers={"kid": "api-ec-kid", "alg": "ES256"},
    )


@pytest.fixture
def auth_api_client(api_ec_key_pair, db_session: Session):
    """Provide a TestClient using real token verification with mocked JWKS keys."""
    _, _, ec_jwk = api_ec_key_pair
    mock_client = MagicMock()
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"keys": [ec_jwk]}
    mock_client.get.return_value = mock_resp

    test_settings = AuthSettings(supabase_url=SUPABASE_URL, jwt_audience=AUDIENCE)
    test_manager = JWKSManager(
        jwks_url=test_settings.jwks_url,
        fetch_timeout=5.0,
        min_refresh_interval=10.0,
        http_client=mock_client,
    )

    from asm.db.session import get_db

    def _get_db():
        yield db_session

    # Override settings, jwks manager, and db
    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_current_auth_settings] = lambda: test_settings
    app.dependency_overrides[get_current_jwks_manager] = lambda: test_manager

    # Ensure get_current_user is NOT overridden so real auth runs
    app.dependency_overrides.pop(get_current_user, None)

    with TestClient(app) as test_client:
        yield test_client, test_manager

    app.dependency_overrides.clear()


def test_health_remains_public_without_token(auth_api_client):
    """GET /health succeeds with 200 without Authorization header."""
    client, _ = auth_api_client
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_unauthenticated_request_rejected(auth_api_client):
    """Protected endpoints reject requests without token with 401 and WWW-Authenticate."""
    client, _ = auth_api_client

    # 1. /orgs/{org_id}/domains
    res1 = client.get("/orgs/1/domains")
    assert res1.status_code == 401
    assert "Bearer" in res1.headers.get("WWW-Authenticate", "")

    # 2. /orgs
    res2 = client.get("/orgs")
    assert res2.status_code == 401
    assert "Bearer" in res2.headers.get("WWW-Authenticate", "")


def test_authenticated_request_with_valid_token(api_ec_key_pair, auth_api_client):
    """Valid Bearer token allows access and JIT upserts user record."""
    client, _ = auth_api_client
    priv_key, _, _ = api_ec_key_pair
    user_id = str(uuid.uuid4())
    token = make_token(priv_key, sub=user_id, email="authenticated_user@example.com")

    headers = {"Authorization": f"Bearer {token}"}
    resp = client.post("/orgs", json={"name": "Valid Org"}, headers=headers)
    assert resp.status_code == 201
    assert resp.json()["name"] == "Valid Org"

    # Query orgs with same token
    resp_list = client.get("/orgs", headers=headers)
    assert resp_list.status_code == 200
    assert len(resp_list.json()) == 1


def test_anonymous_token_rejected_with_401(api_ec_key_pair, auth_api_client):
    """Token with is_anonymous: true returns 401."""
    client, _ = auth_api_client
    priv_key, _, _ = api_ec_key_pair
    user_id = str(uuid.uuid4())
    token = make_token(priv_key, sub=user_id, is_anonymous=True)

    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/orgs", headers=headers)
    assert resp.status_code == 401
    assert "Anonymous tokens are not allowed" in resp.json()["detail"]


def test_jwks_outage_returns_503(api_ec_key_pair, auth_api_client):
    """JWKS endpoint failure returns 503 Service Unavailable."""
    client, test_manager = auth_api_client
    priv_key, _, _ = api_ec_key_pair

    # Force JWKSManager client to return 503
    test_manager._http_client.get.return_value.status_code = 503
    test_manager._keys.clear()  # empty cache to force fetch

    token = make_token(priv_key, sub=str(uuid.uuid4()))
    headers = {"Authorization": f"Bearer {token}"}
    resp = client.get("/orgs", headers=headers)
    assert resp.status_code == 503
    assert resp.json()["detail"] == "Authentication service unavailable"


def test_unconfigured_auth_fails_closed(api_ec_key_pair, db_session: Session, caplog):
    """When SUPABASE_URL is not set, API logs startup warning and protected endpoints return 503."""
    priv_key, _, _ = api_ec_key_pair
    user_id = str(uuid.uuid4())
    token = make_token(priv_key, sub=user_id)

    unconfigured_settings = AuthSettings(supabase_url="")
    mock_manager = MagicMock()

    from asm.db.session import get_db

    def _get_db():
        yield db_session

    app.dependency_overrides[get_db] = _get_db
    app.dependency_overrides[get_current_auth_settings] = lambda: unconfigured_settings
    app.dependency_overrides[get_current_jwks_manager] = lambda: mock_manager
    app.dependency_overrides.pop(get_current_user, None)

    try:
        with caplog.at_level(logging.WARNING):
            with TestClient(app) as client:
                # 1. /health stays public (200 OK)
                health_resp = client.get("/health")
                assert health_resp.status_code == 200
                assert health_resp.json()["status"] == "ok"

                # 2. Protected endpoint without token returns 503 "authentication not configured"
                resp_no_token = client.get("/orgs")
                assert resp_no_token.status_code == 503
                assert resp_no_token.json()["detail"] == "authentication not configured"

                # 3. Protected endpoint with valid token returns 503 (token is not accepted!)
                resp_with_token = client.get(
                    "/orgs",
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert resp_with_token.status_code == 503
                assert resp_with_token.json()["detail"] == "authentication not configured"

                # 4. Protected endpoint with invalid token returns 503
                resp_invalid_token = client.get(
                    "/orgs",
                    headers={"Authorization": "Bearer badtoken"},
                )
                assert resp_invalid_token.status_code == 503
                assert resp_invalid_token.json()["detail"] == "authentication not configured"

                # 5. Domains route also returns 503
                resp_domains = client.get(
                    "/orgs/1/domains",
                    headers={"Authorization": f"Bearer {token}"},
                )
                assert resp_domains.status_code == 503
                assert resp_domains.json()["detail"] == "authentication not configured"

        # 6. Verify clear warning logged at startup
        warning_logged = any(
            "SUPABASE_URL is not set" in record.message
            for record in caplog.records
        )
        assert warning_logged
    finally:
        app.dependency_overrides.clear()



def _unsigned_token_with_header(header: dict) -> str:
    """Build a JWT-shaped string with an arbitrary (attacker-chosen) header."""
    import base64
    import json

    def b64(data: dict) -> str:
        raw = json.dumps(data).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    return f"{b64(header)}.{b64({'sub': 'x'})}.c2ln"


@pytest.mark.parametrize(
    "header",
    [
        {"alg": 'none", error="evil_alg', "kid": "api-ec-kid"},
        {"alg": "ES256", "kid": 'evil_kid", realm="injected'},
    ],
)
def test_www_authenticate_never_echoes_token_header_values(auth_api_client, header):
    """alg and kid come from the attacker; they must not appear in the 401 response."""
    client, _ = auth_api_client
    token = _unsigned_token_with_header(header)
    resp = client.get("/orgs", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401
    www_auth = resp.headers["WWW-Authenticate"]
    assert "evil" not in www_auth
    assert "injected" not in www_auth
    assert "evil" not in resp.text
    assert www_auth.count('"') == 4  # error="..." and error_description="..." only

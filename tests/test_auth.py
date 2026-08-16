from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi.testclient import TestClient

from verigence_security.app import create_app
from verigence_security.auth_store import MemoryAuthStore, PostgresAuthStore
from verigence_security.upstream import ExternalIdentity


class FakeUpstream:
    def __init__(self, subject: str = "clerk-user-1", email: str = "pc@test.example") -> None:
        self.subject = subject
        self.email = email

    def authorization_url(self, *, state: str) -> str:
        return f"https://clerk.test/oauth/authorize?state={state}"

    async def authenticate_code(self, *, code: str) -> ExternalIdentity:
        if code != "clerk-code":
            raise AssertionError("unexpected fake upstream code")
        return ExternalIdentity(subject=self.subject, email=self.email)


def _basic(client_id: str = "audit-core", secret: str = "audit-core-secret") -> dict[str, str]:
    encoded = base64.b64encode(f"{client_id}:{secret}".encode()).decode()
    return {"Authorization": f"Basic {encoded}"}


def _provision(store: MemoryAuthStore, *, role: str = "PC") -> None:
    store.ensure_tenant("tenant-1")
    store.upsert_user(
        user_id="user-1",
        external_subject="clerk-user-1",
        email="pc@test.example",
        active=True,
    )
    store.upsert_membership(
        user_id="user-1",
        tenant_id="tenant-1",
        roles=(role,),
        direct_permissions=frozenset(),
        active=True,
    )


def _complete_login(
    client: TestClient,
    *,
    client_id: str = "audit-core",
    redirect_uri: str = "https://audit-core.test/oauth/callback",
    code_challenge: str | None = None,
) -> str:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "state": "module-state-1",
        "tenant_id": "tenant-1",
    }
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = "S256"
    authorize = client.get("/oauth/authorize", params=params, follow_redirects=False)
    assert authorize.status_code == 302
    assert authorize.headers["location"].startswith("/auth/login?request_id=")

    login = client.get(authorize.headers["location"], follow_redirects=False)
    assert login.status_code == 302
    upstream_state = parse_qs(urlparse(login.headers["location"]).query)["state"][0]

    callback = client.get(
        "/auth/callback",
        params={"code": "clerk-code", "state": upstream_state},
        follow_redirects=False,
    )
    assert callback.status_code == 302
    location = callback.headers["location"]
    parsed = urlparse(location)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == redirect_uri
    values = parse_qs(parsed.query)
    assert values["state"] == ["module-state-1"]
    return values["code"][0]


def test_security_owned_login_code_exchange_and_session(settings):
    store = MemoryAuthStore()
    _provision(store)
    app = create_app(settings, auth_store=store, upstream_provider=FakeUpstream())
    client = TestClient(app)

    code = _complete_login(client)

    session = client.get("/session")
    assert session.status_code == 200
    assert session.json() == {
        "authenticated": True,
        "userId": "user-1",
        "email": "pc@test.example",
        "tenants": [{"tenantId": "tenant-1", "roles": ["PC"]}],
    }

    token_response = client.post(
        "/oauth/token",
        headers=_basic(),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://audit-core.test/oauth/callback",
        },
    )
    assert token_response.status_code == 200
    claims = app.state.token_service.decode(token_response.json()["access_token"])
    assert claims["sub"] == "user-1"
    assert claims["tenant_id"] == "tenant-1"
    assert claims["actor_type"] == "USER"
    assert claims["roles"] == ["PC"]
    assert "audit.evidence.upload" in claims["permissions"]
    assert "di.document.upload" in claims["permissions"]
    assert "di.verification.write" not in claims["permissions"]

    reused = client.post(
        "/oauth/token",
        headers=_basic(),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://audit-core.test/oauth/callback",
        },
    )
    assert reused.status_code == 400
    assert reused.json()["error"] == "invalid_grant"

    logout = client.post("/auth/logout")
    assert logout.status_code == 200
    assert client.get("/session").json() == {"authenticated": False}


def test_login_cannot_self_assert_tenant_or_roles(settings):
    store = MemoryAuthStore()
    _provision(store, role="PC")
    app = create_app(settings, auth_store=store, upstream_provider=FakeUpstream())
    client = TestClient(app)

    denied = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "audit-core",
            "redirect_uri": "https://audit-core.test/oauth/callback",
            "state": "s1",
            "tenant_id": "tenant-not-member",
            "roles": "PM",
        },
        follow_redirects=False,
    )
    assert denied.status_code == 302
    assert "error=access_denied" in denied.headers["location"]

    code = _complete_login(client)
    response = client.post(
        "/oauth/token",
        headers=_basic(),
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://audit-core.test/oauth/callback",
            "roles": "PM",
        },
    )
    assert response.status_code == 200
    claims = app.state.token_service.decode(response.json()["access_token"])
    assert claims["roles"] == ["PC"]
    assert "di.verification.write" not in claims["permissions"]


def test_unprovisioned_upstream_identity_is_denied(settings):
    store = MemoryAuthStore()
    _provision(store)
    app = create_app(
        settings,
        auth_store=store,
        upstream_provider=FakeUpstream(subject="unknown-clerk-user"),
    )
    client = TestClient(app)

    authorize = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "audit-core",
            "redirect_uri": "https://audit-core.test/oauth/callback",
            "state": "s1",
            "tenant_id": "tenant-1",
        },
        follow_redirects=False,
    )
    login = client.get(authorize.headers["location"], follow_redirects=False)
    upstream_state = parse_qs(urlparse(login.headers["location"]).query)["state"][0]
    callback = client.get(
        "/auth/callback",
        params={"code": "clerk-code", "state": upstream_state},
        follow_redirects=False,
    )
    assert callback.status_code == 403
    assert callback.json()["error"] == "access_denied"


def test_public_client_requires_and_verifies_pkce(settings):
    store = MemoryAuthStore()
    _provision(store)
    app = create_app(settings, auth_store=store, upstream_provider=FakeUpstream())
    client = TestClient(app)

    missing = client.get(
        "/oauth/authorize",
        params={
            "response_type": "code",
            "client_id": "mobile-test",
            "redirect_uri": "verigence://oauth/callback",
            "state": "s1",
            "tenant_id": "tenant-1",
        },
        follow_redirects=False,
    )
    assert missing.status_code == 302
    assert "error=invalid_request" in missing.headers["location"]

    verifier = "a" * 64
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode("ascii")).digest()
    ).rstrip(b"=").decode("ascii")
    code = _complete_login(
        client,
        client_id="mobile-test",
        redirect_uri="verigence://oauth/callback",
        code_challenge=challenge,
    )
    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "authorization_code",
            "client_id": "mobile-test",
            "code": code,
            "redirect_uri": "verigence://oauth/callback",
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 200
    claims = app.state.token_service.decode(response.json()["access_token"])
    assert claims["sub"] == "user-1"


def test_service_token_requires_known_tenant(settings):
    store = MemoryAuthStore()
    app = create_app(settings, auth_store=store, upstream_provider=FakeUpstream())
    client = TestClient(app)

    unknown = client.post(
        "/oauth/token",
        headers=_basic(),
        data={
            "grant_type": "client_credentials",
            "tenant_id": "tenant-unknown",
            "scope": "di.document.read",
        },
    )
    assert unknown.status_code == 400
    assert unknown.json()["error"] == "invalid_grant"

    store.ensure_tenant("tenant-1")
    response = client.post(
        "/oauth/token",
        headers=_basic(),
        data={
            "grant_type": "client_credentials",
            "tenant_id": "tenant-1",
            "scope": "di.document.read",
        },
    )
    assert response.status_code == 200
    claims = app.state.token_service.decode(response.json()["access_token"])
    assert claims["sub"] == "audit-core"
    assert claims["tenant_id"] == "tenant-1"
    assert claims["actor_type"] == "SERVICE"
    assert claims["permissions"] == ["di.document.read"]


def test_public_client_configuration_does_not_allow_client_credentials(settings):
    app = create_app(settings, upstream_provider=FakeUpstream())
    app.state.auth_service.ensure_tenant("tenant-1")
    client = TestClient(app)
    response = client.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": "mobile-test",
            "tenant_id": "tenant-1",
            "scope": "di.document.read",
        },
    )
    assert response.status_code == 401
    assert response.json()["error"] == "invalid_client"


@pytest.mark.skipif(
    not os.environ.get("SECURITY_TEST_DATABASE_URL"),
    reason="PostgreSQL auth persistence test requires SECURITY_TEST_DATABASE_URL",
)
def test_postgres_auth_membership_and_audit_persist():
    import psycopg

    database_url = os.environ["SECURITY_TEST_DATABASE_URL"]
    schema = Path("database/0001_role_templates.sql").read_text(encoding="utf-8")
    schema += "\n" + Path("database/0002_auth.sql").read_text(encoding="utf-8")
    with psycopg.connect(database_url) as conn, conn.cursor() as cur:
        cur.execute(schema)
        cur.execute(
            """
            TRUNCATE security_auth_audit,
                     security_oauth_authorization_codes,
                     security_oauth_authorization_requests,
                     security_auth_sessions,
                     security_user_tenant_memberships,
                     security_users,
                     security_tenants
            RESTART IDENTITY
            """
        )
        conn.commit()

    first = PostgresAuthStore(database_url)
    first.ensure_tenant("tenant-db")
    first.upsert_user(
        user_id="user-db",
        external_subject="clerk-db",
        email="db@test.example",
    )
    first.upsert_membership(
        user_id="user-db",
        tenant_id="tenant-db",
        roles=("PC",),
    )
    first.record_audit(
        event_type="test",
        outcome="SUCCESS",
        user_id="user-db",
        tenant_id="tenant-db",
    )

    second = PostgresAuthStore(database_url)
    assert second.tenant_exists("tenant-db")
    user = second.get_user_by_external_subject("clerk-db")
    assert user is not None
    assert user.user_id == "user-db"
    membership = second.get_membership("user-db", "tenant-db")
    assert membership is not None
    assert membership.roles == ("PC",)

    with psycopg.connect(database_url) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT event_type, outcome FROM security_auth_audit ORDER BY audit_id DESC LIMIT 1"
        )
        assert cur.fetchone() == ("test", "SUCCESS")

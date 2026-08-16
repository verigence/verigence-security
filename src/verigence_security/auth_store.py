from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Protocol


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class SecurityUser:
    user_id: str
    external_subject: str
    email: str | None
    active: bool


@dataclass(frozen=True)
class TenantMembership:
    user_id: str
    tenant_id: str
    roles: tuple[str, ...]
    direct_permissions: frozenset[str]
    active: bool


@dataclass(frozen=True)
class AuthSession:
    user_id: str
    expires_at: datetime


@dataclass(frozen=True)
class AuthorizationRequest:
    client_id: str
    redirect_uri: str
    state: str
    tenant_id: str
    code_challenge: str | None
    code_challenge_method: str | None
    upstream_nonce: str | None
    expires_at: datetime


@dataclass(frozen=True)
class AuthorizationCode:
    client_id: str
    redirect_uri: str
    user_id: str
    tenant_id: str
    code_challenge: str | None
    code_challenge_method: str | None
    expires_at: datetime


class AuthStore(Protocol):
    def ensure_tenant(self, tenant_id: str) -> None: ...

    def tenant_exists(self, tenant_id: str) -> bool: ...

    def upsert_user(
        self, *, user_id: str, external_subject: str, email: str | None, active: bool = True
    ) -> SecurityUser: ...

    def get_user(self, user_id: str) -> SecurityUser | None: ...

    def get_user_by_external_subject(self, external_subject: str) -> SecurityUser | None: ...

    def upsert_membership(
        self,
        *,
        user_id: str,
        tenant_id: str,
        roles: tuple[str, ...],
        direct_permissions: frozenset[str] = frozenset(),
        active: bool = True,
    ) -> TenantMembership: ...

    def get_membership(self, user_id: str, tenant_id: str) -> TenantMembership | None: ...

    def list_memberships(self, user_id: str) -> list[TenantMembership]: ...

    def create_session(self, session_token: str, *, user_id: str, expires_at: datetime) -> None: ...

    def get_session(self, session_token: str) -> AuthSession | None: ...

    def delete_session(self, session_token: str) -> None: ...

    def create_authorization_request(
        self, request_id: str, request: AuthorizationRequest
    ) -> None: ...

    def get_authorization_request(self, request_id: str) -> AuthorizationRequest | None: ...

    def bind_upstream_state(self, request_id: str, *, upstream_state: str, nonce: str) -> bool: ...

    def consume_authorization_request_by_upstream_state(
        self, upstream_state: str
    ) -> AuthorizationRequest | None: ...

    def create_authorization_code(self, code: str, auth_code: AuthorizationCode) -> None: ...

    def consume_authorization_code(self, code: str) -> AuthorizationCode | None: ...

    def record_audit(
        self,
        *,
        event_type: str,
        outcome: str,
        user_id: str | None = None,
        tenant_id: str | None = None,
        client_id: str | None = None,
        detail: str | None = None,
    ) -> None: ...


class MemoryAuthStore:
    def __init__(self) -> None:
        self.tenants: set[str] = set()
        self.users: dict[str, SecurityUser] = {}
        self.external_users: dict[str, str] = {}
        self.memberships: dict[tuple[str, str], TenantMembership] = {}
        self.sessions: dict[str, AuthSession] = {}
        self.requests: dict[str, AuthorizationRequest] = {}
        self.request_upstream_states: dict[str, str] = {}
        self.codes: dict[str, AuthorizationCode] = {}
        self.audit_events: list[dict[str, str | None]] = []

    def ensure_tenant(self, tenant_id: str) -> None:
        if tenant_id:
            self.tenants.add(tenant_id)

    def tenant_exists(self, tenant_id: str) -> bool:
        return tenant_id in self.tenants

    def upsert_user(
        self, *, user_id: str, external_subject: str, email: str | None, active: bool = True
    ) -> SecurityUser:
        previous = self.users.get(user_id)
        if previous is not None and previous.external_subject != external_subject:
            self.external_users.pop(previous.external_subject, None)
        owner = self.external_users.get(external_subject)
        if owner is not None and owner != user_id:
            raise ValueError("external subject is already linked to another Verigence user")
        row = SecurityUser(user_id, external_subject, email, active)
        self.users[user_id] = row
        self.external_users[external_subject] = user_id
        return row

    def get_user(self, user_id: str) -> SecurityUser | None:
        return self.users.get(user_id)

    def get_user_by_external_subject(self, external_subject: str) -> SecurityUser | None:
        user_id = self.external_users.get(external_subject)
        return None if user_id is None else self.users.get(user_id)

    def upsert_membership(
        self,
        *,
        user_id: str,
        tenant_id: str,
        roles: tuple[str, ...],
        direct_permissions: frozenset[str] = frozenset(),
        active: bool = True,
    ) -> TenantMembership:
        self.ensure_tenant(tenant_id)
        row = TenantMembership(user_id, tenant_id, roles, direct_permissions, active)
        self.memberships[(user_id, tenant_id)] = row
        return row

    def get_membership(self, user_id: str, tenant_id: str) -> TenantMembership | None:
        return self.memberships.get((user_id, tenant_id))

    def list_memberships(self, user_id: str) -> list[TenantMembership]:
        return sorted(
            [row for (candidate, _), row in self.memberships.items() if candidate == user_id],
            key=lambda row: row.tenant_id,
        )

    def create_session(self, session_token: str, *, user_id: str, expires_at: datetime) -> None:
        self.sessions[_digest(session_token)] = AuthSession(user_id=user_id, expires_at=expires_at)

    def get_session(self, session_token: str) -> AuthSession | None:
        row = self.sessions.get(_digest(session_token))
        if row is None or row.expires_at <= datetime.now(timezone.utc):
            return None
        return row

    def delete_session(self, session_token: str) -> None:
        self.sessions.pop(_digest(session_token), None)

    def create_authorization_request(self, request_id: str, request: AuthorizationRequest) -> None:
        self.requests[_digest(request_id)] = request

    def get_authorization_request(self, request_id: str) -> AuthorizationRequest | None:
        row = self.requests.get(_digest(request_id))
        if row is None or row.expires_at <= datetime.now(timezone.utc):
            return None
        return row

    def bind_upstream_state(self, request_id: str, *, upstream_state: str, nonce: str) -> bool:
        key = _digest(request_id)
        row = self.requests.get(key)
        if row is None or row.expires_at <= datetime.now(timezone.utc):
            return False
        self.requests[key] = AuthorizationRequest(
            client_id=row.client_id,
            redirect_uri=row.redirect_uri,
            state=row.state,
            tenant_id=row.tenant_id,
            code_challenge=row.code_challenge,
            code_challenge_method=row.code_challenge_method,
            upstream_nonce=nonce,
            expires_at=row.expires_at,
        )
        self.request_upstream_states[_digest(upstream_state)] = key
        return True

    def consume_authorization_request_by_upstream_state(
        self, upstream_state: str
    ) -> AuthorizationRequest | None:
        key = self.request_upstream_states.pop(_digest(upstream_state), None)
        if key is None:
            return None
        row = self.requests.pop(key, None)
        if row is None or row.expires_at <= datetime.now(timezone.utc):
            return None
        return row

    def create_authorization_code(self, code: str, auth_code: AuthorizationCode) -> None:
        self.codes[_digest(code)] = auth_code

    def consume_authorization_code(self, code: str) -> AuthorizationCode | None:
        row = self.codes.pop(_digest(code), None)
        if row is None or row.expires_at <= datetime.now(timezone.utc):
            return None
        return row

    def record_audit(
        self,
        *,
        event_type: str,
        outcome: str,
        user_id: str | None = None,
        tenant_id: str | None = None,
        client_id: str | None = None,
        detail: str | None = None,
    ) -> None:
        self.audit_events.append(
            {
                "event_type": event_type,
                "outcome": outcome,
                "user_id": user_id,
                "tenant_id": tenant_id,
                "client_id": client_id,
                "detail": detail,
            }
        )


class PostgresAuthStore:
    def __init__(self, database_url: str) -> None:
        self.database_url = database_url

    def ensure_tenant(self, tenant_id: str) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO security_tenants (tenant_id, active, created_at)
                VALUES (%s, TRUE, now())
                ON CONFLICT (tenant_id) DO NOTHING
                """,
                (tenant_id,),
            )
            conn.commit()

    def tenant_exists(self, tenant_id: str) -> bool:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM security_tenants WHERE tenant_id = %s AND active = TRUE",
                (tenant_id,),
            )
            return cur.fetchone() is not None

    def upsert_user(
        self, *, user_id: str, external_subject: str, email: str | None, active: bool = True
    ) -> SecurityUser:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO security_users (user_id, external_subject, email, active, created_at, updated_at)
                VALUES (%s, %s, %s, %s, now(), now())
                ON CONFLICT (user_id) DO UPDATE SET
                    external_subject = EXCLUDED.external_subject,
                    email = EXCLUDED.email,
                    active = EXCLUDED.active,
                    updated_at = now()
                RETURNING user_id, external_subject, email, active
                """,
                (user_id, external_subject, email, active),
            )
            row = cur.fetchone()
            conn.commit()
        if row is None:
            raise RuntimeError("user upsert did not return a row")
        return SecurityUser(str(row[0]), str(row[1]), row[2], bool(row[3]))

    def get_user(self, user_id: str) -> SecurityUser | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "SELECT user_id, external_subject, email, active FROM security_users WHERE user_id = %s",
                (user_id,),
            )
            row = cur.fetchone()
        return None if row is None else SecurityUser(str(row[0]), str(row[1]), row[2], bool(row[3]))

    def get_user_by_external_subject(self, external_subject: str) -> SecurityUser | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT user_id, external_subject, email, active
                FROM security_users
                WHERE external_subject = %s
                """,
                (external_subject,),
            )
            row = cur.fetchone()
        return None if row is None else SecurityUser(str(row[0]), str(row[1]), row[2], bool(row[3]))

    def upsert_membership(
        self,
        *,
        user_id: str,
        tenant_id: str,
        roles: tuple[str, ...],
        direct_permissions: frozenset[str] = frozenset(),
        active: bool = True,
    ) -> TenantMembership:
        self.ensure_tenant(tenant_id)
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO security_user_tenant_memberships
                    (user_id, tenant_id, roles, direct_permissions, active, created_at, updated_at)
                VALUES (%s, %s, %s::jsonb, %s::jsonb, %s, now(), now())
                ON CONFLICT (user_id, tenant_id) DO UPDATE SET
                    roles = EXCLUDED.roles,
                    direct_permissions = EXCLUDED.direct_permissions,
                    active = EXCLUDED.active,
                    updated_at = now()
                RETURNING user_id, tenant_id, roles, direct_permissions, active
                """,
                (
                    user_id,
                    tenant_id,
                    json.dumps(list(roles)),
                    json.dumps(sorted(direct_permissions)),
                    active,
                ),
            )
            row = cur.fetchone()
            conn.commit()
        if row is None:
            raise RuntimeError("membership upsert did not return a row")
        return _membership_from_row(row)

    def get_membership(self, user_id: str, tenant_id: str) -> TenantMembership | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT user_id, tenant_id, roles, direct_permissions, active
                FROM security_user_tenant_memberships
                WHERE user_id = %s AND tenant_id = %s
                """,
                (user_id, tenant_id),
            )
            row = cur.fetchone()
        return None if row is None else _membership_from_row(row)

    def list_memberships(self, user_id: str) -> list[TenantMembership]:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT user_id, tenant_id, roles, direct_permissions, active
                FROM security_user_tenant_memberships
                WHERE user_id = %s
                ORDER BY tenant_id
                """,
                (user_id,),
            )
            rows = cur.fetchall()
        return [_membership_from_row(row) for row in rows]

    def create_session(self, session_token: str, *, user_id: str, expires_at: datetime) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO security_auth_sessions (session_hash, user_id, expires_at, created_at)
                VALUES (%s, %s, %s, now())
                """,
                (_digest(session_token), user_id, expires_at),
            )
            conn.commit()

    def get_session(self, session_token: str) -> AuthSession | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT user_id, expires_at
                FROM security_auth_sessions
                WHERE session_hash = %s AND expires_at > now()
                """,
                (_digest(session_token),),
            )
            row = cur.fetchone()
        return None if row is None else AuthSession(str(row[0]), row[1])

    def delete_session(self, session_token: str) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                "DELETE FROM security_auth_sessions WHERE session_hash = %s",
                (_digest(session_token),),
            )
            conn.commit()

    def create_authorization_request(self, request_id: str, request: AuthorizationRequest) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO security_oauth_authorization_requests
                    (request_hash, client_id, redirect_uri, state, tenant_id,
                     code_challenge, code_challenge_method, expires_at, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now())
                """,
                (
                    _digest(request_id),
                    request.client_id,
                    request.redirect_uri,
                    request.state,
                    request.tenant_id,
                    request.code_challenge,
                    request.code_challenge_method,
                    request.expires_at,
                ),
            )
            conn.commit()

    def get_authorization_request(self, request_id: str) -> AuthorizationRequest | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                SELECT client_id, redirect_uri, state, tenant_id, code_challenge,
                       code_challenge_method, upstream_nonce, expires_at
                FROM security_oauth_authorization_requests
                WHERE request_hash = %s AND expires_at > now()
                """,
                (_digest(request_id),),
            )
            row = cur.fetchone()
        return None if row is None else _authorization_request_from_row(row)

    def bind_upstream_state(self, request_id: str, *, upstream_state: str, nonce: str) -> bool:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE security_oauth_authorization_requests
                SET upstream_state_hash = %s, upstream_nonce = %s
                WHERE request_hash = %s AND expires_at > now()
                RETURNING request_hash
                """,
                (_digest(upstream_state), nonce, _digest(request_id)),
            )
            updated = cur.fetchone() is not None
            conn.commit()
        return updated

    def consume_authorization_request_by_upstream_state(
        self, upstream_state: str
    ) -> AuthorizationRequest | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                DELETE FROM security_oauth_authorization_requests
                WHERE upstream_state_hash = %s AND expires_at > now()
                RETURNING client_id, redirect_uri, state, tenant_id, code_challenge,
                          code_challenge_method, upstream_nonce, expires_at
                """,
                (_digest(upstream_state),),
            )
            row = cur.fetchone()
            conn.commit()
        return None if row is None else _authorization_request_from_row(row)

    def create_authorization_code(self, code: str, auth_code: AuthorizationCode) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO security_oauth_authorization_codes
                    (code_hash, client_id, redirect_uri, user_id, tenant_id,
                     code_challenge, code_challenge_method, expires_at, created_at)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, now())
                """,
                (
                    _digest(code),
                    auth_code.client_id,
                    auth_code.redirect_uri,
                    auth_code.user_id,
                    auth_code.tenant_id,
                    auth_code.code_challenge,
                    auth_code.code_challenge_method,
                    auth_code.expires_at,
                ),
            )
            conn.commit()

    def consume_authorization_code(self, code: str) -> AuthorizationCode | None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                UPDATE security_oauth_authorization_codes
                SET used_at = now()
                WHERE code_hash = %s AND used_at IS NULL AND expires_at > now()
                RETURNING client_id, redirect_uri, user_id, tenant_id,
                          code_challenge, code_challenge_method, expires_at
                """,
                (_digest(code),),
            )
            row = cur.fetchone()
            conn.commit()
        return None if row is None else _authorization_code_from_row(row)

    def record_audit(
        self,
        *,
        event_type: str,
        outcome: str,
        user_id: str | None = None,
        tenant_id: str | None = None,
        client_id: str | None = None,
        detail: str | None = None,
    ) -> None:
        with self._connect() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO security_auth_audit
                    (event_type, outcome, user_id, tenant_id, client_id, detail, occurred_at)
                VALUES (%s, %s, %s, %s, %s, %s, now())
                """,
                (event_type, outcome, user_id, tenant_id, client_id, detail),
            )
            conn.commit()

    def _connect(self):
        try:
            import psycopg
        except ImportError as exc:  # pragma: no cover
            raise RuntimeError("psycopg is required for PostgreSQL auth storage") from exc
        return psycopg.connect(self.database_url)


def _membership_from_row(row) -> TenantMembership:
    return TenantMembership(
        user_id=str(row[0]),
        tenant_id=str(row[1]),
        roles=tuple(str(role) for role in row[2]),
        direct_permissions=frozenset(str(permission) for permission in row[3]),
        active=bool(row[4]),
    )


def _authorization_request_from_row(row) -> AuthorizationRequest:
    return AuthorizationRequest(
        client_id=str(row[0]),
        redirect_uri=str(row[1]),
        state=str(row[2]),
        tenant_id=str(row[3]),
        code_challenge=row[4],
        code_challenge_method=row[5],
        upstream_nonce=row[6],
        expires_at=row[7],
    )


def _authorization_code_from_row(row) -> AuthorizationCode:
    return AuthorizationCode(
        client_id=str(row[0]),
        redirect_uri=str(row[1]),
        user_id=str(row[2]),
        tenant_id=str(row[3]),
        code_challenge=row[4],
        code_challenge_method=row[5],
        expires_at=row[6],
    )

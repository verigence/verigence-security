from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse

from verigence_security.auth_store import (
    AuthStore,
    AuthorizationCode,
    AuthorizationRequest,
    MemoryAuthStore,
    PostgresAuthStore,
    SecurityUser,
    TenantMembership,
)
from verigence_security.role_templates import RoleTemplateService
from verigence_security.settings import IntegrationClient, Settings
from verigence_security.tokens import IssuedToken, TokenService, UnknownRole
from verigence_security.upstream import (
    ClerkOAuthProvider,
    UpstreamAuthenticationError,
    UpstreamConfigurationError,
    UpstreamIdentityProvider,
)


class AuthorizationError(Exception):
    """Base interactive OAuth authorization error."""


class InvalidClient(AuthorizationError):
    pass


class InvalidRequest(AuthorizationError):
    pass


class InvalidGrant(AuthorizationError):
    pass


class AccessDenied(AuthorizationError):
    pass


@dataclass(frozen=True)
class AuthorizationResult:
    redirect_uri: str
    code: str
    state: str


class AuthService:
    def __init__(
        self,
        *,
        settings: Settings,
        store: AuthStore,
        role_templates: RoleTemplateService,
        upstream: UpstreamIdentityProvider,
    ) -> None:
        self.settings = settings
        self.store = store
        self.role_templates = role_templates
        self.upstream = upstream

    def ensure_tenant(self, tenant_id: str) -> None:
        self.store.ensure_tenant(tenant_id)

    def audit(
        self,
        *,
        event_type: str,
        outcome: str,
        user_id: str | None = None,
        tenant_id: str | None = None,
        client_id: str | None = None,
        detail: str | None = None,
    ) -> None:
        self.store.record_audit(
            event_type=event_type,
            outcome=outcome,
            user_id=user_id,
            tenant_id=tenant_id,
            client_id=client_id,
            detail=detail,
        )

    def tenant_exists(self, tenant_id: str) -> bool:
        if self.store.tenant_exists(tenant_id):
            return True
        return bool(self.role_templates.store.list("TENANT", tenant_id))

    def client(self, client_id: str) -> IntegrationClient:
        client = self.settings.integration_clients.get(client_id)
        if client is None:
            raise InvalidClient("unknown OAuth client")
        return client

    def validate_authorization_request(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        response_type: str,
        state: str,
        tenant_id: str,
        code_challenge: str | None,
        code_challenge_method: str | None,
    ) -> IntegrationClient:
        client = self.client(client_id)
        if response_type != "code":
            raise InvalidRequest("response_type must be code")
        if redirect_uri not in client.redirect_uris:
            raise InvalidClient("redirect_uri is not registered for this client")
        if not state:
            raise InvalidRequest("state is required")
        if not tenant_id:
            raise InvalidRequest("tenant_id is required")
        if not self.tenant_exists(tenant_id):
            raise AccessDenied("unknown or inactive Tenant")
        if client.public:
            if not code_challenge or code_challenge_method != "S256":
                raise InvalidRequest("public clients require PKCE S256")
        elif code_challenge_method not in {None, "", "S256"}:
            raise InvalidRequest("unsupported code_challenge_method")
        return client

    def existing_session_user(self, session_token: str | None) -> SecurityUser | None:
        if not session_token:
            return None
        session = self.store.get_session(session_token)
        if session is None:
            return None
        user = self.store.get_user(session.user_id)
        if user is None or not user.active:
            return None
        return user

    def create_pending_authorization(
        self,
        *,
        client_id: str,
        redirect_uri: str,
        state: str,
        tenant_id: str,
        code_challenge: str | None,
        code_challenge_method: str | None,
    ) -> str:
        request_id = secrets.token_urlsafe(32)
        self.store.create_authorization_request(
            request_id,
            AuthorizationRequest(
                client_id=client_id,
                redirect_uri=redirect_uri,
                state=state,
                tenant_id=tenant_id,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method or None,
                upstream_nonce=None,
                expires_at=_future(self.settings.authorization_request_ttl_seconds),
            ),
        )
        return request_id

    def start_upstream_login(self, request_id: str) -> str:
        pending = self.store.get_authorization_request(request_id)
        if pending is None:
            raise InvalidRequest("authorization request is missing or expired")
        upstream_state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(24)
        if not self.store.bind_upstream_state(
            request_id, upstream_state=upstream_state, nonce=nonce
        ):
            raise InvalidRequest("authorization request is missing or expired")
        target = self.upstream.authorization_url(state=upstream_state)
        self.audit(
            event_type="interactive_login_started",
            outcome="SUCCESS",
            tenant_id=pending.tenant_id,
            client_id=pending.client_id,
        )
        return target

    async def complete_upstream_login(
        self, *, code: str, upstream_state: str
    ) -> tuple[AuthorizationResult, str]:
        pending = self.store.consume_authorization_request_by_upstream_state(upstream_state)
        if pending is None:
            raise InvalidGrant("upstream state is invalid or expired")
        identity = await self.upstream.authenticate_code(code=code)
        user = self.store.get_user_by_external_subject(identity.subject)
        if user is None or not user.active:
            raise AccessDenied("authenticated identity is not provisioned in Verigence Security")
        membership = self._active_membership(user.user_id, pending.tenant_id)
        session_token = secrets.token_urlsafe(48)
        self.store.create_session(
            session_token,
            user_id=user.user_id,
            expires_at=_future(self.settings.session_ttl_seconds),
        )
        result = self._issue_authorization_code(user, membership, pending)
        self.audit(
            event_type="interactive_login",
            outcome="SUCCESS",
            user_id=user.user_id,
            tenant_id=membership.tenant_id,
            client_id=pending.client_id,
        )
        return result, session_token

    def authorize_existing_session(
        self,
        *,
        user: SecurityUser,
        client_id: str,
        redirect_uri: str,
        state: str,
        tenant_id: str,
        code_challenge: str | None,
        code_challenge_method: str | None,
    ) -> AuthorizationResult:
        membership = self._active_membership(user.user_id, tenant_id)
        pending = AuthorizationRequest(
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            tenant_id=tenant_id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method or None,
            upstream_nonce=None,
            expires_at=_future(self.settings.authorization_request_ttl_seconds),
        )
        return self._issue_authorization_code(user, membership, pending)

    def exchange_authorization_code(
        self,
        *,
        client_id: str,
        code: str,
        redirect_uri: str,
        code_verifier: str | None,
        tokens: TokenService,
    ) -> IssuedToken:
        auth_code = self.store.consume_authorization_code(code)
        if auth_code is None:
            raise InvalidGrant("authorization code is invalid, expired or already used")
        if auth_code.client_id != client_id or auth_code.redirect_uri != redirect_uri:
            raise InvalidGrant("authorization code is not bound to this client/redirect URI")
        if auth_code.code_challenge:
            if not code_verifier or _pkce_s256(code_verifier) != auth_code.code_challenge:
                raise InvalidGrant("PKCE verification failed")
        membership = self._active_membership(auth_code.user_id, auth_code.tenant_id)
        user = self.store.get_user(auth_code.user_id)
        if user is None or not user.active:
            raise InvalidGrant("user is inactive")
        try:
            return tokens.issue_user_access_token(
                subject=user.user_id,
                tenant_id=membership.tenant_id,
                roles=membership.roles,
                direct_permissions=membership.direct_permissions,
            )
        except UnknownRole as exc:
            raise InvalidGrant("membership contains an unknown role") from exc

    def session_payload(self, session_token: str | None) -> dict:
        user = self.existing_session_user(session_token)
        if user is None:
            return {"authenticated": False}
        memberships = [row for row in self.store.list_memberships(user.user_id) if row.active]
        return {
            "authenticated": True,
            "userId": user.user_id,
            "email": user.email,
            "tenants": [
                {"tenantId": row.tenant_id, "roles": list(row.roles)} for row in memberships
            ],
        }

    def logout(self, session_token: str | None) -> None:
        if session_token:
            session = self.store.get_session(session_token)
            self.store.delete_session(session_token)
            self.audit(
                event_type="logout",
                outcome="SUCCESS",
                user_id=None if session is None else session.user_id,
            )

    def _active_membership(self, user_id: str, tenant_id: str) -> TenantMembership:
        membership = self.store.get_membership(user_id, tenant_id)
        if membership is None or not membership.active:
            raise AccessDenied("user is not an active member of the requested Tenant")
        return membership

    def _issue_authorization_code(
        self,
        user: SecurityUser,
        membership: TenantMembership,
        pending: AuthorizationRequest,
    ) -> AuthorizationResult:
        code = secrets.token_urlsafe(40)
        self.store.create_authorization_code(
            code,
            AuthorizationCode(
                client_id=pending.client_id,
                redirect_uri=pending.redirect_uri,
                user_id=user.user_id,
                tenant_id=membership.tenant_id,
                code_challenge=pending.code_challenge,
                code_challenge_method=pending.code_challenge_method,
                expires_at=_future(self.settings.authorization_code_ttl_seconds),
            ),
        )
        self.audit(
            event_type="authorization_code_issued",
            outcome="SUCCESS",
            user_id=user.user_id,
            tenant_id=membership.tenant_id,
            client_id=pending.client_id,
        )
        return AuthorizationResult(
            redirect_uri=pending.redirect_uri,
            code=code,
            state=pending.state,
        )


def create_auth_store(settings: Settings) -> AuthStore:
    if settings.role_database_url:
        return PostgresAuthStore(settings.role_database_url)
    return MemoryAuthStore()


def create_upstream_provider(settings: Settings) -> UpstreamIdentityProvider:
    return ClerkOAuthProvider(settings)


def register_auth_routes(app: FastAPI, auth: AuthService) -> None:
    settings = auth.settings

    @app.get("/oauth/authorize")
    async def oauth_authorize(request: Request):
        params = request.query_params
        client_id = params.get("client_id", "")
        redirect_uri = params.get("redirect_uri", "")
        state = params.get("state", "")
        tenant_id = params.get("tenant_id", "")
        response_type = params.get("response_type", "")
        code_challenge = params.get("code_challenge")
        code_challenge_method = params.get("code_challenge_method")
        try:
            auth.validate_authorization_request(
                client_id=client_id,
                redirect_uri=redirect_uri,
                response_type=response_type,
                state=state,
                tenant_id=tenant_id,
                code_challenge=code_challenge,
                code_challenge_method=code_challenge_method,
            )
        except InvalidClient as exc:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_client", "detail": str(exc)},
            )
        except AccessDenied as exc:
            return _authorization_error_redirect(redirect_uri, state, "access_denied", str(exc))
        except InvalidRequest as exc:
            return _authorization_error_redirect(redirect_uri, state, "invalid_request", str(exc))

        user = auth.existing_session_user(request.cookies.get(settings.session_cookie_name))
        if user is not None:
            try:
                result = auth.authorize_existing_session(
                    user=user,
                    client_id=client_id,
                    redirect_uri=redirect_uri,
                    state=state,
                    tenant_id=tenant_id,
                    code_challenge=code_challenge,
                    code_challenge_method=code_challenge_method,
                )
            except AccessDenied as exc:
                return _authorization_error_redirect(
                    redirect_uri, state, "access_denied", str(exc)
                )
            return RedirectResponse(_authorization_success_url(result), status_code=302)

        request_id = auth.create_pending_authorization(
            client_id=client_id,
            redirect_uri=redirect_uri,
            state=state,
            tenant_id=tenant_id,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        return RedirectResponse(f"/auth/login?request_id={request_id}", status_code=302)

    @app.get("/auth/login")
    async def auth_login(request_id: str):
        try:
            target = auth.start_upstream_login(request_id)
        except UpstreamConfigurationError:
            return JSONResponse(status_code=503, content={"error": "authentication_unavailable"})
        except InvalidRequest as exc:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_request", "detail": str(exc)},
            )
        return RedirectResponse(target, status_code=302)

    @app.get("/auth/callback")
    async def auth_callback(request: Request):
        code = request.query_params.get("code", "")
        upstream_state = request.query_params.get("state", "")
        if not code or not upstream_state:
            return JSONResponse(status_code=400, content={"error": "invalid_request"})
        try:
            result, session_token = await auth.complete_upstream_login(
                code=code, upstream_state=upstream_state
            )
        except UpstreamAuthenticationError:
            return JSONResponse(status_code=401, content={"error": "authentication_failed"})
        except InvalidGrant:
            return JSONResponse(status_code=400, content={"error": "invalid_grant"})
        except AccessDenied as exc:
            return JSONResponse(
                status_code=403,
                content={"error": "access_denied", "detail": str(exc)},
            )

        response = RedirectResponse(_authorization_success_url(result), status_code=302)
        response.set_cookie(
            settings.session_cookie_name,
            session_token,
            max_age=settings.session_ttl_seconds,
            httponly=True,
            secure=settings.session_cookie_secure,
            samesite="lax",
            path="/",
        )
        return response

    @app.get("/session")
    async def session(request: Request) -> JSONResponse:
        return JSONResponse(
            content=auth.session_payload(request.cookies.get(settings.session_cookie_name))
        )

    @app.post("/auth/logout")
    async def auth_logout(request: Request) -> JSONResponse:
        auth.logout(request.cookies.get(settings.session_cookie_name))
        response = JSONResponse(content={"loggedOut": True})
        response.delete_cookie(settings.session_cookie_name, path="/")
        return response


def _authorization_success_url(result: AuthorizationResult) -> str:
    return _append_query(result.redirect_uri, {"code": result.code, "state": result.state})


def _authorization_error_redirect(
    redirect_uri: str, state: str, error: str, description: str
) -> RedirectResponse:
    return RedirectResponse(
        _append_query(
            redirect_uri,
            {"error": error, "error_description": description, "state": state},
        ),
        status_code=302,
    )


def _append_query(url: str, values: dict[str, str]) -> str:
    parts = urlsplit(url)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(values)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _future(seconds: int) -> datetime:
    return datetime.now(timezone.utc) + timedelta(seconds=seconds)

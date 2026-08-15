from __future__ import annotations

import base64
import hmac
import logging
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from verigence_security.role_templates import (
    InvalidRoleTemplate,
    MemoryRoleTemplateStore,
    PostgresRoleTemplateStore,
    RoleTemplate,
    RoleTemplateService,
    RoleTemplateStore,
    SECURITY_ROLE_TEMPLATE_PLATFORM_WRITE,
    SECURITY_ROLE_TEMPLATE_READ,
    SECURITY_ROLE_TEMPLATE_TENANT_WRITE,
    UnknownRoleTemplate,
)
from verigence_security.settings import Settings
from verigence_security.tokens import InvalidToken, PermissionDenied, TokenService

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
logger = logging.getLogger("verigence_security.oauth")


def create_app(
    settings: Settings | None = None,
    role_store: RoleTemplateStore | None = None,
) -> FastAPI:
    resolved_settings = settings or Settings.from_env()
    resolved_store = role_store or _role_store_from_settings(resolved_settings)
    role_templates = RoleTemplateService(resolved_store)
    role_templates.seed_platform_defaults()
    tokens = TokenService(resolved_settings, role_permission_resolver=role_templates)
    app = FastAPI(title="Verigence Security", docs_url=None, redoc_url=None)
    app.state.token_service = tokens
    app.state.role_template_service = role_templates
    app.state.role_template_store = resolved_store
    app.state.settings = resolved_settings

    @app.get("/health")
    async def health() -> dict[str, str]:
        return {"status": "ok"}

    @app.get("/.well-known/jwks.json")
    async def jwks() -> dict:
        return tokens.jwks()

    @app.post("/oauth/token")
    async def oauth_token(request: Request) -> JSONResponse:
        client_id = _authenticate_client(request, resolved_settings)
        if client_id is None:
            _audit("token_denied", client_id=None, grant_type=None, reason="invalid_client")
            return JSONResponse(
                status_code=401,
                content={"error": "invalid_client"},
                headers={"WWW-Authenticate": "Basic"},
            )

        form = _parse_form(await request.body())
        grant_type = form.get("grant_type", "")
        requested_permissions = form.get("scope", "").split()

        try:
            if grant_type == "client_credentials":
                tenant_id = form.get("tenant_id", "")
                if not tenant_id:
                    return _oauth_error("invalid_request", "tenant_id is required")
                issued = tokens.issue_service_token(
                    client_id=client_id,
                    tenant_id=tenant_id,
                    requested_permissions=requested_permissions,
                )
            elif grant_type == TOKEN_EXCHANGE_GRANT:
                if form.get("subject_token_type", ACCESS_TOKEN_TYPE) != ACCESS_TOKEN_TYPE:
                    return _oauth_error("invalid_request", "unsupported subject_token_type")
                subject_token = form.get("subject_token", "")
                if not subject_token:
                    return _oauth_error("invalid_request", "subject_token is required")
                issued = tokens.exchange_user_token(
                    client_id=client_id,
                    subject_token=subject_token,
                    requested_permissions=requested_permissions,
                )
            else:
                return _oauth_error("unsupported_grant_type", "unsupported grant_type")
        except InvalidToken:
            _audit("token_denied", client_id=client_id, grant_type=grant_type, reason="invalid_grant")
            return _oauth_error("invalid_grant", "subject token is invalid")
        except PermissionDenied:
            _audit("token_denied", client_id=client_id, grant_type=grant_type, reason="invalid_scope")
            return _oauth_error("invalid_scope", "requested permission is not authorized")

        _audit(
            "token_issued",
            client_id=client_id,
            grant_type=grant_type,
            reason=None,
            scope=issued.scope,
        )
        return JSONResponse(
            content={
                "access_token": issued.access_token,
                "issued_token_type": ACCESS_TOKEN_TYPE,
                "token_type": "Bearer",
                "expires_in": issued.expires_in,
                "scope": issued.scope,
            }
        )

    @app.post("/v1/tenants/{tenant_id}/role-templates/bootstrap")
    async def bootstrap_tenant_role_templates(tenant_id: str, request: Request) -> JSONResponse:
        actor = _admin_actor(request, tokens)
        if isinstance(actor, JSONResponse):
            return actor
        denied = _require_tenant_role_write(actor, tenant_id)
        if denied is not None:
            return denied
        replace = request.query_params.get("replace", "false").lower() == "true"
        rows = role_templates.seed_tenant(
            tenant_id=tenant_id,
            actor_sub=actor["sub"],
            correlation_id=request.headers.get("X-Correlation-ID"),
            replace=replace,
        )
        return JSONResponse(content={"roles": [_template_payload(row) for row in rows]})

    @app.get("/v1/tenants/{tenant_id}/role-templates")
    async def get_tenant_role_templates(tenant_id: str, request: Request) -> JSONResponse:
        actor = _admin_actor(request, tokens)
        if isinstance(actor, JSONResponse):
            return actor
        denied = _require_tenant_role_read(actor, tenant_id)
        if denied is not None:
            return denied
        rows = role_templates.list_tenant(tenant_id)
        return JSONResponse(content={"roles": [_template_payload(row) for row in rows]})

    @app.put("/v1/tenants/{tenant_id}/role-templates/{role_key}")
    async def put_tenant_role_template(
        tenant_id: str,
        role_key: str,
        request: Request,
    ) -> JSONResponse:
        actor = _admin_actor(request, tokens)
        if isinstance(actor, JSONResponse):
            return actor
        denied = _require_tenant_role_write(actor, tenant_id)
        if denied is not None:
            return denied
        permissions = await _permission_body(request)
        if isinstance(permissions, JSONResponse):
            return permissions
        try:
            row = role_templates.update_tenant(
                tenant_id=tenant_id,
                role_key=role_key,
                permissions=permissions,
                actor_sub=actor["sub"],
                correlation_id=request.headers.get("X-Correlation-ID"),
            )
        except (InvalidRoleTemplate, UnknownRoleTemplate) as exc:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_role_template", "detail": str(exc)},
            )
        return JSONResponse(content=_template_payload(row))

    @app.get("/v1/platform/role-templates")
    async def get_platform_role_templates(request: Request) -> JSONResponse:
        actor = _admin_actor(request, tokens)
        if isinstance(actor, JSONResponse):
            return actor
        permissions = set(actor["permissions"])
        if SECURITY_ROLE_TEMPLATE_READ not in permissions:
            return _forbidden()
        rows = role_templates.list_platform()
        return JSONResponse(content={"roles": [_template_payload(row) for row in rows]})

    @app.put("/v1/platform/role-templates/{role_key}")
    async def put_platform_role_template(role_key: str, request: Request) -> JSONResponse:
        actor = _admin_actor(request, tokens)
        if isinstance(actor, JSONResponse):
            return actor
        if SECURITY_ROLE_TEMPLATE_PLATFORM_WRITE not in set(actor["permissions"]):
            return _forbidden()
        permissions = await _permission_body(request)
        if isinstance(permissions, JSONResponse):
            return permissions
        try:
            row = role_templates.update_platform(
                role_key=role_key,
                permissions=permissions,
                actor_sub=actor["sub"],
                correlation_id=request.headers.get("X-Correlation-ID"),
            )
        except (InvalidRoleTemplate, UnknownRoleTemplate) as exc:
            return JSONResponse(
                status_code=400,
                content={"error": "invalid_role_template", "detail": str(exc)},
            )
        return JSONResponse(content=_template_payload(row))

    return app


def _role_store_from_settings(settings: Settings) -> RoleTemplateStore:
    if settings.role_database_url:
        return PostgresRoleTemplateStore(settings.role_database_url)
    return MemoryRoleTemplateStore()


def _parse_form(body: bytes) -> dict[str, str]:
    values = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    return {key: items[-1] for key, items in values.items() if items}


def _authenticate_client(request: Request, settings: Settings) -> str | None:
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Basic "):
        return None
    try:
        decoded = base64.b64decode(authorization[6:], validate=True).decode("utf-8")
        client_id, client_secret = decoded.split(":", 1)
    except (ValueError, UnicodeDecodeError):
        return None
    client = settings.integration_clients.get(client_id)
    if client is None or not hmac.compare_digest(client.secret, client_secret):
        return None
    return client_id


def _admin_actor(request: Request, tokens: TokenService) -> dict | JSONResponse:
    authorization = request.headers.get("Authorization", "")
    if not authorization.startswith("Bearer "):
        return JSONResponse(status_code=401, content={"error": "invalid_token"})
    try:
        claims = tokens.decode(authorization[7:])
    except InvalidToken:
        return JSONResponse(status_code=401, content={"error": "invalid_token"})
    if claims.get("actor_type") != "USER":
        return JSONResponse(status_code=401, content={"error": "invalid_token"})
    if not isinstance(claims.get("sub"), str) or not isinstance(claims.get("tenant_id"), str):
        return JSONResponse(status_code=401, content={"error": "invalid_token"})
    permissions = claims.get("permissions")
    if not isinstance(permissions, list) or not all(isinstance(item, str) for item in permissions):
        return JSONResponse(status_code=401, content={"error": "invalid_token"})
    return claims


def _require_tenant_role_read(actor: dict, tenant_id: str) -> JSONResponse | None:
    permissions = set(actor["permissions"])
    if SECURITY_ROLE_TEMPLATE_READ not in permissions:
        return _forbidden()
    if actor["tenant_id"] != tenant_id and SECURITY_ROLE_TEMPLATE_PLATFORM_WRITE not in permissions:
        return _forbidden()
    return None


def _require_tenant_role_write(actor: dict, tenant_id: str) -> JSONResponse | None:
    permissions = set(actor["permissions"])
    if SECURITY_ROLE_TEMPLATE_PLATFORM_WRITE in permissions:
        return None
    if SECURITY_ROLE_TEMPLATE_TENANT_WRITE not in permissions:
        return _forbidden()
    if actor["tenant_id"] != tenant_id:
        return _forbidden()
    return None


async def _permission_body(request: Request) -> frozenset[str] | JSONResponse:
    try:
        body = await request.json()
    except ValueError:
        return JSONResponse(status_code=400, content={"error": "invalid_request"})
    if not isinstance(body, dict):
        return JSONResponse(status_code=400, content={"error": "invalid_request"})
    permissions = body.get("permissions")
    if not isinstance(permissions, list) or not all(
        isinstance(permission, str) and permission for permission in permissions
    ):
        return JSONResponse(status_code=400, content={"error": "invalid_request"})
    return frozenset(permissions)


def _template_payload(row: RoleTemplate) -> dict:
    return {
        "scopeType": row.scope_type,
        "tenantId": row.tenant_id,
        "roleKey": row.role_key,
        "permissions": sorted(row.permissions),
        "version": row.version,
        "updatedBy": row.updated_by,
        "updatedAt": row.updated_at.isoformat(),
    }


def _forbidden() -> JSONResponse:
    return JSONResponse(status_code=403, content={"error": "forbidden"})


def _oauth_error(error: str, description: str) -> JSONResponse:
    return JSONResponse(status_code=400, content={"error": error, "error_description": description})


def _audit(
    event: str,
    *,
    client_id: str | None,
    grant_type: str | None,
    reason: str | None,
    scope: str | None = None,
) -> None:
    logger.info(
        event,
        extra={
            "client_id": client_id,
            "grant_type": grant_type,
            "reason": reason,
            "scope": scope,
        },
    )

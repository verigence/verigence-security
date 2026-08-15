from __future__ import annotations

import base64
import hmac
import logging
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from verigence_security.settings import Settings
from verigence_security.tokens import InvalidToken, PermissionDenied, TokenService

TOKEN_EXCHANGE_GRANT = "urn:ietf:params:oauth:grant-type:token-exchange"
ACCESS_TOKEN_TYPE = "urn:ietf:params:oauth:token-type:access_token"
logger = logging.getLogger("verigence_security.oauth")


def create_app(settings: Settings | None = None) -> FastAPI:
    resolved_settings = settings or Settings.from_env()
    tokens = TokenService(resolved_settings)
    app = FastAPI(title="Verigence Security", docs_url=None, redoc_url=None)
    app.state.token_service = tokens
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

    return app


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

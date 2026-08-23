from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse, PlainTextResponse

from verigence_security.core.correlation import HEADER
from verigence_security.core.errors import SecurityError

logger = logging.getLogger(__name__)


def _route_template(request: Request) -> str | None:
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) and path else None


def security_error_handler(request: Request, exc: Exception) -> JSONResponse:
    # Registered specifically for SecurityError in main.py. The broader Exception annotation
    # matches Starlette's handler protocol; this guard prevents accidental misuse elsewhere.
    if not isinstance(exc, SecurityError):
        raise exc

    cid = getattr(request.state, "correlation_id", None)
    denied = exc.status_code in {401, 403}
    event_name = "security_request_denied" if denied else "security_request_failed"
    level = logging.ERROR if exc.status_code >= 500 else logging.INFO
    logger.log(
        level,
        "%s error_code=%s correlation_id=%s",
        event_name,
        exc.code,
        cid,
        extra={
            "event_name": event_name,
            "outcome": "DENIED" if denied else "FAILURE",
            "error_code": exc.code,
            "http_method": request.method,
            "http_route": _route_template(request),
            "http_status_code": exc.status_code,
        },
    )

    response = JSONResponse(
        status_code=exc.status_code,
        content={
            "code": exc.code,
            "title": exc.title,
            "status": exc.status_code,
            "detail": exc.detail,
            "correlationId": cid,
        },
        media_type="application/problem+json",
    )
    if cid:
        response.headers[HEADER] = cid
    return response


async def unexpected_error_handler(request: Request, exc: Exception) -> PlainTextResponse:
    """Preserve the v1.3 correlation contract even for an otherwise-unhandled HTTP 500.

    v1.3 does not define a normative application error code for an unexpected 500, so this handler
    deliberately does not invent one. It emits a generic body, records one owning exception event,
    and always returns the correlation header.
    """

    cid = getattr(request.state, "correlation_id", None)
    logger.error(
        "security_unexpected_exception correlation_id=%s",
        cid,
        extra={
            "event_name": "security_unexpected_exception",
            "outcome": "FAILURE",
            "http_method": request.method,
            "http_route": _route_template(request),
            "http_status_code": 500,
        },
        exc_info=exc,
    )
    response = PlainTextResponse("Internal Server Error", status_code=500)
    if cid:
        response.headers[HEADER] = cid
    return response

from __future__ import annotations

import logging

from fastapi import Request
from fastapi.exception_handlers import request_validation_exception_handler as fastapi_validation_handler
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, PlainTextResponse

from verigence_security.core.correlation import HEADER
from verigence_security.core.errors import SecurityError

logger = logging.getLogger(__name__)


def _route_template(request: Request) -> str | None:
    route = request.scope.get("route")
    path = getattr(route, "path", None)
    return path if isinstance(path, str) and path else None


def _validation_issue_summary(exc: RequestValidationError) -> str:
    """Return field/type-only validation diagnostics without request values or PII."""

    summaries: list[str] = []
    for issue in exc.errors()[:12]:
        location = issue.get("loc")
        field = (
            ".".join(str(part) for part in location)
            if isinstance(location, (list, tuple))
            else "unknown"
        )
        issue_type = issue.get("type")
        safe_type = issue_type if isinstance(issue_type, str) and issue_type else "validation_error"
        summaries.append(f"{field}:{safe_type}")
    return ",".join(summaries) if summaries else "unknown"


async def request_validation_error_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """Log safe 422 diagnostics while preserving FastAPI's normal validation response.

    Only field locations and Pydantic validation types are logged. Request bodies, header values,
    passwords, onboarding keys, OTPs, emails, phone numbers and validation inputs are never logged.
    """

    if not isinstance(exc, RequestValidationError):
        raise exc

    cid = getattr(request.state, "correlation_id", None)
    issues = _validation_issue_summary(exc)
    logger.warning(
        "security_request_validation_failed correlation_id=%s issues=%s",
        cid,
        issues,
        extra={
            "event_name": "security_request_validation_failed",
            "outcome": "FAILURE",
            "http_method": request.method,
            "http_route": _route_template(request) or request.url.path,
            "http_status_code": 422,
            "validation_issues": issues,
        },
    )
    response = await fastapi_validation_handler(request, exc)
    if cid:
        response.headers[HEADER] = cid
    return response


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

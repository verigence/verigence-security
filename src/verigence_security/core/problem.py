from __future__ import annotations

import logging

from fastapi import Request
from fastapi.responses import JSONResponse, PlainTextResponse

from verigence_security.core.correlation import HEADER
from verigence_security.core.errors import SecurityError

logger = logging.getLogger(__name__)


def security_error_handler(request: Request, exc: SecurityError) -> JSONResponse:
    cid = getattr(request.state, "correlation_id", None)
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
    deliberately does not invent one. It emits a generic body, logs the exception with the resolved
    correlation ID, and always returns the correlation header.
    """

    cid = getattr(request.state, "correlation_id", None)
    logger.exception("Unhandled Security API exception; correlation_id=%s", cid, exc_info=exc)
    response = PlainTextResponse("Internal Server Error", status_code=500)
    if cid:
        response.headers[HEADER] = cid
    return response

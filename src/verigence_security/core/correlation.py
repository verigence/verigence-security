from __future__ import annotations

import re
from contextvars import ContextVar
from uuid import uuid4

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

HEADER = "X-Correlation-ID"
CORRELATION_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"
_PATTERN = re.compile(CORRELATION_ID_PATTERN)
correlation_id_ctx: ContextVar[str | None] = ContextVar("correlation_id", default=None)


def resolve_correlation_id(value: str | None) -> str:
    if value is None:
        return str(uuid4())
    if not _PATTERN.fullmatch(value):
        from verigence_security.core.errors import security_error
        raise security_error("CORRELATION_ID_INVALID")
    return value


def current_correlation_id() -> str:
    value = correlation_id_ctx.get()
    return value or str(uuid4())


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        supplied = request.headers.get(HEADER)
        if supplied is not None and not _PATTERN.fullmatch(supplied):
            # The invalid caller value is not normalized or propagated. A new server-side ID is
            # generated solely so the 400 response can itself be traced. This behavior is called
            # out in IMPLEMENTATION_STATUS as a v1.3 contract clarification to baseline.
            cid = str(uuid4())
            request.state.correlation_id = cid
            response = JSONResponse(
                status_code=400,
                content={
                    "code": "CORRELATION_ID_INVALID",
                    "title": "Invalid correlation ID",
                    "status": 400,
                    "detail": None,
                    "correlationId": cid,
                },
                media_type="application/problem+json",
            )
            response.headers[HEADER] = cid
            return response

        cid = supplied or str(uuid4())
        token = correlation_id_ctx.set(cid)
        request.state.correlation_id = cid
        try:
            response = await call_next(request)
        finally:
            correlation_id_ctx.reset(token)
        response.headers[HEADER] = cid
        return response

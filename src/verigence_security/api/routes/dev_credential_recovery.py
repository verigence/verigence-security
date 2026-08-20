from __future__ import annotations

import hashlib
import secrets

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse

from verigence_security.adapters.clerk_backend import ClerkBackendClient
from verigence_security.config import Settings, get_settings
from verigence_security.core.types import AppEnvironment

router = APIRouter(prefix="/security/v1/dev", tags=["dev-credential-recovery"])

# One-time DEV recovery control. Only the SHA-256 digest is committed; the bearer value itself
# never enters source control. This entire route is removed immediately after recovery succeeds.
_RESET_TOKEN_SHA256 = "4e852fb2d946b5895e6e42672265e8ba5d6750bad84124400d03346ced25e460"
_SUPERADMIN_CLERK_SUBJECT = "user_3I7HFuZZiFC9K2muiweXFRoeoud"
_used = False


@router.get("/credential-recovery/superadmin", include_in_schema=False)
def recover_superadmin_password(
    token: str = Query(..., min_length=32, max_length=128),
    settings: Settings = Depends(get_settings),
) -> JSONResponse:
    """Reset the approved DEV SuperAdmin to a server-generated one-time recovery password."""

    if settings.app_env != AppEnvironment.DEV:
        raise HTTPException(status_code=404, detail="Not found")

    supplied_digest = hashlib.sha256(token.encode("utf-8")).hexdigest()
    if not secrets.compare_digest(supplied_digest, _RESET_TOKEN_SHA256):
        raise HTTPException(status_code=404, detail="Not found")

    global _used
    if _used:
        raise HTTPException(status_code=410, detail="Recovery token already used")

    # Generate inside the Security process so no password value is stored in GitHub or CI input.
    new_password = f"Vg9!{secrets.token_urlsafe(18)}"
    clerk = ClerkBackendClient(settings)
    clerk._request_object(  # noqa: SLF001 - temporary DEV-only recovery boundary
        "PATCH",
        f"/users/{_SUPERADMIN_CLERK_SUBJECT}",
        json={
            "password": new_password,
            "sign_out_of_other_sessions": True,
        },
    )
    if not clerk.verify_password(
        clerk_user_id=_SUPERADMIN_CLERK_SUBJECT,
        password=new_password,
    ):
        raise HTTPException(status_code=502, detail="Clerk password verification failed after reset")

    _used = True
    response = JSONResponse(
        {
            "status": "RESET_VERIFIED",
            "target": "SuperAdmin",
            "clerkUserId": _SUPERADMIN_CLERK_SUBJECT,
            "password": new_password,
        }
    )
    response.headers["Cache-Control"] = "no-store, max-age=0"
    response.headers["Pragma"] = "no-cache"
    return response

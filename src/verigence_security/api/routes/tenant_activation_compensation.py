from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.api.platform_dependencies import platform_session
from verigence_security.api.platform_schemas import PlatformTenantResponse
from verigence_security.api.v2_human_dependencies import security_human_actor
from verigence_security.core.errors import security_error
from verigence_security.services.v2_human_actor import HumanActorContext

router = APIRouter(prefix="/security/v1/platform", tags=["Platform Administration"])


def _tenant_response(row: dict[str, object]) -> dict[str, object]:
    return {
        "tenantId": str(row["tenant_id"]),
        "tenantCode": row["tenant_code"],
        "tenantName": row["tenant_name"],
        "status": row["status"],
        "createdAtUtc": row["created_at_utc"],
        "updatedAtUtc": row["updated_at_utc"],
    }


@router.post(
    "/tenants/{tenantId}/restore-configuring",
    response_model=PlatformTenantResponse,
)
def restore_tenant_to_configuring(
    tenantId: str,
    request: Request,
    actor: HumanActorContext = Depends(security_human_actor),
    session: Session = Depends(platform_session),
) -> dict[str, object]:
    """Compensate a just-completed UC02 activation back to CONFIGURING.

    This endpoint is intentionally narrow and idempotent for CONFIGURING. It exists
    only so the Audit Core synchronous admin transaction can undo a Security ACTIVE
    commit when the corresponding Audit Core commit cannot complete.
    """
    if not actor.is_super_admin:
        raise security_error("PERMISSION_DENIED")

    current = session.execute(
        text(
            """
            SELECT tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc
            FROM security.tenants
            WHERE tenant_id=:tenant_id
            FOR UPDATE
            """
        ),
        {"tenant_id": tenantId},
    ).mappings().first()
    if current is None:
        raise HTTPException(status_code=404, detail="Tenant not found")

    before = dict(current)
    if str(before["status"]) == "CONFIGURING":
        return _tenant_response(before)
    if str(before["status"]) != "ACTIVE":
        raise HTTPException(
            status_code=409,
            detail="Tenant activation compensation requires ACTIVE or CONFIGURING status",
        )

    now = datetime.now(UTC)
    try:
        updated = session.execute(
            text(
                """
                UPDATE security.tenants
                SET status='CONFIGURING',updated_at_utc=:now
                WHERE tenant_id=:tenant_id AND status='ACTIVE'
                RETURNING tenant_id,tenant_code,tenant_name,status,created_at_utc,updated_at_utc
                """
            ),
            {"tenant_id": tenantId, "now": now},
        ).mappings().first()
        if updated is None:
            raise RuntimeError("Tenant activation compensation state changed concurrently")

        session.execute(
            text(
                """
                INSERT INTO security.admin_change_records
                (admin_change_id,correlation_id,scope_type,tenant_id,actor_user_id,
                 operation_key,resource_type,resource_id,outcome,before_state_json,
                 after_state_json,occurred_at_utc)
                VALUES
                (:admin_change_id,:correlation_id,'TENANT',:tenant_id,:actor_user_id,
                 'platform.tenant.activation_compensate','tenant',:tenant_id,'SUCCESS',
                 CAST(:before_state_json AS jsonb),CAST(:after_state_json AS jsonb),:now)
                """
            ),
            {
                "admin_change_id": str(uuid4()),
                "correlation_id": request.state.correlation_id,
                "tenant_id": tenantId,
                "actor_user_id": actor.user_id,
                "before_state_json": json.dumps(
                    {
                        "tenantId": tenantId,
                        "tenantCode": before["tenant_code"],
                        "tenantName": before["tenant_name"],
                        "status": "ACTIVE",
                    }
                ),
                "after_state_json": json.dumps(
                    {
                        "tenantId": tenantId,
                        "tenantCode": before["tenant_code"],
                        "tenantName": before["tenant_name"],
                        "status": "CONFIGURING",
                    }
                ),
                "now": now,
            },
        )
        session.commit()
    except Exception:
        session.rollback()
        raise

    return _tenant_response(dict(updated))

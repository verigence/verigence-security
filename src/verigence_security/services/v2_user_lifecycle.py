from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError
from verigence_security.services.v2_human_actor import HumanActorContext


@dataclass(frozen=True, slots=True)
class UserLifecycleResult:
    user_id: str
    status: str
    previous_status: str
    changed: bool
    deletion_request_id: str | None = None


@dataclass(frozen=True, slots=True)
class HardDeleteResult:
    user_id: str
    deletion_request_id: str
    tombstone_id: str
    deleted_at_utc: datetime
    retain_until_utc: datetime


class V2UserLifecycleService:
    """Phase-1 global USER lifecycle and deletion coordinator.

    The scoped Executive/TenantAdmin ACTIVE->SUSPENDED branch is intentionally not
    inferred here until its request Tenant-context contract is explicitly fixed.
    SuperAdmin suspension remains supported. All other approved lifecycle/deletion
    rules are enforced by this service.
    """

    def __init__(self, session: Session) -> None:
        self.s = session

    def transition(
        self,
        *,
        user_id: str,
        requested_status: str,
        actor: HumanActorContext,
        reason_code: str | None,
        reason: str | None,
        correlation_id: str,
        clerk: ClerkBackendClient,
    ) -> UserLifecycleResult:
        target = requested_status.strip().upper()
        if target not in {"ACTIVE", "REJECTED", "SUSPENDED", "DISABLED"}:
            raise ValueError("Unsupported Phase-1 USER status")

        now = datetime.now(UTC)
        post_commit_ban_subject: str | None = None
        try:
            row = self._user_for_update(user_id)
            if row is None:
                raise LookupError("USER not found")
            current = str(row["status"])
            clerk_subject = self._clerk_subject(user_id)

            if self._is_active_super_admin(user_id) and target != "ACTIVE":
                raise ValueError("The active Phase-1 SuperAdmin cannot be made non-ACTIVE")

            if target == current:
                self.s.rollback()
                request_id = self._open_deletion_request_id(user_id) if target == "DISABLED" else None
                return UserLifecycleResult(user_id, target, current, False, request_id)

            deletion_request_id: str | None = None

            if target == "ACTIVE":
                if current not in {"PENDING", "REJECTED", "SUSPENDED", "DISABLED", "INVITED"}:
                    raise ValueError(f"USER cannot transition from {current} to ACTIVE")
                self._require_super_admin(actor)
                if clerk_subject is None:
                    raise ValueError("USER has no active Clerk identity")
                # Fail closed: provider reactivation must succeed before Security grants ACTIVE.
                clerk.unban_user(clerk_subject)
                if current == "DISABLED":
                    self.s.execute(
                        text(
                            """
                            UPDATE security.user_deletion_requests
                            SET status='CANCELLED',checked_by_user_id=:actor,
                                checked_at_utc=:now,outcome='REACTIVATED'
                            WHERE user_id=:user_id AND status='REQUESTED'
                            """
                        ),
                        {"actor": actor.user_id, "now": now, "user_id": user_id},
                    )

            elif target == "REJECTED":
                if current != "PENDING":
                    raise ValueError("Only a PENDING USER can be rejected")
                self._require_super_admin(actor)
                self.s.execute(
                    text(
                        """
                        UPDATE security.platform_user_onboarding_requests
                        SET status='REJECTED',reviewed_by_user_id=:actor,
                            reviewed_at_utc=:now,review_reason=:reason
                        WHERE user_id=:user_id
                          AND status='PENDING_ADMIN_APPROVAL'
                        """
                    ),
                    {
                        "actor": actor.user_id,
                        "now": now,
                        "reason": reason,
                        "user_id": user_id,
                    },
                )

            elif target == "SUSPENDED":
                if current != "ACTIVE":
                    raise ValueError("Only an ACTIVE USER can be suspended")
                # The approved Executive/TenantAdmin rule is Tenant-contextual, but the
                # approved status API currently has no Tenant context in its contract.
                # Until that is explicitly resolved, only the unambiguous SuperAdmin path runs.
                self._require_super_admin(actor)
                post_commit_ban_subject = clerk_subject

            elif target == "DISABLED":
                if current not in {"ACTIVE", "REJECTED"}:
                    raise ValueError("Deletion can be requested only for an ACTIVE or REJECTED USER")
                if (reason_code or "").strip().upper() != "DELETE_REQUEST":
                    raise ValueError("DISABLED requires reasonCode=DELETE_REQUEST")
                self._require_deletion_maker(actor, user_id)
                deletion_request_id = str(uuid4())
                self.s.execute(
                    text(
                        """
                        INSERT INTO security.user_deletion_requests
                        (deletion_request_id,user_id,requested_by_user_id,requested_at_utc,
                         reason,status,correlation_id)
                        VALUES (:request_id,:user_id,:actor,:now,:reason,'REQUESTED',:correlation_id)
                        """
                    ),
                    {
                        "request_id": deletion_request_id,
                        "user_id": user_id,
                        "actor": actor.user_id,
                        "now": now,
                        "reason": reason,
                        "correlation_id": correlation_id,
                    },
                )
                post_commit_ban_subject = clerk_subject

            self.s.execute(
                text(
                    """
                    UPDATE security.users
                    SET status=:status,updated_at_utc=:now
                    WHERE user_id=:user_id
                    """
                ),
                {"status": target, "now": now, "user_id": user_id},
            )
            if target in {"SUSPENDED", "DISABLED", "REJECTED"}:
                self.s.execute(
                    text(
                        """
                        UPDATE security.access_sessions
                        SET status='REVOKED',last_activity_at_utc=:now
                        WHERE principal_id=:user_id
                          AND actor_type='USER'
                          AND status='ACTIVE'
                        """
                    ),
                    {"user_id": user_id, "now": now},
                )

            self._audit(
                actor_user_id=actor.user_id,
                correlation_id=correlation_id,
                operation_key="security.user.status.change",
                resource_id=user_id,
                before={"status": current},
                after={
                    "status": target,
                    "reasonCode": reason_code,
                    "reason": reason,
                    "deletionRequestId": deletion_request_id,
                },
                now=now,
            )
            self.s.commit()
        except Exception:
            self.s.rollback()
            raise

        # Security denial state is already committed. Provider failure cannot restore access.
        if post_commit_ban_subject is not None:
            clerk.ban_user(post_commit_ban_subject)

        return UserLifecycleResult(
            user_id=user_id,
            status=target,
            previous_status=current,
            changed=True,
            deletion_request_id=deletion_request_id,
        )

    def hard_delete(
        self,
        *,
        user_id: str,
        actor: HumanActorContext,
        correlation_id: str,
        clerk: ClerkBackendClient,
    ) -> HardDeleteResult:
        self._require_super_admin(actor)
        if self._is_active_super_admin(user_id):
            raise ValueError("The active Phase-1 SuperAdmin cannot be hard-deleted")

        # Read the immutable provider subject before provider deletion. The Security USER is
        # already DISABLED at this point, so a provider-side success followed by a DB failure
        # leaves a fail-closed disabled local account rather than an active orphan.
        row = self._user_snapshot(user_id)
        if row is None:
            raise LookupError("USER not found")
        if str(row["status"]) != "DISABLED":
            raise ValueError("USER must be DISABLED before hard deletion")
        request = self._open_deletion_request(user_id)
        if request is None:
            raise ValueError("DISABLED USER has no active deletion request")

        clerk_subject = self._clerk_subject(user_id)
        if clerk_subject is not None:
            try:
                clerk.delete_user(clerk_subject)
            except ClerkBackendError as exc:
                if exc.status_code != 404:
                    raise

        now = datetime.now(UTC)
        retain_until = now + timedelta(days=21)
        tombstone_id = str(uuid4())
        deletion_request_id = str(request["deletion_request_id"])
        safe_reference = {
            "deletedUserId": user_id,
            "displayName": row["display_name"],
            "primaryEmail": row["primary_email"],
            "requestedByUserId": (
                str(request["requested_by_user_id"])
                if request["requested_by_user_id"] is not None
                else None
            ),
            "requestReason": request["reason"],
        }

        try:
            locked = self._user_for_update(user_id)
            if locked is None or str(locked["status"]) != "DISABLED":
                raise ValueError("USER deletion preconditions changed")
            locked_request = self._open_deletion_request(user_id, for_update=True)
            if locked_request is None or str(locked_request["deletion_request_id"]) != deletion_request_id:
                raise ValueError("Deletion request changed before hard delete")

            self.s.execute(
                text(
                    """
                    INSERT INTO security.deleted_user_tombstones
                    (tombstone_id,deleted_user_id,deletion_request_id,safe_actor_reference,
                     deleted_at_utc,retain_until_utc,deletion_correlation_id)
                    VALUES (:tombstone_id,:user_id,:request_id,CAST(:reference AS jsonb),
                            :now,:retain_until,:correlation_id)
                    """
                ),
                {
                    "tombstone_id": tombstone_id,
                    "user_id": user_id,
                    "request_id": deletion_request_id,
                    "reference": json.dumps(safe_reference),
                    "now": now,
                    "retain_until": retain_until,
                    "correlation_id": correlation_id,
                },
            )
            self.s.execute(
                text(
                    """
                    UPDATE security.user_deletion_requests
                    SET status='COMPLETED',checked_by_user_id=:actor,
                        checked_at_utc=:now,outcome='HARD_DELETED'
                    WHERE deletion_request_id=:request_id
                    """
                ),
                {"actor": actor.user_id, "now": now, "request_id": deletion_request_id},
            )
            self._audit(
                actor_user_id=actor.user_id,
                correlation_id=correlation_id,
                operation_key="security.user.status.change",
                resource_id=user_id,
                before={"status": "DISABLED", "deletionRequestId": deletion_request_id},
                after={"status": "DELETED", "tombstoneId": tombstone_id},
                now=now,
            )

            # Remove live principal-bound runtime state. Security events intentionally survive
            # through the FK-independent historical reference established by migration 0015.
            self.s.execute(
                text("DELETE FROM security.access_context_evaluations WHERE principal_id=:user_id"),
                {"user_id": user_id},
            )
            self.s.execute(
                text("DELETE FROM security.access_sessions WHERE principal_id=:user_id"),
                {"user_id": user_id},
            )
            self.s.execute(
                text("DELETE FROM security.principal_permission_grants WHERE principal_id=:user_id"),
                {"user_id": user_id},
            )
            self.s.execute(
                text("DELETE FROM security.principal_tenant_scopes WHERE principal_id=:user_id"),
                {"user_id": user_id},
            )
            self.s.execute(
                text("DELETE FROM security.principal_credentials WHERE principal_id=:user_id"),
                {"user_id": user_id},
            )

            # Subject/object USER FKs are ON DELETE CASCADE after migration 0015. Historical
            # actor references retain the UUID but no longer require the live USER row.
            deleted = self.s.execute(
                text("DELETE FROM security.users WHERE user_id=:user_id RETURNING user_id"),
                {"user_id": user_id},
            ).scalar_one_or_none()
            if deleted is None:
                raise ValueError("USER disappeared during hard delete")
            self.s.execute(
                text("DELETE FROM security.security_principals WHERE principal_id=:user_id"),
                {"user_id": user_id},
            )
            self.s.commit()
        except Exception:
            self.s.rollback()
            raise

        return HardDeleteResult(
            user_id=user_id,
            deletion_request_id=deletion_request_id,
            tombstone_id=tombstone_id,
            deleted_at_utc=now,
            retain_until_utc=retain_until,
        )

    def _user_for_update(self, user_id: str) -> dict[str, object] | None:
        row = self.s.execute(
            text(
                """
                SELECT user_id,status,display_name,primary_email
                FROM security.users
                WHERE user_id=:user_id
                FOR UPDATE
                """
            ),
            {"user_id": user_id},
        ).mappings().first()
        return dict(row) if row is not None else None

    def _user_snapshot(self, user_id: str) -> dict[str, object] | None:
        row = self.s.execute(
            text(
                """
                SELECT user_id,status,display_name,primary_email
                FROM security.users
                WHERE user_id=:user_id
                """
            ),
            {"user_id": user_id},
        ).mappings().first()
        return dict(row) if row is not None else None

    def _clerk_subject(self, user_id: str) -> str | None:
        value = self.s.execute(
            text(
                """
                SELECT provider_subject
                FROM security.external_identities
                WHERE user_id=:user_id AND provider='CLERK' AND status='ACTIVE'
                """
            ),
            {"user_id": user_id},
        ).scalar_one_or_none()
        return str(value) if value is not None else None

    def _open_deletion_request_id(self, user_id: str) -> str | None:
        row = self._open_deletion_request(user_id)
        return str(row["deletion_request_id"]) if row is not None else None

    def _open_deletion_request(
        self,
        user_id: str,
        *,
        for_update: bool = False,
    ) -> dict[str, object] | None:
        suffix = " FOR UPDATE" if for_update else ""
        row = self.s.execute(
            text(
                """
                SELECT deletion_request_id,user_id,requested_by_user_id,requested_at_utc,
                       reason,status,correlation_id
                FROM security.user_deletion_requests
                WHERE user_id=:user_id AND status='REQUESTED'
                """ + suffix
            ),
            {"user_id": user_id},
        ).mappings().first()
        return dict(row) if row is not None else None

    def _is_active_super_admin(self, user_id: str) -> bool:
        return (
            self.s.execute(
                text(
                    """
                    SELECT 1
                    FROM security.user_admin_role_assignments
                    WHERE user_id=:user_id
                      AND role_key='SuperAdmin'
                      AND status='ACTIVE'
                    LIMIT 1
                    """
                ),
                {"user_id": user_id},
            ).first()
            is not None
        )

    def _actor_is_executive(self, user_id: str) -> bool:
        return (
            self.s.execute(
                text(
                    """
                    SELECT 1
                    FROM security.user_tenant_operating_roles
                    WHERE user_id=:user_id
                      AND role_key='Executive'
                      AND status='ACTIVE'
                    LIMIT 1
                    """
                ),
                {"user_id": user_id},
            ).first()
            is not None
        )

    @staticmethod
    def _require_super_admin(actor: HumanActorContext) -> None:
        if not actor.is_super_admin:
            raise PermissionError("SuperAdmin authority is required")

    def _require_deletion_maker(self, actor: HumanActorContext, target_user_id: str) -> None:
        if actor.user_id == target_user_id:
            return
        if actor.is_super_admin or actor.has_admin_classification:
            return
        if self._actor_is_executive(actor.user_id):
            return
        raise PermissionError("Caller is not an approved Phase-1 deletion-request maker")

    def _audit(
        self,
        *,
        actor_user_id: str,
        correlation_id: str,
        operation_key: str,
        resource_id: str,
        before: dict[str, object],
        after: dict[str, object],
        now: datetime,
    ) -> None:
        self.s.execute(
            text(
                """
                INSERT INTO security.admin_change_records
                (admin_change_id,correlation_id,scope_type,actor_user_id,operation_key,
                 resource_type,resource_id,outcome,before_state_json,after_state_json,
                 occurred_at_utc)
                VALUES (:id,:correlation_id,'PLATFORM',:actor,:operation_key,
                        'USER',:resource_id,'SUCCESS',CAST(:before AS jsonb),
                        CAST(:after AS jsonb),:now)
                """
            ),
            {
                "id": str(uuid4()),
                "correlation_id": correlation_id,
                "actor": actor_user_id,
                "operation_key": operation_key,
                "resource_id": resource_id,
                "before": json.dumps(before),
                "after": json.dumps(after),
                "now": now,
            },
        )

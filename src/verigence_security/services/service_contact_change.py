from __future__ import annotations

import json
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import UUID, uuid4

from sqlalchemy import text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError
from verigence_security.services.phase1_self_onboarding import Phase1SelfOnboardingService
from verigence_security.services.v2_platform_user_create import InvalidUserInput


class ContactConflict(ValueError):
    """The new email or mobile already belongs to another Verigence user."""


@dataclass(frozen=True, slots=True)
class ContactChangeResult:
    user_id: str
    email: str | None
    mobile: str | None
    email_changed: bool
    mobile_changed: bool
    old_email_removed: bool


class ServiceContactChange:
    """The HR service corrects an employee's email or mobile on the SAME Verigence login.

    The user keeps the same user id and the same identity-provider user, so roles, memberships and
    sessions are untouched; only the contact details change. The email order is: add the new email
    at the provider and make it primary, then update Security, then remove the old provider
    address. If the Security update fails the provider is put back. Repeating the same request is
    safe and finishes whatever step was left. The mobile number is kept in Security only (the
    provider account is created without one), so a mobile change never calls the provider."""

    def __init__(self, session: Session) -> None:
        self.s = session

    def change(
        self,
        *,
        user_id: str,
        email: str | None,
        mobile: str | None,
        principal_id: str,
        integration_key: str,
        correlation_id: str,
        clerk: ClerkBackendClient,
    ) -> ContactChangeResult:
        onboarding = Phase1SelfOnboardingService(self.s)
        try:
            clean_email = onboarding._email(email) if email else None
            clean_mobile = onboarding._indian_mobile(mobile) if mobile else None
        except ValueError as exc:
            raise InvalidUserInput(str(exc)) from exc
        if clean_email is None and clean_mobile is None:
            raise InvalidUserInput("An email or a mobile number is required")
        try:
            UUID(user_id)
        except ValueError as exc:
            raise LookupError("User not found") from exc

        row = self.s.execute(
            text(
                """
                SELECT u.primary_email, u.primary_mobile, e.provider_subject
                FROM security.users u
                LEFT JOIN security.external_identities e
                  ON e.user_id=u.user_id AND e.provider='CLERK' AND e.status='ACTIVE'
                WHERE u.user_id=CAST(:user_id AS uuid)
                """
            ),
            {"user_id": user_id},
        ).first()
        if row is None:
            raise LookupError("User not found")
        current_email = (row[0] or "").strip().lower()
        current_mobile = row[1]
        clerk_subject = row[2]
        email_changes = clean_email is not None and clean_email != current_email
        mobile_changes = clean_mobile is not None and clean_mobile != current_mobile
        if clean_email is not None and not clerk_subject:
            raise ValueError("The user has no sign-in identity")

        if email_changes and self._other_user_has_email(user_id, clean_email or ""):
            raise ContactConflict("Another Verigence user already has this email")
        if mobile_changes and self._other_user_has_mobile(user_id, clean_mobile or ""):
            raise ContactConflict("Another Verigence user already has this mobile number")

        # Never hold a database transaction open across the identity-provider calls.
        self.s.rollback()
        previous: str | None = None
        if clean_email is not None:
            # Also run when Security already has this email: a repeat then finishes the provider side.
            previous = clerk.replace_primary_email(str(clerk_subject), clean_email)

        if email_changes or mobile_changes:
            try:
                self._update(
                    user_id=user_id,
                    old_email=current_email,
                    new_email=clean_email if email_changes else None,
                    new_mobile=clean_mobile if mobile_changes else None,
                    principal_id=principal_id,
                    integration_key=integration_key,
                    correlation_id=correlation_id,
                )
            except IntegrityError as exc:
                self.s.rollback()
                self._put_back(clerk, str(clerk_subject), previous, email_changes)
                raise ContactConflict("Email or mobile number is already registered") from exc
            except Exception:
                self.s.rollback()
                self._put_back(clerk, str(clerk_subject), previous, email_changes)
                raise

        removed = False
        if clean_email is not None:
            # The old address is removed last and only as a tidy-up: if this fails, sign-in still
            # works (Security finds users by its own email) and a repeat of the request removes it.
            with suppress(ClerkBackendError):
                clerk.remove_other_emails(str(clerk_subject), clean_email)
                removed = True
        return ContactChangeResult(
            user_id=user_id,
            email=clean_email,
            mobile=clean_mobile,
            email_changed=email_changes,
            mobile_changed=mobile_changes,
            old_email_removed=removed,
        )

    def _other_user_has_email(self, user_id: str, email: str) -> bool:
        return (
            self.s.execute(
                text(
                    "SELECT 1 FROM security.users WHERE lower(primary_email)=:email"
                    " AND user_id<>CAST(:user_id AS uuid) LIMIT 1"
                ),
                {"email": email, "user_id": user_id},
            ).first()
            is not None
        )

    def _other_user_has_mobile(self, user_id: str, mobile: str) -> bool:
        return (
            self.s.execute(
                text(
                    "SELECT 1 FROM security.users"
                    " WHERE regexp_replace(coalesce(primary_mobile,''), '[^0-9]', '', 'g')=:digits"
                    " AND user_id<>CAST(:user_id AS uuid) LIMIT 1"
                ),
                {"digits": mobile.removeprefix("+"), "user_id": user_id},
            ).first()
            is not None
        )

    def _update(
        self,
        *,
        user_id: str,
        old_email: str,
        new_email: str | None,
        new_mobile: str | None,
        principal_id: str,
        integration_key: str,
        correlation_id: str,
    ) -> None:
        now = datetime.now(UTC)
        if new_email is not None:
            self.s.execute(
                text(
                    "UPDATE security.users SET primary_email=:email, updated_at_utc=:now"
                    " WHERE user_id=CAST(:user_id AS uuid)"
                ),
                {"email": new_email, "now": now, "user_id": user_id},
            )
            # Users created by a service carry their email as the principal name; keep it in step.
            self.s.execute(
                text(
                    "UPDATE security.security_principals SET principal_name=:email, updated_at_utc=:now"
                    " WHERE principal_id=CAST(:user_id AS uuid) AND lower(principal_name)=:old"
                ),
                {"email": new_email, "now": now, "user_id": user_id, "old": old_email},
            )
        if new_mobile is not None:
            self.s.execute(
                text(
                    "UPDATE security.users SET primary_mobile=:mobile, updated_at_utc=:now"
                    " WHERE user_id=CAST(:user_id AS uuid)"
                ),
                {"mobile": new_mobile, "now": now, "user_id": user_id},
            )
        self.s.execute(
            text(
                """
                INSERT INTO security.security_events
                (security_event_id,tenant_id,principal_id,actor_type,event_type,entity_type,
                 entity_id,outcome,reason_code,correlation_id,payload_json,occurred_at_utc)
                VALUES (:id,NULL,:principal_id,'SERVICE_INTEGRATION','SERVICE_USER_CONTACT_CHANGE',
                        'USER',:user_id,'SUCCESS','CHANGED',:correlation_id,CAST(:payload AS jsonb),:now)
                """
            ),
            {
                "id": str(uuid4()),
                "principal_id": principal_id,
                "user_id": user_id,
                "correlation_id": correlation_id,
                "payload": json.dumps(
                    {
                        "integrationKey": integration_key,
                        "emailFrom": old_email if new_email is not None else None,
                        "emailTo": new_email,
                        "mobileChanged": new_mobile is not None,
                    }
                ),
                "now": now,
            },
        )
        self.s.commit()

    @staticmethod
    def _put_back(clerk: ClerkBackendClient, subject: str, previous: str | None, email_changed: bool) -> None:
        """Security could not save the change, so the provider is returned to the old email."""
        if not email_changed or not previous:
            return
        with suppress(ClerkBackendError):
            clerk.replace_primary_email(subject, previous)
            clerk.remove_other_emails(subject, previous)

from __future__ import annotations

from typing import Any

from sqlalchemy import text
from sqlalchemy.orm import Session

TARGET_USER_STATUSES = frozenset({"PENDING", "REJECTED", "ACTIVE", "SUSPENDED", "DISABLED"})


class V2UserDirectoryService:
    def __init__(self, session: Session) -> None:
        self.s = session

    def list_users(
        self,
        *,
        status: str | None,
        search: str | None,
        limit: int,
        offset: int,
    ) -> list[dict[str, Any]]:
        normalized_status = status.strip().upper() if status else None
        if normalized_status is not None and normalized_status not in TARGET_USER_STATUSES:
            raise ValueError("Unsupported Phase-1 USER status filter")
        normalized_search = search.strip().lower() if search else None
        if normalized_search == "":
            normalized_search = None

        rows = self.s.execute(
            text(
                """
                SELECT u.user_id,u.display_name,u.primary_email,u.primary_mobile,u.status,
                       u.created_at_utc,u.updated_at_utc,
                       e.provider_subject AS clerk_subject,
                       r.status AS onboarding_status
                FROM security.users u
                LEFT JOIN security.external_identities e
                  ON e.user_id=u.user_id AND e.provider='CLERK' AND e.status='ACTIVE'
                LEFT JOIN security.platform_user_onboarding_requests r
                  ON r.user_id=u.user_id
                WHERE (:status IS NULL OR u.status=:status)
                  AND (
                    :search IS NULL
                    OR lower(u.display_name) LIKE '%' || :search || '%'
                    OR lower(COALESCE(u.primary_email,'')) LIKE '%' || :search || '%'
                    OR lower(COALESCE(u.primary_mobile,'')) LIKE '%' || :search || '%'
                  )
                ORDER BY u.created_at_utc DESC,u.user_id
                LIMIT :limit OFFSET :offset
                """
            ),
            {
                "status": normalized_status,
                "search": normalized_search,
                "limit": limit,
                "offset": offset,
            },
        ).mappings()
        return [dict(row) for row in rows]

    def get_user(self, user_id: str) -> dict[str, Any] | None:
        row = self.s.execute(
            text(
                """
                SELECT u.user_id,u.display_name,u.primary_email,u.primary_mobile,u.status,
                       u.created_at_utc,u.updated_at_utc,
                       e.provider_subject AS clerk_subject,
                       r.status AS onboarding_status
                FROM security.users u
                LEFT JOIN security.external_identities e
                  ON e.user_id=u.user_id AND e.provider='CLERK' AND e.status='ACTIVE'
                LEFT JOIN security.platform_user_onboarding_requests r
                  ON r.user_id=u.user_id
                WHERE u.user_id=:user_id
                """
            ),
            {"user_id": user_id},
        ).mappings().first()
        return dict(row) if row is not None else None

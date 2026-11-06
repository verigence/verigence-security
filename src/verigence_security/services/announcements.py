from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any, Literal
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.orm import Session

Kind = Literal["NOTICE", "WELCOME", "MAINTENANCE"]
Audience = Literal["EVERYONE", "PEOPLE"]

# Until SuperAdmin sets it: a person sees at most one notice or greeting in this many hours.
DEFAULT_QUIET_HOURS = 20

# Every query reading these names the announcements table "a".
_COLUMNS = (
    "a.announcement_id, a.kind, a.title, a.body, a.back_at_utc, a.starts_at_utc, a.ends_at_utc,"
    " a.audience, a.active,"
    " (SELECT left(i.sha256, 16) FROM security.announcement_images i"
    "  WHERE i.announcement_id = a.announcement_id)"
)

IMAGE_TYPES = {"image/png", "image/jpeg", "image/webp", "image/gif"}
MAX_IMAGE_BYTES = 2 * 1024 * 1024


def sniff_image(data: bytes) -> str | None:
    """The image type from the file's first bytes (never from what the uploader claims)."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if data.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "image/gif"
    return None


def _view(row: Any) -> dict[str, Any]:
    return {
        "announcementId": str(row[0]),
        "kind": row[1],
        "title": row[2],
        "body": row[3],
        "backAt": row[4].isoformat() if row[4] else None,
        "startsAt": row[5].isoformat(),
        "endsAt": row[6].isoformat() if row[6] else None,
        "audience": row[7],
        "active": bool(row[8]),
        # Changes when the image changes, so the apps can cache it by this version.
        "imageVersion": row[9],
    }


class AnnouncementService:
    """What people are told inside the apps. Greetings and notices are shown once per person and at
    most one a day; maintenance blocks the apps until it is ended."""

    def __init__(self, session: Session) -> None:
        self.session = session

    # ---- what the apps read ----------------------------------------------------------------

    def maintenance(self) -> dict[str, Any] | None:
        """The maintenance notice in force now, if any. Read before sign-in, so it needs no login."""
        row = self.session.execute(
            text(
                f"SELECT {_COLUMNS} FROM security.announcements a"
                " WHERE a.kind='MAINTENANCE' AND a.active AND a.starts_at_utc<=CURRENT_TIMESTAMP"
                " AND (a.ends_at_utc IS NULL OR a.ends_at_utc>CURRENT_TIMESTAMP)"
                " ORDER BY a.starts_at_utc DESC LIMIT 1"
            )
        ).first()
        return _view(row) if row else None

    def next_for(self, *, user_id: str) -> dict[str, Any] | None:
        """The one notice or greeting this person should see now, or None."""
        quiet_hours = self.quiet_hours()
        recent = (
            None
            if quiet_hours == 0
            else self.session.execute(
                text(
                    "SELECT 1 FROM security.announcement_seen s"
                    " JOIN security.announcements a ON a.announcement_id=s.announcement_id"
                    " WHERE s.user_id=CAST(:u AS uuid) AND a.kind<>'MAINTENANCE'"
                    " AND s.seen_at_utc>CURRENT_TIMESTAMP-CAST(:quiet AS interval) LIMIT 1"
                ),
                {"u": user_id, "quiet": f"{quiet_hours} hours"},
            ).first()
        )
        if recent is not None:
            return None
        row = self.session.execute(
            text(
                f"SELECT {_COLUMNS} FROM security.announcements a"
                " WHERE a.kind IN ('NOTICE','WELCOME') AND a.active"
                " AND a.starts_at_utc<=CURRENT_TIMESTAMP"
                " AND (a.ends_at_utc IS NULL OR a.ends_at_utc>CURRENT_TIMESTAMP)"
                " AND (a.audience='EVERYONE' OR EXISTS ("
                "   SELECT 1 FROM security.announcement_people p"
                "   WHERE p.announcement_id=a.announcement_id AND p.user_id=CAST(:u AS uuid)))"
                " AND NOT EXISTS ("
                "   SELECT 1 FROM security.announcement_seen s"
                "   WHERE s.announcement_id=a.announcement_id AND s.user_id=CAST(:u AS uuid))"
                " ORDER BY a.starts_at_utc, a.created_at_utc LIMIT 1"
            ),
            {"u": user_id},
        ).first()
        return _view(row) if row else None

    def quiet_hours(self) -> int:
        value = self.session.execute(
            text("SELECT quiet_hours FROM security.announcement_settings WHERE singleton")
        ).scalar_one_or_none()
        return DEFAULT_QUIET_HOURS if value is None else int(value)

    def set_quiet_hours(self, *, hours: int, actor_user_id: str, correlation_id: str) -> None:
        if not 0 <= hours <= 720:
            raise ValueError("Hours must be between 0 and 720")
        now = datetime.now(UTC)
        before = self.quiet_hours()
        try:
            self.session.execute(
                text(
                    "INSERT INTO security.announcement_settings (singleton,quiet_hours,updated_by_user_id)"
                    " VALUES (true,:h,CAST(:a AS uuid))"
                    " ON CONFLICT (singleton) DO UPDATE SET quiet_hours=EXCLUDED.quiet_hours,"
                    " updated_by_user_id=EXCLUDED.updated_by_user_id, updated_at_utc=CURRENT_TIMESTAMP"
                ),
                {"h": hours, "a": actor_user_id},
            )
            self._audit("settings", {"quietHours": before}, {"quietHours": hours}, actor_user_id, correlation_id, now)
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise

    def mark_seen(self, *, announcement_id: str, user_id: str) -> None:
        try:
            self.session.execute(
                text(
                    "INSERT INTO security.announcement_seen (announcement_id,user_id)"
                    " SELECT announcement_id, CAST(:u AS uuid) FROM security.announcements"
                    " WHERE announcement_id=CAST(:a AS uuid) AND kind<>'MAINTENANCE'"
                    " ON CONFLICT DO NOTHING"
                ),
                {"a": announcement_id, "u": user_id},
            )
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise

    # ---- what SuperAdmin manages -------------------------------------------------------------

    def listing(self) -> list[dict[str, Any]]:
        rows = self.session.execute(
            text(
                f"SELECT {_COLUMNS},"
                " (SELECT count(*) FROM security.announcement_seen s WHERE s.announcement_id=a.announcement_id),"
                " (SELECT count(*) FROM security.announcement_people p WHERE p.announcement_id=a.announcement_id)"
                " FROM security.announcements a ORDER BY a.created_at_utc DESC LIMIT 100"
            )
        ).all()
        return [{**_view(r), "seenBy": int(r[10]), "chosenPeople": int(r[11])} for r in rows]

    def people_of(self, announcement_id: str) -> list[dict[str, Any]]:
        rows = self.session.execute(
            text(
                "SELECT u.user_id, u.display_name, u.primary_email FROM security.announcement_people p"
                " JOIN security.users u ON u.user_id=p.user_id"
                " WHERE p.announcement_id=CAST(:a AS uuid) ORDER BY u.display_name"
            ),
            {"a": announcement_id},
        ).all()
        return [{"userId": str(r[0]), "displayName": r[1], "email": r[2]} for r in rows]

    def create(
        self,
        *,
        kind: str,
        title: str,
        body: str,
        back_at: datetime | None,
        starts_at: datetime | None,
        ends_at: datetime | None,
        audience: str,
        people: list[str],
        actor_user_id: str,
        correlation_id: str,
    ) -> str:
        if kind == "MAINTENANCE" and audience != "EVERYONE":
            raise ValueError("Maintenance is for everyone")
        if audience == "PEOPLE" and not people:
            raise ValueError("Choose at least one person")
        announcement_id = str(uuid4())
        now = datetime.now(UTC)
        try:
            self.session.execute(
                text(
                    "INSERT INTO security.announcements (announcement_id,kind,title,body,back_at_utc,"
                    " starts_at_utc,ends_at_utc,audience,created_by_user_id)"
                    " VALUES (CAST(:id AS uuid),:kind,:title,:body,:back,COALESCE(:starts,CURRENT_TIMESTAMP),"
                    " :ends,:aud,CAST(:actor AS uuid))"
                ),
                {
                    "id": announcement_id,
                    "kind": kind,
                    "title": title,
                    "body": body,
                    "back": back_at,
                    "starts": starts_at,
                    "ends": ends_at,
                    "aud": audience,
                    "actor": actor_user_id,
                },
            )
            self._set_people(announcement_id, people if audience == "PEOPLE" else [])
            self._audit(announcement_id, None, {"kind": kind, "title": title}, actor_user_id, correlation_id, now)
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
        return announcement_id

    def update(
        self,
        *,
        announcement_id: str,
        title: str | None,
        body: str | None,
        back_at: datetime | None,
        ends_at: datetime | None,
        active: bool | None,
        people: list[str] | None,
        actor_user_id: str,
        correlation_id: str,
    ) -> None:
        now = datetime.now(UTC)
        try:
            row = self.session.execute(
                text(
                    "SELECT kind,audience FROM security.announcements WHERE announcement_id=CAST(:a AS uuid) FOR UPDATE"
                ),
                {"a": announcement_id},
            ).first()
            if row is None:
                raise LookupError("Announcement not found")
            self.session.execute(
                text(
                    "UPDATE security.announcements SET title=COALESCE(:title,title), body=COALESCE(:body,body),"
                    " back_at_utc=COALESCE(:back,back_at_utc), ends_at_utc=COALESCE(:ends,ends_at_utc),"
                    " active=COALESCE(:active,active), updated_at_utc=CURRENT_TIMESTAMP"
                    " WHERE announcement_id=CAST(:a AS uuid)"
                ),
                {
                    "a": announcement_id,
                    "title": title,
                    "body": body,
                    "back": back_at,
                    "ends": ends_at,
                    "active": active,
                },
            )
            if people is not None and row[1] == "PEOPLE":
                if not people:
                    raise ValueError("Choose at least one person")
                self._set_people(announcement_id, people)
            self._audit(
                announcement_id,
                None,
                {"active": active, "titleChanged": title is not None},
                actor_user_id,
                correlation_id,
                now,
            )
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise

    # ---- the image ---------------------------------------------------------------------------

    def image(self, announcement_id: str) -> tuple[str, bytes, str] | None:
        """(content type, bytes, sha256) of the announcement's image, if it has one."""
        row = self.session.execute(
            text(
                "SELECT content_type, data, sha256 FROM security.announcement_images"
                " WHERE announcement_id=CAST(:a AS uuid)"
            ),
            {"a": announcement_id},
        ).first()
        return (str(row[0]), bytes(row[1]), str(row[2])) if row else None

    def set_image(
        self,
        *,
        announcement_id: str,
        data: bytes,
        width: int | None,
        height: int | None,
        actor_user_id: str,
        correlation_id: str,
    ) -> str:
        """Adds or replaces the image. Returns its version. The type is read from the bytes."""
        if not data or len(data) > MAX_IMAGE_BYTES:
            raise ValueError("The image must be at most 2 MB")
        content_type = sniff_image(data)
        if content_type is None:
            raise ValueError("Only PNG, JPEG, WebP or GIF images can be added")
        digest = hashlib.sha256(data).hexdigest()
        now = datetime.now(UTC)
        try:
            exists = self.session.execute(
                text("SELECT 1 FROM security.announcements WHERE announcement_id=CAST(:a AS uuid) FOR UPDATE"),
                {"a": announcement_id},
            ).first()
            if exists is None:
                raise LookupError("Announcement not found")
            self.session.execute(
                text(
                    "INSERT INTO security.announcement_images (announcement_id,content_type,data,sha256,"
                    " width,height,uploaded_by_user_id,uploaded_at_utc) VALUES (CAST(:a AS uuid),:t,:d,:s,"
                    " :w,:h,CAST(:actor AS uuid),:now) ON CONFLICT (announcement_id) DO UPDATE SET"
                    " content_type=EXCLUDED.content_type, data=EXCLUDED.data, sha256=EXCLUDED.sha256,"
                    " width=EXCLUDED.width, height=EXCLUDED.height,"
                    " uploaded_by_user_id=EXCLUDED.uploaded_by_user_id, uploaded_at_utc=EXCLUDED.uploaded_at_utc"
                ),
                {
                    "a": announcement_id,
                    "t": content_type,
                    "d": data,
                    "s": digest,
                    "w": width,
                    "h": height,
                    "actor": actor_user_id,
                    "now": now,
                },
            )
            self.session.execute(
                text("UPDATE security.announcements SET updated_at_utc=:now WHERE announcement_id=CAST(:a AS uuid)"),
                {"a": announcement_id, "now": now},
            )
            self._audit(
                announcement_id,
                None,
                {"image": content_type, "bytes": len(data), "sha256": digest},
                actor_user_id,
                correlation_id,
                now,
            )
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise
        return digest[:16]

    def remove_image(self, *, announcement_id: str, actor_user_id: str, correlation_id: str) -> None:
        now = datetime.now(UTC)
        try:
            removed = self.session.execute(
                text(
                    "DELETE FROM security.announcement_images WHERE announcement_id=CAST(:a AS uuid) RETURNING sha256"
                ),
                {"a": announcement_id},
            ).first()
            if removed is None:
                raise LookupError("This announcement has no image")
            self._audit(announcement_id, {"sha256": removed[0]}, {"image": None}, actor_user_id, correlation_id, now)
            self.session.commit()
        except Exception:
            self.session.rollback()
            raise

    def _set_people(self, announcement_id: str, people: list[str]) -> None:
        self.session.execute(
            text("DELETE FROM security.announcement_people WHERE announcement_id=CAST(:a AS uuid)"),
            {"a": announcement_id},
        )
        for user_id in sorted(set(people)):
            self.session.execute(
                text(
                    "INSERT INTO security.announcement_people (announcement_id,user_id)"
                    " SELECT CAST(:a AS uuid), user_id FROM security.users"
                    " WHERE user_id=CAST(:u AS uuid) AND status='ACTIVE'"
                ),
                {"a": announcement_id, "u": user_id},
            )

    def _audit(
        self,
        announcement_id: str,
        before: dict[str, Any] | None,
        after: dict[str, Any] | None,
        actor_user_id: str,
        correlation_id: str,
        now: datetime,
    ) -> None:
        self.session.execute(
            text(
                """
                INSERT INTO security.admin_change_records (
                    admin_change_id,correlation_id,scope_type,tenant_id,actor_user_id,
                    operation_key,resource_type,resource_id,outcome,
                    before_state_json,after_state_json,occurred_at_utc
                ) VALUES (
                    CAST(:id AS uuid),:corr,'PLATFORM',NULL,CAST(:actor AS uuid),
                    'security.announcement.manage','ANNOUNCEMENT',:resource,
                    'SUCCESS',CAST(:before AS jsonb),CAST(:after AS jsonb),:now
                )
                """
            ),
            {
                "id": str(uuid4()),
                "corr": correlation_id,
                "actor": actor_user_id,
                "resource": announcement_id,
                "before": json.dumps(before) if before is not None else None,
                "after": json.dumps(after) if after is not None else None,
                "now": now,
            },
        )

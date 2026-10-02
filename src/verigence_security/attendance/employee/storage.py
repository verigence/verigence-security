from __future__ import annotations

import base64
import hashlib
import hmac
import time
from dataclasses import dataclass
from urllib.parse import urlencode

from sqlalchemy import text

from verigence_security.attendance.config import get_attendance_settings
from verigence_security.attendance.employee.db import employee_attendance_engine


class AttendanceStorageError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class StoredObject:
    data: bytes
    content_type: str
    sha256: str


class AttendanceStorage:
    """Database-backed evidence storage inside the existing Attendance database."""

    def put(self, *, object_key: str, data: bytes, content_type: str) -> None:
        digest = hashlib.sha256(data).hexdigest()
        try:
            with employee_attendance_engine().begin() as connection:
                connection.execute(
                    text(
                        """
                        INSERT INTO verigence_attendance.binary_objects (
                            object_key,content_type,content_bytes,sha256
                        ) VALUES (:key,:content_type,:data,:sha256)
                        """
                    ),
                    {
                        "key": object_key,
                        "content_type": content_type,
                        "data": data,
                        "sha256": digest,
                    },
                )
        except Exception as exc:
            raise AttendanceStorageError("Attendance evidence storage is unavailable") from exc

    def get(self, *, object_key: str) -> StoredObject:
        try:
            with employee_attendance_engine().connect() as connection:
                row = connection.execute(
                    text(
                        """
                        SELECT content_bytes,content_type,sha256
                        FROM verigence_attendance.binary_objects
                        WHERE object_key=:key
                        """
                    ),
                    {"key": object_key},
                ).mappings().first()
        except Exception as exc:
            raise AttendanceStorageError("Attendance evidence storage is unavailable") from exc
        if row is None:
            raise AttendanceStorageError("Attendance evidence was not found")
        return StoredObject(
            data=bytes(row["content_bytes"]),
            content_type=str(row["content_type"]),
            sha256=str(row["sha256"]),
        )

    def _secret(self) -> bytes:
        secret = get_attendance_settings().security_client_secret
        if not secret:
            raise AttendanceStorageError("Attendance signing secret is unavailable")
        return secret.encode("utf-8")

    def presign(self, *, object_key: str, expires_seconds: int = 900) -> str:
        expires = int(time.time()) + max(60, min(expires_seconds, 3600))
        token = base64.urlsafe_b64encode(object_key.encode("utf-8")).decode("ascii").rstrip("=")
        payload = f"{object_key}\n{expires}".encode("utf-8")
        signature = hmac.new(self._secret(), payload, hashlib.sha256).hexdigest()
        query = urlencode({"expires": expires, "signature": signature})
        return f"/employee-attendance/v1/files/{token}?{query}"

    def resolve_presigned(
        self,
        *,
        token: str,
        expires: int,
        signature: str,
    ) -> StoredObject:
        if expires < int(time.time()):
            raise AttendanceStorageError("Attendance file link has expired")
        try:
            padding = "=" * (-len(token) % 4)
            object_key = base64.urlsafe_b64decode(token + padding).decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise AttendanceStorageError("Attendance file link is invalid") from exc
        payload = f"{object_key}\n{expires}".encode("utf-8")
        expected = hmac.new(self._secret(), payload, hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            raise AttendanceStorageError("Attendance file link is invalid")
        return self.get(object_key=object_key)


_storage = AttendanceStorage()


def storage() -> AttendanceStorage:
    return _storage

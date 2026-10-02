from __future__ import annotations

import hashlib
from dataclasses import dataclass

from sqlalchemy import text

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


_storage = AttendanceStorage()


def storage() -> AttendanceStorage:
    return _storage

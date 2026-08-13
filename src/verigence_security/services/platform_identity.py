from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, slots=True)
class PlatformIdentityResult:
    access_token: str
    expires_at_utc: datetime
    user_id: str
    roles: tuple[str, ...]
    permissions: tuple[str, ...]

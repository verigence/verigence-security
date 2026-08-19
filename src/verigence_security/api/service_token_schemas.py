from __future__ import annotations

from pydantic import BaseModel


class ServiceTokenResponse(BaseModel):
    accessToken: str
    tokenType: str = "Bearer"
    expiresIn: int
    audience: str

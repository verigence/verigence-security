from __future__ import annotations

from uuid import UUID

from pydantic import BaseModel, Field, model_validator

from verigence_security.api.schemas import GeoContext


class ClerkCredentialRequest(BaseModel):
    identifier: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1)
    totpCode: str | None = Field(default=None, min_length=1, max_length=32)

    @model_validator(mode="after")
    def normalize_identifier(self) -> ClerkCredentialRequest:
        self.identifier = self.identifier.strip()
        if not self.identifier:
            raise ValueError("Identifier cannot be blank")
        return self


class ClerkUserAccessLoginRequest(ClerkCredentialRequest):
    tenantId: UUID
    deviceId: UUID
    geo: GeoContext


class ClerkSelfRegistrationRequest(BaseModel):
    displayName: str = Field(min_length=1, max_length=240)
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1)

    @model_validator(mode="after")
    def normalize_values(self) -> ClerkSelfRegistrationRequest:
        self.displayName = self.displayName.strip()
        self.email = self.email.strip()
        if not self.displayName or not self.email:
            raise ValueError("Display name and email cannot be blank")
        return self


class ClerkInvitationAcceptanceRequest(BaseModel):
    password: str = Field(min_length=1)
    totpCode: str | None = Field(default=None, min_length=1, max_length=32)

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import httpx

from verigence_security.config import Settings
from verigence_security.core.errors import security_error


@dataclass(frozen=True, slots=True)
class ClerkBackendUser:
    user_id: str
    display_name: str
    primary_email: str | None
    username: str | None
    totp_enabled: bool
    banned: bool
    locked: bool


class ClerkBackendClient:
    """Server-to-server Clerk credential/user adapter.

    Passwords and TOTP values are accepted only as transient call arguments and are never retained.
    """

    def __init__(self, settings: Settings) -> None:
        if not settings.clerk_secret_key:
            raise security_error("AUTH_TOKEN_INVALID")
        self._base_url = settings.clerk_backend_api_url.rstrip("/")
        self._headers = {
            "Authorization": f"Bearer {settings.clerk_secret_key}",
            "Content-Type": "application/json",
        }

    def find_user(self, identifier: str) -> ClerkBackendUser | None:
        normalized = identifier.strip()
        if not normalized:
            return None
        payload = self._request_json(
            "GET",
            "/users",
            params={"query": normalized, "limit": "20"},
        )
        if not isinstance(payload, list):
            raise security_error("AUTH_TOKEN_INVALID")
        exact = [
            self._user_from_payload(row)
            for row in payload
            if isinstance(row, dict) and self._matches_identifier(row, normalized)
        ]
        if not exact:
            return None
        if len(exact) != 1:
            raise security_error("AUTH_TOKEN_INVALID")
        return exact[0]

    def get_user(self, user_id: str) -> ClerkBackendUser | None:
        try:
            payload = self._request_json("GET", f"/users/{user_id}")
        except ClerkNotFoundError:
            return None
        if not isinstance(payload, dict):
            raise security_error("AUTH_TOKEN_INVALID")
        return self._user_from_payload(payload)

    def create_user(
        self,
        *,
        email: str,
        password: str,
        first_name: str | None = None,
        last_name: str | None = None,
    ) -> ClerkBackendUser:
        body: dict[str, object] = {
            "email_address": [email.strip()],
            "password": password,
        }
        if first_name:
            body["first_name"] = first_name
        if last_name:
            body["last_name"] = last_name
        payload = self._request_json("POST", "/users", json=body)
        if not isinstance(payload, dict):
            raise security_error("AUTH_TOKEN_INVALID")
        return self._user_from_payload(payload)

    def verify_password(self, *, user_id: str, password: str) -> bool:
        try:
            payload = self._request_json(
                "POST",
                f"/users/{user_id}/verify_password",
                json={"password": password},
            )
        except ClerkCredentialError:
            return False
        return isinstance(payload, dict) and payload.get("verified") is True

    def verify_totp(self, *, user_id: str, code: str) -> bool:
        try:
            payload = self._request_json(
                "POST",
                f"/users/{user_id}/verify_totp",
                json={"code": code},
            )
        except ClerkCredentialError:
            return False
        return isinstance(payload, dict) and payload.get("verified") is True

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, str] | None = None,
        json: dict[str, object] | None = None,
    ) -> Any:
        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.request(
                    method,
                    f"{self._base_url}{path}",
                    headers=self._headers,
                    params=params,
                    json=json,
                )
        except httpx.HTTPError as exc:
            raise security_error("AUTH_TOKEN_INVALID", "Identity provider unavailable") from exc
        if response.status_code == 404:
            raise ClerkNotFoundError
        if response.status_code in {400, 401, 403, 409, 422}:
            raise ClerkCredentialError
        if response.status_code >= 500:
            raise security_error("AUTH_TOKEN_INVALID", "Identity provider unavailable")
        if not response.is_success:
            raise security_error("AUTH_TOKEN_INVALID")
        try:
            return response.json()
        except ValueError as exc:
            raise security_error("AUTH_TOKEN_INVALID") from exc

    @staticmethod
    def _matches_identifier(row: dict[str, Any], identifier: str) -> bool:
        target = identifier.casefold()
        username = row.get("username")
        if isinstance(username, str) and username.casefold() == target:
            return True
        for item in row.get("email_addresses", []):
            if isinstance(item, dict):
                value = item.get("email_address")
                if isinstance(value, str) and value.casefold() == target:
                    return True
        for item in row.get("phone_numbers", []):
            if isinstance(item, dict):
                value = item.get("phone_number")
                if isinstance(value, str) and value == identifier:
                    return True
        return False

    @staticmethod
    def _user_from_payload(row: dict[str, Any]) -> ClerkBackendUser:
        user_id = row.get("id")
        if not isinstance(user_id, str) or not user_id:
            raise security_error("AUTH_TOKEN_INVALID")
        first_name = row.get("first_name") if isinstance(row.get("first_name"), str) else ""
        last_name = row.get("last_name") if isinstance(row.get("last_name"), str) else ""
        display_name = " ".join(value for value in (first_name, last_name) if value).strip()
        username = row.get("username") if isinstance(row.get("username"), str) else None
        primary_email: str | None = None
        primary_id = row.get("primary_email_address_id")
        for item in row.get("email_addresses", []):
            if not isinstance(item, dict):
                continue
            value = item.get("email_address")
            if isinstance(value, str) and (item.get("id") == primary_id or primary_email is None):
                primary_email = value
                if item.get("id") == primary_id:
                    break
        return ClerkBackendUser(
            user_id=user_id,
            display_name=display_name or username or primary_email or user_id,
            primary_email=primary_email,
            username=username,
            totp_enabled=bool(row.get("totp_enabled")),
            banned=bool(row.get("banned")),
            locked=bool(row.get("locked")),
        )


class ClerkCredentialError(Exception):
    pass


class ClerkNotFoundError(Exception):
    pass

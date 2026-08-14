from __future__ import annotations

from typing import Any

import httpx

from verigence_security.config import Settings


class ClerkBackendError(RuntimeError):
    """Clerk Backend API operation failed or returned an unusable response."""


class ClerkBackendClient:
    """Narrow Clerk Backend API adapter for Verigence human identity lifecycle.

    Active v1.4.6 onboarding uses Clerk client-side sign-up for password and email OTP. Security
    uses this backend adapter only to verify the resulting Clerk user, synchronize profile names,
    and enforce lifecycle actions. Mobile numbers remain Verigence-only.
    """

    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        if not settings.clerk_secret_key.strip():
            raise ClerkBackendError("CLERK_SECRET_KEY is required for Clerk lifecycle operations")
        self._base_url = settings.clerk_backend_api_url.rstrip("/")
        self._secret_key = settings.clerk_secret_key.strip()
        self._client = client

    # Historical v1.4.5 compatibility only. Active v1.4.6 onboarding MUST NOT call this method.
    def create_user(
        self,
        *,
        first_name: str,
        last_name: str,
        email: str,
        password: str,
    ) -> str:
        payload = {
            "first_name": first_name,
            "last_name": last_name,
            "email_address": [email],
            "password": password,
        }
        data = self._request("POST", "/users", json=payload)
        clerk_user_id = data.get("id")
        if not isinstance(clerk_user_id, str) or not clerk_user_id.startswith("user_"):
            raise ClerkBackendError("Clerk user response did not contain an immutable user ID")
        return clerk_user_id

    def delete_user(self, clerk_user_id: str) -> None:
        self._request("DELETE", f"/users/{clerk_user_id}")

    # Historical v1.4.2 compatibility only. The active Phase 1 onboarding API no longer uses
    # Clerk invitations or a later invitation-binding route.
    def create_invitation(
        self,
        *,
        email: str,
        security_user_id: str,
        onboarding_request_id: str,
    ) -> str:
        payload = {
            "email_address": email,
            "notify": True,
            "public_metadata": {
                "verigence_user_id": security_user_id,
                "verigence_onboarding_request_id": onboarding_request_id,
            },
        }
        data = self._request("POST", "/invitations", json=payload)
        invitation_id = data.get("id")
        if not isinstance(invitation_id, str) or not invitation_id:
            raise ClerkBackendError("Clerk invitation response did not contain an invitation ID")
        return invitation_id

    def get_user(self, clerk_user_id: str) -> dict[str, Any]:
        data = self._request("GET", f"/users/{clerk_user_id}")
        if not isinstance(data.get("id"), str):
            raise ClerkBackendError("Clerk user response did not contain a user ID")
        return data

    def is_email_verified(self, clerk_user_id: str, expected_email: str) -> bool:
        expected = expected_email.strip().lower()
        user = self.get_user(clerk_user_id)
        values = user.get("email_addresses")
        if not isinstance(values, list):
            return False
        for item in values:
            if not isinstance(item, dict):
                continue
            value = item.get("email_address")
            if not isinstance(value, str) or value.strip().lower() != expected:
                continue
            verification = item.get("verification")
            return isinstance(verification, dict) and verification.get("status") == "verified"
        return False

    def update_user_profile(self, clerk_user_id: str, *, first_name: str, last_name: str) -> None:
        self._request(
            "PATCH",
            f"/users/{clerk_user_id}",
            json={"first_name": first_name, "last_name": last_name},
        )

    def primary_email(self, clerk_user_id: str) -> str | None:
        user = self.get_user(clerk_user_id)
        primary_id = user.get("primary_email_address_id")
        values = user.get("email_addresses")
        if not isinstance(values, list):
            return None
        for item in values:
            if not isinstance(item, dict):
                continue
            if primary_id is not None and item.get("id") != primary_id:
                continue
            value = item.get("email_address")
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
        for item in values:
            if isinstance(item, dict):
                value = item.get("email_address")
                if isinstance(value, str) and value.strip():
                    return value.strip().lower()
        return None

    def ban_user(self, clerk_user_id: str) -> None:
        self._request("POST", f"/users/{clerk_user_id}/ban")

    def unban_user(self, clerk_user_id: str) -> None:
        self._request("POST", f"/users/{clerk_user_id}/unban")

    def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        headers = {
            "Authorization": f"Bearer {self._secret_key}",
            "Content-Type": "application/json",
        }
        owns_client = self._client is None
        client = self._client or httpx.Client(timeout=10.0)
        try:
            response = client.request(
                method,
                f"{self._base_url}{path}",
                headers=headers,
                **kwargs,
            )
            if response.status_code < 200 or response.status_code >= 300:
                raise ClerkBackendError(
                    f"Clerk Backend API returned HTTP {response.status_code} for {method} {path}"
                )
            body = response.json()
            if not isinstance(body, dict):
                raise ClerkBackendError("Clerk Backend API returned a non-object response")
            return body
        except httpx.HTTPError as exc:
            raise ClerkBackendError(f"Clerk Backend API request failed for {method} {path}") from exc
        finally:
            if owns_client:
                client.close()

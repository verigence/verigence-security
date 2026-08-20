from __future__ import annotations

from contextlib import suppress
from dataclasses import dataclass
from typing import Any
from uuid import uuid4

import httpx

from verigence_security.config import Settings


class ClerkBackendError(RuntimeError):
    """Clerk Backend API operation failed or returned an unusable response."""

    def __init__(
        self,
        message: str,
        *,
        status_code: int | None = None,
        provider_code: str | None = None,
        provider_detail: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.provider_code = provider_code
        self.provider_detail = provider_detail

    @property
    def retryable(self) -> bool:
        return self.status_code is None or self.status_code >= 500


@dataclass(frozen=True, slots=True)
class ClerkBackendUser:
    user_id: str
    display_name: str
    primary_email: str | None
    totp_enabled: bool
    banned: bool
    locked: bool


class ClerkBackendClient:
    """Server-to-server Clerk adapter for Verigence human identity.

    Mobile/Web never call Clerk. Passwords and OTP values are transient call arguments only and
    are never retained by this adapter. Clerk remains the credential store/verifier; Security
    remains the Verigence identity, authorization and lifecycle authority.
    """

    def __init__(self, settings: Settings, client: httpx.Client | None = None) -> None:
        if not settings.clerk_secret_key.strip():
            raise ClerkBackendError("CLERK_SECRET_KEY is required for Clerk lifecycle operations")
        self._base_url = settings.clerk_backend_api_url.rstrip("/")
        self._secret_key = settings.clerk_secret_key.strip()
        self._client = client

    def create_pending_email_user(
        self,
        *,
        first_name: str,
        last_name: str,
        email: str,
        password: str,
    ) -> tuple[str, str, str]:
        """Create a banned Clerk user and prepare the applicant email for OTP verification.

        The DEV Clerk instance requires every user to retain at least one verified email address.
        Clerk also marks email addresses supplied to createUser as verified automatically. To keep
        that provider invariant without falsely verifying the applicant's email, Security creates
        the banned user with an internal temporary verified placeholder, then attaches the real
        signup email as a separate unverified EmailAddress and prepares email-code verification.
        The placeholder is removed only after the applicant email has actually verified.
        """

        placeholder_email = f"verigence-pending-{uuid4().hex}@example.com"
        data = self._request_object(
            "POST",
            "/users",
            json={
                "first_name": first_name,
                "last_name": last_name,
                "email_address": [placeholder_email],
                "password": password,
                "banned": True,
            },
        )
        clerk_user_id = data.get("id")
        if not isinstance(clerk_user_id, str) or not clerk_user_id.startswith("user_"):
            raise ClerkBackendError("Clerk user response did not contain an immutable user ID")
        if data.get("banned") is not True:
            with suppress(Exception):
                self.delete_user(clerk_user_id)
            raise ClerkBackendError("Pending Clerk user was not created banned")

        try:
            placeholder_id = self._email_address_id(data, placeholder_email)
            placeholder_item = self._email_item(data, placeholder_email)
            verification = placeholder_item.get("verification")
            if not isinstance(verification, dict) or verification.get("status") != "verified":
                raise ClerkBackendError("Pending Clerk placeholder email was not verified")

            applicant = self._request_object(
                "POST",
                "/email_addresses",
                json={
                    "user_id": clerk_user_id,
                    "email_address": email,
                    "primary": False,
                    "verified": False,
                },
            )
            email_address_id = applicant.get("id")
            if not isinstance(email_address_id, str) or not email_address_id:
                raise ClerkBackendError("Clerk did not return the signup email address ID")
            if applicant.get("email_address", "").strip().lower() != email.strip().lower():
                raise ClerkBackendError("Clerk attached a different signup email address")

            verification_id = self.prepare_email_verification(email_address_id)

            # Defensive invariant check: the provider placeholder must still exist until the real
            # applicant email is verified, otherwise the Clerk instance can reject subsequent calls.
            current = self.get_user(clerk_user_id)
            if self._email_address_id(current, placeholder_email) != placeholder_id:
                raise ClerkBackendError("Pending Clerk placeholder email changed during preparation")
        except Exception:
            # Best-effort compensation. A failed onboarding preparation must not leave a provider
            # identity reserving the applicant's email. The user remains banned until deletion.
            with suppress(Exception):
                self.delete_user(clerk_user_id)
            raise

        return clerk_user_id, email_address_id, verification_id

    # Retained for controlled migration/test compatibility. Normal self-onboarding uses
    # create_pending_email_user() so email ownership is verified explicitly.
    def create_user(
        self,
        *,
        first_name: str,
        last_name: str,
        email: str,
        password: str,
    ) -> str:
        data = self._request_object(
            "POST",
            "/users",
            json={
                "first_name": first_name,
                "last_name": last_name,
                "email_address": [email],
                "password": password,
            },
        )
        clerk_user_id = data.get("id")
        if not isinstance(clerk_user_id, str) or not clerk_user_id.startswith("user_"):
            raise ClerkBackendError("Clerk user response did not contain an immutable user ID")
        return clerk_user_id

    def prepare_email_verification(self, email_address_id: str) -> str:
        data = self._request_object(
            "POST",
            f"/email_addresses/{email_address_id}/prepare_verification",
            json={"strategy": "email_code"},
        )
        verification = self._verification_payload(data)
        verification_id = verification.get("id")
        if not isinstance(verification_id, str) or not verification_id.startswith("ver_"):
            raise ClerkBackendError("Clerk email verification response did not contain a verification ID")
        if verification.get("status") != "unverified":
            raise ClerkBackendError("Clerk email verification was not prepared as unverified")
        if verification.get("strategy") != "email_code":
            raise ClerkBackendError("Clerk email verification did not use email_code")
        return verification_id

    def attempt_email_verification(
        self,
        email_address_id: str,
        verification_id: str,
        code: str,
    ) -> bool:
        try:
            data = self._request_object(
                "POST",
                f"/email_addresses/{email_address_id}/attempt_verification",
                json={"verification_id": verification_id, "code": code},
            )
        except ClerkBackendError as exc:
            if exc.status_code in {400, 401, 403, 409, 422}:
                return False
            raise
        verification = self._verification_payload(data)
        return verification.get("status") == "verified"

    def finalize_pending_email_user(
        self,
        *,
        clerk_user_id: str,
        email_address_id: str,
        expected_email: str,
    ) -> None:
        """Promote the verified applicant email and remove only our temporary placeholder.

        This is intentionally idempotent so Security can safely resume after an OTP succeeded at
        Clerk but a later Security database commit failed. It never unbans the Clerk user; Admin
        approval remains the only path that activates the provider identity.
        """

        expected = expected_email.strip().lower()
        user = self.get_user(clerk_user_id)
        if user.get("banned") is not True:
            raise ClerkBackendError("Pending Clerk user must remain banned during email verification")

        applicant = self._email_item(user, expected)
        if applicant.get("id") != email_address_id:
            raise ClerkBackendError("Signup email address ID changed during verification")
        verification = applicant.get("verification")
        if not isinstance(verification, dict) or verification.get("status") != "verified":
            raise ClerkBackendError("Signup email is not verified at Clerk")

        if user.get("primary_email_address_id") != email_address_id:
            self._request_object(
                "PATCH",
                f"/email_addresses/{email_address_id}",
                json={"primary": True, "verified": True},
            )

        # Re-read before deletion so we never remove an unexpected address. Only placeholders
        # generated by this adapter are eligible for cleanup.
        user = self.get_user(clerk_user_id)
        if user.get("banned") is not True:
            raise ClerkBackendError("Pending Clerk user became usable during email finalization")
        if user.get("primary_email_address_id") != email_address_id:
            raise ClerkBackendError("Verified signup email was not promoted to primary")

        extras: list[dict[str, Any]] = []
        values = user.get("email_addresses")
        if not isinstance(values, list):
            raise ClerkBackendError("Clerk user response did not contain email addresses")
        for item in values:
            if not isinstance(item, dict) or item.get("id") == email_address_id:
                continue
            value = item.get("email_address")
            if not isinstance(value, str) or not self._is_pending_placeholder(value):
                raise ClerkBackendError("Pending Clerk user contains an unexpected extra email address")
            extras.append(item)

        for item in extras:
            item_id = item.get("id")
            if isinstance(item_id, str) and item_id:
                self._request_json(
                    "DELETE",
                    f"/email_addresses/{item_id}",
                    allow_empty=True,
                )

        final = self.get_user(clerk_user_id)
        if final.get("banned") is not True:
            raise ClerkBackendError("Pending Clerk user must remain banned after email finalization")
        if final.get("primary_email_address_id") != email_address_id:
            raise ClerkBackendError("Final Clerk primary email does not match the signup email")
        values = final.get("email_addresses")
        if not isinstance(values, list) or len(values) != 1:
            raise ClerkBackendError("Pending Clerk user retained unexpected email addresses")
        applicant = self._email_item(final, expected)
        if applicant.get("id") != email_address_id:
            raise ClerkBackendError("Final Clerk signup email address ID changed")
        verification = applicant.get("verification")
        if not isinstance(verification, dict) or verification.get("status") != "verified":
            raise ClerkBackendError("Final Clerk signup email is not verified")

    def find_user(self, identifier: str) -> ClerkBackendUser | None:
        normalized = identifier.strip()
        if not normalized:
            return None
        payload = self._request_json(
            "GET",
            "/users",
            params={"query": normalized, "limit": "20"},
        )
        rows: list[Any]
        if isinstance(payload, list):
            rows = payload
        elif isinstance(payload, dict) and isinstance(payload.get("data"), list):
            rows = payload["data"]
        else:
            raise ClerkBackendError("Clerk user-list response had an invalid shape")
        exact = [
            self._user_from_payload(row)
            for row in rows
            if isinstance(row, dict) and self._matches_identifier(row, normalized)
        ]
        if not exact:
            return None
        if len(exact) != 1:
            raise ClerkBackendError("Clerk identifier resolved to multiple users")
        return exact[0]

    def verify_password(self, *, clerk_user_id: str, password: str) -> bool:
        try:
            data = self._request_object(
                "POST",
                f"/users/{clerk_user_id}/verify_password",
                json={"password": password},
            )
        except ClerkBackendError as exc:
            if exc.status_code in {400, 401, 403, 409, 422}:
                return False
            raise
        return data.get("verified") is True

    def verify_totp(self, *, clerk_user_id: str, code: str) -> bool:
        try:
            data = self._request_object(
                "POST",
                f"/users/{clerk_user_id}/verify_totp",
                json={"code": code},
            )
        except ClerkBackendError as exc:
            if exc.status_code in {400, 401, 403, 409, 422}:
                return False
            raise
        return data.get("verified") is True

    def delete_user(self, clerk_user_id: str) -> None:
        self._request_json("DELETE", f"/users/{clerk_user_id}", allow_empty=True)

    # Historical v1.4.2 compatibility only. New onboarding does not use Clerk invitations.
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
        data = self._request_object("POST", "/invitations", json=payload)
        invitation_id = data.get("id")
        if not isinstance(invitation_id, str) or not invitation_id:
            raise ClerkBackendError("Clerk invitation response did not contain an invitation ID")
        return invitation_id

    def get_user(self, clerk_user_id: str) -> dict[str, Any]:
        data = self._request_object("GET", f"/users/{clerk_user_id}")
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
        self._request_object(
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
        self._request_object("POST", f"/users/{clerk_user_id}/ban")

    def unban_user(self, clerk_user_id: str) -> None:
        self._request_object("POST", f"/users/{clerk_user_id}/unban")

    def _request_object(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        body = self._request_json(method, path, **kwargs)
        if not isinstance(body, dict):
            raise ClerkBackendError("Clerk Backend API returned a non-object response")
        return body

    def _request_json(
        self,
        method: str,
        path: str,
        *,
        allow_empty: bool = False,
        **kwargs: Any,
    ) -> Any:
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
                provider_code, provider_detail = self._provider_error(response)
                raise ClerkBackendError(
                    f"Clerk Backend API returned HTTP {response.status_code} for {method} {path}",
                    status_code=response.status_code,
                    provider_code=provider_code,
                    provider_detail=provider_detail,
                )
            if allow_empty and not response.content:
                return None
            try:
                return response.json()
            except ValueError as exc:
                if allow_empty:
                    return None
                raise ClerkBackendError("Clerk Backend API returned invalid JSON") from exc
        except httpx.HTTPError as exc:
            raise ClerkBackendError(f"Clerk Backend API request failed for {method} {path}") from exc
        finally:
            if owns_client:
                client.close()

    @staticmethod
    def _provider_error(response: httpx.Response) -> tuple[str | None, str | None]:
        try:
            payload = response.json()
        except ValueError:
            return None, None

        candidate: object = payload
        if isinstance(payload, dict) and isinstance(payload.get("errors"), list) and payload["errors"]:
            candidate = payload["errors"][0]
        if not isinstance(candidate, dict):
            return None, None

        code = candidate.get("code")
        detail = (
            candidate.get("long_message")
            or candidate.get("longMessage")
            or candidate.get("message")
            or candidate.get("short_message")
            or candidate.get("shortMessage")
        )
        return (
            code if isinstance(code, str) and code else None,
            detail if isinstance(detail, str) and detail else None,
        )

    @staticmethod
    def _verification_payload(data: dict[str, Any]) -> dict[str, Any]:
        nested = data.get("verification")
        return nested if isinstance(nested, dict) else data

    @staticmethod
    def _email_item(user: dict[str, Any], expected_email: str) -> dict[str, Any]:
        expected = expected_email.strip().lower()
        values = user.get("email_addresses")
        if not isinstance(values, list):
            raise ClerkBackendError("Clerk user response did not contain email addresses")
        for item in values:
            if not isinstance(item, dict):
                continue
            value = item.get("email_address")
            if isinstance(value, str) and value.strip().lower() == expected:
                return item
        raise ClerkBackendError("Clerk user response did not contain the expected email address")

    @classmethod
    def _email_address_id(cls, user: dict[str, Any], expected_email: str) -> str:
        item = cls._email_item(user, expected_email)
        item_id = item.get("id")
        if not isinstance(item_id, str) or not item_id:
            raise ClerkBackendError("Clerk user response did not contain the email address ID")
        return item_id

    @staticmethod
    def _is_pending_placeholder(value: str) -> bool:
        normalized = value.strip().lower()
        return normalized.startswith("verigence-pending-") and normalized.endswith("@example.com")

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
        return False

    @staticmethod
    def _user_from_payload(row: dict[str, Any]) -> ClerkBackendUser:
        user_id = row.get("id")
        if not isinstance(user_id, str) or not user_id:
            raise ClerkBackendError("Clerk user response did not contain an immutable user ID")
        first_name = row.get("first_name") if isinstance(row.get("first_name"), str) else ""
        last_name = row.get("last_name") if isinstance(row.get("last_name"), str) else ""
        display_name = " ".join(value for value in (first_name, last_name) if value).strip()
        primary_email: str | None = None
        primary_id = row.get("primary_email_address_id")
        values = row.get("email_addresses")
        if isinstance(values, list):
            for item in values:
                if not isinstance(item, dict):
                    continue
                value = item.get("email_address")
                if isinstance(value, str) and (item.get("id") == primary_id or primary_email is None):
                    primary_email = value
                    if item.get("id") == primary_id:
                        break
        return ClerkBackendUser(
            user_id=user_id,
            display_name=display_name or primary_email or user_id,
            primary_email=primary_email,
            totp_enabled=bool(row.get("totp_enabled")),
            banned=bool(row.get("banned")),
            locked=bool(row.get("locked")),
        )

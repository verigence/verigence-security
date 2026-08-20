from __future__ import annotations

from contextlib import suppress

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError


def prepare_password_recovery_email(
    clerk: ClerkBackendClient,
    *,
    clerk_user_id: str,
    expected_email: str,
) -> tuple[str, str]:
    """Prepare a backend email-code proof for an existing verified Clerk address.

    Clerk's EmailAddress verification endpoint is designed around an unverified verification state.
    Verigence therefore temporarily marks the already-proven registered email unverified before
    preparing a fresh email-code challenge. If preparation fails, the previous verified state is
    restored immediately. Web/Mobile never see or call Clerk directly.
    """

    email_address_id = _verified_email_address_id(
        clerk,
        clerk_user_id=clerk_user_id,
        expected_email=expected_email,
    )
    clerk._request_object(  # noqa: SLF001 - internal Security adapter boundary
        "PATCH",
        f"/email_addresses/{email_address_id}",
        json={"verified": False},
    )
    try:
        verification_id = clerk.prepare_email_verification(email_address_id)
    except Exception:
        with suppress(Exception):
            restore_registered_email(clerk, email_address_id=email_address_id)
        raise
    return email_address_id, verification_id


def restore_registered_email(clerk: ClerkBackendClient, *, email_address_id: str) -> None:
    """Restore the prior verified state after a cancelled/expired recovery challenge."""

    clerk._request_object(  # noqa: SLF001 - internal Security adapter boundary
        "PATCH",
        f"/email_addresses/{email_address_id}",
        json={"verified": True},
    )


def update_password(
    clerk: ClerkBackendClient,
    *,
    clerk_user_id: str,
    password: str,
) -> None:
    """Set the Clerk-owned password and revoke provider sessions after recovery."""

    clerk._request_object(  # noqa: SLF001 - internal Security adapter boundary
        "PATCH",
        f"/users/{clerk_user_id}",
        json={
            "password": password,
            "sign_out_of_other_sessions": True,
        },
    )


def _verified_email_address_id(
    clerk: ClerkBackendClient,
    *,
    clerk_user_id: str,
    expected_email: str,
) -> str:
    user = clerk.get_user(clerk_user_id)
    values = user.get("email_addresses")
    if not isinstance(values, list):
        raise ClerkBackendError("Clerk user response did not contain email addresses")

    expected = expected_email.strip().lower()
    for item in values:
        if not isinstance(item, dict):
            continue
        value = item.get("email_address")
        if not isinstance(value, str) or value.strip().lower() != expected:
            continue
        verification = item.get("verification")
        if not isinstance(verification, dict) or verification.get("status") != "verified":
            raise ClerkBackendError("Registered email is not verified at Clerk")
        email_address_id = item.get("id")
        if not isinstance(email_address_id, str) or not email_address_id:
            raise ClerkBackendError("Clerk email address did not contain an ID")
        return email_address_id

    raise ClerkBackendError("Clerk user did not contain the registered email address")

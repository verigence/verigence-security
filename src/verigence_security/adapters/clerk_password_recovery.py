from __future__ import annotations

from contextlib import suppress
from uuid import uuid4

from verigence_security.adapters.clerk_backend import ClerkBackendClient, ClerkBackendError

_RECOVERY_PLACEHOLDER_PREFIX = "verigence-recovery-"
_RECOVERY_PLACEHOLDER_SUFFIX = "@example.com"


def prepare_password_recovery_email(
    clerk: ClerkBackendClient,
    *,
    clerk_user_id: str,
    expected_email: str,
) -> tuple[str, str]:
    """Prepare a backend email-code proof without violating Clerk's verified-email invariant.

    This Clerk instance requires each user to retain at least one verified email address. A password
    recovery challenge needs the registered address to become temporarily unverified so Clerk can
    issue a fresh email-code verification. Security therefore attaches a random, verified internal
    placeholder first, then temporarily marks the registered address unverified and prepares the
    email-code challenge. The placeholder is removed after recovery completes, is cancelled, or is
    self-healed by a later recovery attempt.

    Web/Mobile never see or call Clerk directly.
    """

    email_address_id = _verified_email_address_id(
        clerk,
        clerk_user_id=clerk_user_id,
        expected_email=expected_email,
    )
    _delete_recovery_placeholders(clerk, clerk_user_id=clerk_user_id)

    placeholder_email = (
        f"{_RECOVERY_PLACEHOLDER_PREFIX}{uuid4().hex}{_RECOVERY_PLACEHOLDER_SUFFIX}"
    )
    placeholder = clerk._request_object(  # noqa: SLF001 - internal Security adapter boundary
        "POST",
        "/email_addresses",
        json={
            "user_id": clerk_user_id,
            "email_address": placeholder_email,
            "primary": False,
            "verified": True,
        },
    )
    placeholder_id = placeholder.get("id")
    if not isinstance(placeholder_id, str) or not placeholder_id:
        raise ClerkBackendError("Clerk recovery placeholder did not contain an email address ID")
    verification = placeholder.get("verification")
    if not isinstance(verification, dict) or verification.get("status") != "verified":
        with suppress(Exception):
            clerk._request_json(  # noqa: SLF001 - internal Security adapter boundary
                "DELETE", f"/email_addresses/{placeholder_id}", allow_empty=True
            )
        raise ClerkBackendError("Clerk recovery placeholder was not verified")

    try:
        clerk._request_object(  # noqa: SLF001 - internal Security adapter boundary
            "PATCH",
            f"/email_addresses/{email_address_id}",
            json={"verified": False},
        )
        verification_id = clerk.prepare_email_verification(email_address_id)
    except Exception:
        with suppress(Exception):
            clerk._request_object(  # noqa: SLF001 - internal Security adapter boundary
                "PATCH",
                f"/email_addresses/{email_address_id}",
                json={"verified": True},
            )
        with suppress(Exception):
            clerk._request_json(  # noqa: SLF001 - internal Security adapter boundary
                "DELETE", f"/email_addresses/{placeholder_id}", allow_empty=True
            )
        raise
    return email_address_id, verification_id


def restore_registered_email(clerk: ClerkBackendClient, *, email_address_id: str) -> None:
    """Restore the registered email after a cancelled/expired recovery challenge."""

    restored = clerk._request_object(  # noqa: SLF001 - internal Security adapter boundary
        "PATCH",
        f"/email_addresses/{email_address_id}",
        json={"verified": True},
    )

    # Best-effort placeholder cleanup. The EmailAddress object does not expose its owning user ID,
    # so resolve the owner from the restored email value through the backend user lookup.
    email = restored.get("email_address")
    if isinstance(email, str) and email.strip():
        with suppress(Exception):
            user = clerk.find_user(email)
            if user is not None:
                _delete_recovery_placeholders(clerk, clerk_user_id=user.user_id)


def update_password(
    clerk: ClerkBackendClient,
    *,
    clerk_user_id: str,
    password: str,
) -> None:
    """Set the Clerk-owned password, revoke provider sessions, and clean recovery placeholders."""

    clerk._request_object(  # noqa: SLF001 - internal Security adapter boundary
        "PATCH",
        f"/users/{clerk_user_id}",
        json={
            "password": password,
            "sign_out_of_other_sessions": True,
        },
    )
    with suppress(Exception):
        _delete_recovery_placeholders(clerk, clerk_user_id=clerk_user_id)


def _verified_email_address_id(
    clerk: ClerkBackendClient,
    *,
    clerk_user_id: str,
    expected_email: str,
) -> str:
    user = clerk.get_user(clerk_user_id)
    expected = expected_email.strip().lower()
    item = _registered_email_item(user, expected)
    verification = item.get("verification")

    # Self-heal an abandoned earlier recovery: if our internal verified placeholder remains while
    # the registered email is unverified, restore the registered email and remove the placeholder.
    if not isinstance(verification, dict) or verification.get("status") != "verified":
        placeholders = _recovery_placeholder_ids(user)
        if not placeholders:
            raise ClerkBackendError("Registered email is not verified at Clerk")
        email_address_id = item.get("id")
        if not isinstance(email_address_id, str) or not email_address_id:
            raise ClerkBackendError("Clerk email address did not contain an ID")
        clerk._request_object(  # noqa: SLF001 - internal Security adapter boundary
            "PATCH",
            f"/email_addresses/{email_address_id}",
            json={"verified": True},
        )
        for placeholder_id in placeholders:
            clerk._request_json(  # noqa: SLF001 - internal Security adapter boundary
                "DELETE", f"/email_addresses/{placeholder_id}", allow_empty=True
            )
        user = clerk.get_user(clerk_user_id)
        item = _registered_email_item(user, expected)
        verification = item.get("verification")
        if not isinstance(verification, dict) or verification.get("status") != "verified":
            raise ClerkBackendError("Registered email could not be restored at Clerk")

    email_address_id = item.get("id")
    if not isinstance(email_address_id, str) or not email_address_id:
        raise ClerkBackendError("Clerk email address did not contain an ID")
    return email_address_id


def _registered_email_item(user: dict[str, object], expected_email: str) -> dict[str, object]:
    values = user.get("email_addresses")
    if not isinstance(values, list):
        raise ClerkBackendError("Clerk user response did not contain email addresses")

    for item in values:
        if not isinstance(item, dict):
            continue
        value = item.get("email_address")
        if isinstance(value, str) and value.strip().lower() == expected_email:
            return item
    raise ClerkBackendError("Clerk user did not contain the registered email address")


def _delete_recovery_placeholders(clerk: ClerkBackendClient, *, clerk_user_id: str) -> None:
    user = clerk.get_user(clerk_user_id)
    for placeholder_id in _recovery_placeholder_ids(user):
        clerk._request_json(  # noqa: SLF001 - internal Security adapter boundary
            "DELETE", f"/email_addresses/{placeholder_id}", allow_empty=True
        )


def _recovery_placeholder_ids(user: dict[str, object]) -> list[str]:
    values = user.get("email_addresses")
    if not isinstance(values, list):
        raise ClerkBackendError("Clerk user response did not contain email addresses")

    result: list[str] = []
    for item in values:
        if not isinstance(item, dict):
            continue
        value = item.get("email_address")
        item_id = item.get("id")
        if (
            isinstance(value, str)
            and value.startswith(_RECOVERY_PLACEHOLDER_PREFIX)
            and value.endswith(_RECOVERY_PLACEHOLDER_SUFFIX)
            and isinstance(item_id, str)
            and item_id
        ):
            result.append(item_id)
    return result

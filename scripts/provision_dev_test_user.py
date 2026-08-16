from __future__ import annotations

import os
import uuid

import httpx

from verigence_security.auth_store import PostgresAuthStore
from verigence_security.role_templates import PostgresRoleTemplateStore, RoleTemplateService
from verigence_security.settings import normalize_database_url

CLERK_API = "https://api.clerk.com/v1"


def main() -> None:
    clerk_secret = _required("CLERK_SECRET_KEY")
    raw_database_url = (
        os.environ.get("SECURITY_ROLE_DATABASE_URL")
        or os.environ.get("DATABASE_URL")
        or os.environ.get("MIGRATION_DATABASE_URL")
        or os.environ.get("DEV_DATABASE_URL")
    )
    if not raw_database_url:
        raise RuntimeError(
            "SECURITY_ROLE_DATABASE_URL, DATABASE_URL, MIGRATION_DATABASE_URL or DEV_DATABASE_URL is required"
        )
    database_url = normalize_database_url(raw_database_url)

    email = os.environ.get("SECURITY_DEV_TEST_USER_EMAIL", "verigence.security.devtest@example.com")
    password = _required("SECURITY_DEV_TEST_USER_PASSWORD")
    tenant_id = os.environ.get("SECURITY_DEV_TEST_TENANT_ID", "dev-auth-test")
    role = os.environ.get("SECURITY_DEV_TEST_ROLE", "PC").upper()
    verigence_user_id = os.environ.get("SECURITY_DEV_TEST_USER_ID") or f"dev-user-{uuid.uuid4()}"

    clerk_user = _get_or_create_clerk_user(
        clerk_secret=clerk_secret,
        email=email,
        password=password,
        external_id=verigence_user_id,
    )
    external_subject = clerk_user["id"]
    existing_external_id = clerk_user.get("external_id")
    if isinstance(existing_external_id, str) and existing_external_id:
        verigence_user_id = existing_external_id

    role_store = PostgresRoleTemplateStore(database_url)
    role_service = RoleTemplateService(role_store)
    role_service.seed_platform_defaults()
    role_service.seed_tenant(
        tenant_id=tenant_id,
        actor_sub="DEV_TEST_PROVISIONER",
        correlation_id=None,
        replace=False,
    )

    auth_store = PostgresAuthStore(database_url)
    auth_store.ensure_tenant(tenant_id)
    auth_store.upsert_user(
        user_id=verigence_user_id,
        external_subject=external_subject,
        email=email,
        active=True,
    )
    auth_store.upsert_membership(
        user_id=verigence_user_id,
        tenant_id=tenant_id,
        roles=(role,),
        direct_permissions=frozenset(),
        active=True,
    )
    auth_store.record_audit(
        event_type="dev_test_user_provisioned",
        outcome="SUCCESS",
        user_id=verigence_user_id,
        tenant_id=tenant_id,
        detail=role,
    )

    print(f"Clerk user: {external_subject}")
    print(f"Verigence user: {verigence_user_id}")
    print(f"Email: {email}")
    print(f"Tenant: {tenant_id}")
    print(f"Role: {role}")
    print("The DEV test user was intentionally retained; no delete operation was performed.")


def _get_or_create_clerk_user(
    *, clerk_secret: str, email: str, password: str, external_id: str
) -> dict:
    headers = {"Authorization": f"Bearer {clerk_secret}"}
    with httpx.Client(timeout=15.0, headers=headers) as client:
        response = client.get(f"{CLERK_API}/users", params=[("email_address", email)])
        response.raise_for_status()
        payload = response.json()
        users = payload if isinstance(payload, list) else payload.get("data", [])
        if users:
            return users[0]

        response = client.post(
            f"{CLERK_API}/users",
            json={
                "email_address": [email],
                "password": password,
                "external_id": external_id,
                "first_name": "Verigence",
                "last_name": "Dev Test",
            },
        )
        response.raise_for_status()
        return response.json()


def _required(name: str) -> str:
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


if __name__ == "__main__":
    main()

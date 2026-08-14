# Verigence Security — Initial Platform Super Admin Provisioning Design v1.4.4

**Status:** GOVERNING CLARIFICATION  
**Date:** 2026-08-14  
**Supersedes for fresh installation:** the requirement for a human-operated first Super Admin claim in v1.4.1.

## 1. Purpose

A fresh Verigence installation requires one administrator before normal provisioning can begin.

The initial administrator is an operator-selected Clerk identity. The operator supplies the immutable Clerk `user_...`
identifier during environment setup. Security then creates the corresponding global Security USER, Clerk external-identity
mapping and built-in `platform.super_admin` assignment as a one-time system provisioning operation.

This is installation/bootstrap data, not normal USER onboarding.

## 2. Frozen invariant

> **A Verigence environment is initialized with one operator-selected Clerk identity as the built-in Platform Super Admin. No second administrator, Tenant membership, Tenant role, onboarding key or manual first-user claim is required to make the platform administrable.**

The identity selector is the immutable Clerk User ID, not email, username or display name.

## 3. Provisioned Security data

The one-time provisioning transaction creates:

1. one ACTIVE `security.security_principals` USER principal;
2. one ACTIVE global `security.users` row;
3. one ACTIVE `security.external_identities` mapping with provider `CLERK` and the configured Clerk User ID;
4. one ACTIVE `security.platform_user_role_assignments` row for `platform.super_admin` with source `BOOTSTRAP`;
5. one Platform-scoped `security.admin_change_records` audit event.

No Tenant membership is created.

No Tenant role is created or assigned.

No local password credential is created.

## 4. Authority

`platform.super_admin` remains governed by `SECURITY_SUPER_ADMIN_AUTHORITY_DESIGN_v1.4.3.md`.

Therefore the single built-in role:

- owns every ACTIVE Security permission;
- automatically inherits future ACTIVE permissions;
- can initialize and administer Tenant authorization without a Tenant-specific role;
- does not require redundant assignment of other Platform or Tenant roles.

## 5. Idempotency and fail-closed behavior

Provisioning is serialized with a PostgreSQL advisory transaction lock.

If the configured Clerk identity is already mapped and already has an ACTIVE `platform.super_admin` assignment, the
operation succeeds as an idempotent no-op.

If another ACTIVE Platform Super Admin already exists and the configured Clerk identity is not already the bound initial
administrator, provisioning fails. It must not silently replace, delete or downgrade an existing administrator.

If the configured Clerk identity is already mapped to Security but does not have the required ACTIVE Super Admin role,
provisioning also fails rather than repairing privilege state implicitly.

## 6. Environment ownership

The immutable Clerk User ID is environment configuration, not a schema migration constant.

DEV, UAT and Production may select different Clerk users. The identifier must therefore not be embedded in reusable SQL
migrations.

The DEV deployment/provisioning workflow may carry the DEV Clerk User ID alongside the existing DEV Railway project,
environment and service identifiers because those values are environment-specific, nonsecret deployment configuration.

Clerk passwords, session tokens, secret keys and API secrets must never be committed to Git.

## 7. Authentication after provisioning

Provisioning does not authenticate the person and does not mint a Clerk session.

At runtime:

1. Clerk authenticates the configured person and issues a valid Clerk session JWT;
2. Security verifies that JWT and resolves `provider_subject` to the provisioned global Security USER;
3. Security confirms the Security USER/principal/external identity are ACTIVE;
4. Security resolves `platform.super_admin` and its effective permissions;
5. Security issues the Verigence Platform Admin access token.

Normal USER onboarding remains governed by v1.4.2 and is unaffected.

## 8. Fresh-installation sequence

```text
Operator selects Clerk user_...
        ↓
Security CI exact commit GREEN
        ↓
controlled environment provisioning job
        ↓
Security USER + CLERK mapping + platform.super_admin
        ↓
verify ACTIVE state + complete permission coverage
        ↓
normal Clerk authentication
        ↓
Security Platform Admin login
        ↓
Super Admin provisions remaining users / Tenants / authorization
```

## 9. Historical v1.4.1 bootstrap claim

The Clerk-authenticated bootstrap-claim implementation may remain in source for compatibility/history, but fresh
environment initialization under v1.4.4 does not depend on it.

`SECURITY_BOOTSTRAP_ENABLED` should remain false unless an explicitly approved compatibility/migration procedure requires
the historical claim path.

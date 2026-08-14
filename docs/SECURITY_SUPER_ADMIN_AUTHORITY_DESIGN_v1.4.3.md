# Verigence Security — Built-in Platform Super Admin Authority v1.4.3

**Status:** APPROVED IMPLEMENTATION CLARIFICATION  
**Date:** 2026-08-14  
**Repository:** `verigence/verigence-security`  
**Applies to:** Initial system administration, Platform Super Admin RBAC and Tenant provisioning authority.  
**Clarifies:** Global USER onboarding v1.4.2 and Clerk bootstrap v1.4.1.  

## 1. Purpose

Every new Verigence Security installation requires one initial administrator who can configure and provision the rest of the platform. That administrator is the built-in `platform.super_admin`.

The system MUST NOT require another administrator to grant additional Security or Tenant-administration roles to the Platform Super Admin before the platform can be initialized.

## 2. Built-in role invariant

`platform.super_admin` is a system-owned role.

A USER assigned this role has effective authority for **every ACTIVE Security permission** in the canonical Security permission catalogue.

The role is the single authority assignment for the initial administrator. The USER does not need redundant assignments to `platform.security_admin`, `platform.module_catalog_admin`, `platform.auditor`, or Tenant-specific administrator roles merely to obtain equivalent access.

## 3. Automatic permission inheritance

The database MUST keep the following invariant true:

```text
permissions WHERE status = ACTIVE
        ==
platform_role_permissions WHERE role_key = platform.super_admin
```

When a new Security/module permission becomes ACTIVE, it is automatically granted to `platform.super_admin`.

When a permission is retired or otherwise becomes non-ACTIVE, its Super Admin grant is removed from the effective active bundle.

This avoids hard-coded permission lists becoming stale as new modules and Security administration capabilities are added.

## 4. Tenant provisioning authority

Platform role permissions participate in the effective authorization calculation for Tenant administration.

Therefore an ACTIVE `platform.super_admin` may administer an ACTIVE Tenant without first receiving a Tenant-specific role assignment.

This is required so the first system administrator can create/configure Tenants, define roles, assign users/groups, configure locations/schedules/security policy, and perform the rest of initial provisioning.

Ordinary USERs continue to require Tenant-scoped effective authorization. This clarification does not remove Tenant RBAC for non-Platform administrators.

## 5. Bootstrap identity

Clerk remains the human authentication provider. The initial Super Admin Clerk identity is bound once through the approved bootstrap boundary.

On successful bootstrap, Security creates/resolves the Security USER and assigns exactly one built-in role:

```text
platform.super_admin
```

That single role provides full effective Security administration authority through the data-driven permission invariant above.

## 6. Acceptance requirements

Before this clarification is DONE, automated evidence must prove:

1. `platform.super_admin` owns every ACTIVE Security permission after migration.
2. A newly inserted ACTIVE permission is automatically granted to `platform.super_admin`.
3. Retiring that permission removes its Super Admin grant.
4. A USER with only `platform.super_admin` and no Tenant role assignment can authorize a Tenant administration permission.
5. Existing ordinary Tenant RBAC behavior remains intact.
6. Security CI and real Neon/PostgreSQL validation pass on the exact implementation head.
7. The exact merged `dev` commit deploys successfully to Railway DEV and passes readiness/liveness/correlation checks.

## 7. Governing invariant

> **The built-in Platform Super Admin can initialize and administer the entire Verigence Security platform without requiring another administrator to provision additional roles first.**

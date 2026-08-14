# Verigence Security — Next Steps & Context Recovery Guide

**Repository:** `verigence/verigence-security`  
**Primary integration branch:** `dev`  
**Approved baseline:** Security v1.3 + Admin Control Plane v1.4 + Clerk v1.4.1 + Global USER Onboarding v1.4.2 + Super Admin Authority v1.4.3 + Initial Super Admin Provisioning v1.4.4  
**Last updated:** 2026-08-14

## 1. Governing recovery rule

After a context reset, read in this order:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`;
2. `docs/SECURITY_INITIAL_SUPER_ADMIN_PROVISIONING_DESIGN_v1.4.4.md`;
3. `docs/SECURITY_SUPER_ADMIN_AUTHORITY_DESIGN_v1.4.3.md`;
4. `docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md`;
5. `docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md`;
6. `docs/INITIAL_SUPER_ADMIN_PROVISIONING_TEST_REPORT_v1.4.4.md`;
7. `docs/SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md`;
8. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`;
9. `docs/IMPLEMENTATION_STATUS.md`;
10. current `dev`, open Security PRs and CI/Railway state.

## 2. Invariants that must survive every reset

```text
Normal human onboarding  = Platform-global, once per person
Clerk                     = human authentication provider
Security                  = USER lifecycle + authorization authority
Tenant membership         = not a USER-access prerequisite
Platform Super Admin      = built-in role with full Security authority
Initial administrator     = operator-selected Clerk user_... provisioned as setup data
```

Do not reconstruct Tenant-scoped identity onboarding and do not require the Platform Super Admin to receive a Tenant role before provisioning the platform.

## 3. Current promoted runtime baseline

```text
DEV runtime commit: 951a7694b31c195ccbde45d13346e0eea8ae9f14
```

DEV initial Super Admin:

```text
Clerk User ID:     user_3HtNkIWp32cD9HC7KzDbZdJkr2h
Security user_id:  55d20cae-406d-4918-9a9d-bc63dfcd633c
Role:              platform.super_admin
Status:            ACTIVE
```

The provisioning workflow verified ACTIVE Security principal, global USER, CLERK external identity and Super Admin role, with zero ACTIVE Security permissions missing from `platform.super_admin`.

## 4. Promotion evidence

```text
v1.4.4 PR #51 Security CI:     31775948471 — PASS
v1.4.4 PR #51 Neon:           31775946314 — PASS
PR #51:                       MERGED
First provisioning attempt:   31776049219 — FAIL / ROLLED BACK
Hotfix PR #52 Security CI:     31776200341 — PASS
Hotfix PR #52 Neon:           31776189798 — PASS
PR #52:                       MERGED
Post-merge Security CI:       31776274556 — PASS
Successful DEV provisioning:  31776274559 — PASS
Railway DEV:                  31776274539 — PASS
readiness/liveness/correlation: PASS
```

The failed first provisioning attempt was atomic and rolled back after detecting an audit-bind type defect; the hotfix separated UUID and varchar bind parameters before successful retry.

## 5. Current workstream

**Initial Security-side Super Admin provisioning is complete.**

Next functional proof:

```text
separate UI/auth client
   ↓
normal Clerk authentication for the provisioned Super Admin
   ↓
Clerk session JWT
   ↓
Security Platform Admin token exchange
   ↓
/platform/me + full effective authority
   ↓
Increment G maker-checker
```

Do not request or commit the user's Clerk password, Clerk secret key or a long-lived session token. The authentication proof must use the normal Clerk client flow.

## 6. Global USER onboarding rule

Normal people are onboarded once as global Security USERs. The same `user_id` can receive independent authorization in multiple Tenants without another onboarding event.

Security validates the Platform onboarding key before Clerk provisioning for normal onboarding, and Security Admin controls the normal USER status transition to ACTIVE.

The exceptional initial Super Admin setup in v1.4.4 is installation data and does not weaken or bypass the normal USER onboarding lifecycle.

## 7. Promotion discipline

```text
feature/*
   ↓ Security CI + applicable Neon/PostgreSQL
  dev
   ↓ exact-commit Security CI
controlled environment setup only when explicitly marked
   ↓
immutable GHCR image -> Railway DEV
   ↓ readiness + liveness + correlation
```

The next code increment is Increment G unless the separate UI/auth work exposes a genuine Security login-boundary defect.

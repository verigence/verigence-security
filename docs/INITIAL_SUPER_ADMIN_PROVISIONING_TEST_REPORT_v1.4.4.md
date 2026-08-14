# Verigence Security — Initial Super Admin Provisioning Test Report v1.4.4

**Date:** 2026-08-14  
**Repository:** `verigence/verigence-security`  
**Environment:** DEV  
**Result:** PASS

## 1. Scope

This report covers the v1.4.4 controlled fresh-environment provisioning of the operator-selected Clerk identity as the initial Verigence Platform Super Admin.

Selected identity:

```text
Clerk User ID:     user_3HtNkIWp32cD9HC7KzDbZdJkr2h
Display name:      superadmin
Security user_id:  55d20cae-406d-4918-9a9d-bc63dfcd633c
Role:              platform.super_admin
```

## 2. Functional acceptance criteria

The implementation must:

- accept only an immutable Clerk `user_...` identifier;
- serialize first-administrator provisioning;
- create the global Security USER/principal/external identity/Super Admin assignment atomically;
- be idempotent for the same already-provisioned administrator;
- refuse to replace a different ACTIVE Super Admin;
- create no Tenant membership, Tenant role or local password credential;
- leave normal global USER onboarding unchanged;
- give `platform.super_admin` every ACTIVE Security permission;
- preserve all existing Security/Neon regressions;
- deploy through the exact-commit immutable Railway pipeline.

## 3. Feature validation

### v1.4.4 implementation

```text
PR #51 feature head:      a3cd8189222993c76c1dc8e5d8908629e8c66f1c
Security CI:              31775948471 — PASS
Neon/PostgreSQL:          31775946314 — PASS
PR #51:                   MERGED
DEV merge commit:         4e65c79b87dd3f504ff4909de408689474b6f1b0
Post-merge Security CI:   31776049176 — PASS
```

Security CI passed static/design integrity, compile, Ruff, Mypy, runtime route contract, tests, package build and dependency consistency.

The real Neon/PostgreSQL suite passed the immutable baseline digest, migrations, global USER onboarding lifecycle, Super Admin full-authority tests and retained historical Phase 5 administration tests.

## 4. Controlled provisioning negative-path evidence

First controlled DEV provisioning run:

```text
Run: 31776049219 — FAIL
```

The run exposed a PostgreSQL parameter-type ambiguity in the audit insert because one bind was used as both UUID `actor_user_id` and varchar `resource_id`.

The provisioning service wraps all writes in one transaction and rolls back on error. The failed run therefore did not leave a partial USER, external identity or Super Admin role assignment.

## 5. Hotfix validation

The audit bind was separated in PR #52.

```text
PR #52 feature head:      ae64a9fa0bd2781aeb9840b6c0e9b77aaf0f244c
Security CI:              31776200341 — PASS
Neon/PostgreSQL:          31776189798 — PASS
PR #52:                   MERGED
Promoted runtime commit:  951a7694b31c195ccbde45d13346e0eea8ae9f14
Post-merge Security CI:   31776274556 — PASS
```

## 6. Successful DEV provisioning proof

Controlled provisioning run:

```text
Run: 31776274559 — PASS
```

The workflow output confirmed:

```text
Initial Platform Super Admin created
security_user_id=55d20cae-406d-4918-9a9d-bc63dfcd633c
```

The post-write verification query then confirmed the same Security `user_id` and asserted:

```text
Security principal status       = ACTIVE
Security USER status            = ACTIVE
CLERK external identity status  = ACTIVE
platform.super_admin status     = ACTIVE
ACTIVE permissions missing from platform.super_admin = 0
```

The selected Clerk subject is therefore bound in DEV to the Security Super Admin record.

## 7. Railway deployment proof

```text
Railway DEV run: 31776274539 — PASS
Runtime commit:  951a7694b31c195ccbde45d13346e0eea8ae9f14
```

The deployment pipeline passed:

- exact validated DEV commit checkout;
- immutable image build/publish;
- immutable image validation;
- Railway credential/project-scope verification;
- exact image attachment;
- Railway deployment success;
- public domain resolution;
- `/health/ready` verification;
- `/health/live` verification;
- `X-Correlation-ID` verification.

## 8. Result

**v1.4.4 Security-side initial Super Admin provisioning is PASS and complete in DEV.**

The remaining runtime identity proof is ordinary Clerk authentication from the separate UI/auth client followed by the existing Clerk JWT -> Security Platform Admin token flow. That is not a provisioning defect and must not be replaced with stored passwords or committed Clerk session tokens.

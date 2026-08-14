# Verigence Security — Implementation Progress Tracker v1.4.1

**Status:** HISTORICAL / SUPERSEDED FOR CURRENT EXECUTION  
**Original scope date:** 2026-08-13  
**Superseded for current execution:** 2026-08-14

The current canonical tracker is:

```text
docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md
```

The current governing human-onboarding/Tenant-authorization amendment is:

```text
docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md
```

This file now serves only as a historical checkpoint for the implementation state reached under v1.4/v1.4.1.
Do not use its former Tenant-scoped onboarding or Tenant-membership execution assumptions after v1.4.2.

## Historical status recorded by v1.4.1

Before the v1.4.2 correction, the repository had completed/promoted the practical Admin Control Plane increments
through historical Increment F and implemented the Clerk-backed Platform identity boundary.

Historical sequence:

```text
Increment A  Admin Control Plane persistence foundation          DONE
Increment B  Platform Super Admin / Tenant creation              DONE
Increment C  Module catalogue / DI mapping                       DONE
Increment D  Groups + effective RBAC                             DONE
Increment E  Tenant Role Admin APIs                              DONE
Increment F  Tenant invitation/self-onboarding implementation    DONE HISTORICALLY
Clerk cutover Platform boundary                                  IMPLEMENTED/DEPLOYED
Increment G  Privileged maker-checker                            PAUSED
```

### Important v1.4.2 reinterpretation

Increment F remains evidence that the earlier Tenant onboarding workflow was implemented and tested. Its human
identity model is **not** active architecture after v1.4.2.

v1.4.2 supersedes the following former assumptions:

- human onboarding tied to a Tenant;
- Tenant-specific self-onboarding token/key as the normal identity entry point;
- re-onboarding a human for another Tenant;
- Tenant membership as a mandatory USER runtime authorization/access-session prerequisite.

Historical tables and records are retained until a separate destructive migration/retention decision is approved.

## Clerk v1.4.1 historical promotion evidence

The Clerk Platform boundary was merged through PR #47 and promoted to DEV:

```text
DEV commit:
0464adf353bf23cd7acf85db4368c3d456a06b34

Security CI:
31728164273 — PASS

Railway DEV:
31728164126 — PASS

Railway deployment:
79f026f5-0bbf-4601-856b-a9a7f4e678c6

Immutable image:
ghcr.io/verigence/verigence-security@
sha256:b250d25a7f76116065d22654fb271a8a647a44c4c92fd36c618ef54d16f352f8
```

Detailed Clerk validation evidence is retained in:

```text
docs/CLERK_IDENTITY_INTEGRATION_TEST_REPORT_v1.4.1.md
```

The Clerk boundary that remains valid after v1.4.2 is:

> Clerk owns human authentication. Security owns Verigence USER lifecycle and authorization.

## Current recovery instruction

After a context reset, do not resume from the former v1.4.1 execution pointer. Read:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`;
2. `docs/SECURITY_GLOBAL_USER_ONBOARDING_DESIGN_v1.4.2.md`;
3. `docs/IMPLEMENTATION_PROGRESS_TRACKER_v1.4.2.md`;
4. this historical tracker only when prior evidence is needed.

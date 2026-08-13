# Verigence Security — Implementation Progress Tracker v1.4.1

**Status:** CURRENT CANONICAL EXECUTION TRACKER  
**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Current promoted DEV commit at tracker creation:** `92544b424d9820f8822224b0002f5af58a632185`  
**Date:** 2026-08-13

This tracker supersedes the execution pointer in the older `IMPLEMENTATION_PROGRESS_TRACKER.md` where that file is stale. Historical evidence in the older tracker remains useful; this file is the current execution authority until the older tracker is reconciled.

Implementation authorities:

- `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`;
- `docs/SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md`;
- `docs/SECURITY_CONTROL_REGISTRY_DESIGN_v1.4.md`;
- `docs/SECURITY_SELF_ONBOARDING_DESIGN_v1.4.md`;
- Security v1.3 normative artifacts for unchanged legacy/runtime scope.

---

## 1. Current executive status

| Area | Status | Current position |
|---|---|---|
| Phase 1 CI quality gate | DONE | Design/static, compile, Ruff, Mypy, tests, build, dependency checks enforced |
| Phase 2 Neon DEV | DONE | Approved schema and real PostgreSQL validation |
| Phase 3 Railway DEV | DONE | Immutable exact-commit deployment + readiness/liveness/correlation |
| Phase 4 USER device/session lifecycle | PARTIAL / CONTRACT BOUNDARY | Internal lifecycle substantially complete; old public v1.3 lifecycle contract/idempotency blockers remain |
| Admin Control Plane Increment A | DONE | v1.4 persistence/catalogues/control definitions |
| Increment B | DONE / AUTH TRANSITION REQUIRED | Local Platform bootstrap + direct Tenant Admin APIs deployed; local password auth is now transitional debt superseded by Clerk v1.4.1 target design |
| Increment C | DONE | Module Catalogue API + DI 28-permission/5-template synchronization |
| Increment D | DONE | Groups + effective RBAC + Group-aware runtime permissions |
| Increment E | DONE | Tenant Role Admin APIs + template materialization/provenance/upgrades |
| Increment F | DONE | Human invitation/acceptance + self-onboarding + Platform first Owner + token rotation/disable; privileged assignments remain pending |
| Clerk live integration | NOW | Replace local human auth boundary with Clerk-backed identity, including first Super Admin bootstrap claim |
| Increment G maker-checker | PAUSED | Resume only after Clerk cutover/live identity E2E is green |
| Increment H Control Registry/runtime Admin APIs | PENDING | After G unless sequencing is explicitly changed |
| Increment I DI authorization alignment | PENDING | Recorded corrections remain |
| Increment J Security -> DI deployed E2E | PENDING | Final Admin Control Plane integration proof |
| SYSTEM/SERVICE_INTEGRATION | PENDING | Separate machine-identity phase |

---

## 2. Evidence — Increment A

**DONE — PR #39**

Promoted/deployed evidence retained from prior tracker:

```text
Final-head Neon:      31691819076 — PASS
PR Security CI:       31691822076 — PASS
Promoted DEV commit:  b1c4d60267ccffae4a6a64a3ec87099c13e193e7
Post-merge CI:        31691980302 — PASS
Railway DEV:          31691980334 — PASS
```

---

## 3. Evidence — Increment B

**DONE — PR #41; authentication model now transitional**

```text
Final feature head:   6bff9941417d490856f80d18aa8a2d20455e2ffd
Final-head Neon:      31694765879 — PASS
PR Security CI:       31694771302 — PASS
Promoted DEV commit:  44a3a868d82d03cdb4bca9250a6ce14769d9db8a
Post-merge CI:        31694931046 — PASS
Railway DEV:          31694931027 — PASS
```

Implemented direct Platform Tenant administration remains valid.

The local Platform username/password bootstrap/login is **not the target production identity design anymore**. It must be replaced/disabled in the normal runtime path during the Clerk integration increment according to `SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md`.

Historical local credential rows/code are migration debt, not a reason to delete data without an approved migration/retention decision.

---

## 4. Evidence — Increment C

**DONE — PR #43**

Implemented:

- module catalogue repository/service/API;
- module namespace ownership;
- permission lifecycle;
- template lifecycle/provenance safety;
- DI exact current catalogue fixture: 28 permissions and five approved USER templates;
- active-reference retirement protection.

Evidence:

```text
Final feature head:   ada7fbe7a9fcb484dcafef78eba297bbc7025963
Real Neon:            31697061424 — PASS
PR merge commit:      5ae78f90759c565e359e407cd032a83d7c18fe57
```

Previously recorded promotion evidence:

```text
PR Security CI:       31699750982 — PASS
Railway DEV:          31699886154 — PASS
```

---

## 5. Evidence — Increments D/E

**DONE — PR #44**

### Increment D

- Group CRUD;
- Group membership;
- Group Role assignment;
- direct + Group role union;
- Group-aware effective permissions in the normal USER access-token path;
- authorization-version bumping for effective-RBAC changes.

### Increment E

- Tenant Role CRUD;
- registered permission assignment/removal;
- direct USER Role assignment;
- module template materialization/provenance;
- explicit template upgrade;
- reserved-role protection;
- structured Admin audit.

Evidence:

```text
Final PR head:        e84101cd0a7e838a4c7f9f0cc9ce702dbabb3fb3
Final-head Neon:      31706796721 — PASS
PR Security CI:       31706801264 — PASS
Promoted DEV commit:  f1fb7c9dab8a11773b85d9fbc09b7c14ec705ea4
Post-merge CI:        31706985353 — PASS
Railway DEV:          31706985322 — PASS
```

---

## 6. Evidence — Increment F

**DONE — PR #45**

Final merged scope includes:

- Tenant invitation create/list/cancel;
- authenticated invitation acceptance;
- hash-only one-time invitation acceptance value;
- first Tenant Owner invitation by Platform Super Admin;
- self-onboarding submission using authenticated external identity + Tenant onboarding value;
- Admin list/get/approve/reject for self-onboarding requests;
- self-onboarding value rotate/disable;
- wrong/old/disabled self-onboarding values rejected;
- duplicate self-onboarding returns the existing open request;
- non-privileged onboarding can activate membership after approved flow;
- privileged invitation acceptance remains PENDING and creates privileged-access request(s);
- privileged self-onboarding approval is blocked pending maker-checker;
- Security external identity binding and Tenant-safe access revalidation;
- Admin audit.

Evidence:

```text
Final feature head:   0702aee1f7bc19573385404f0b8470d13de2a446
Final-head Neon:      31713653137 — PASS
PR Security CI:       31713657218 — PASS
Promoted DEV commit:  92544b424d9820f8822224b0002f5af58a632185
Post-merge CI:        31714096355 — PASS
Railway DEV:          31714096369 — PASS
```

Railway run `31714096369` passed:

- exact validated commit gate;
- immutable image build/publish;
- exact Railway service/image attachment;
- deployment SUCCESS;
- `/health/ready`;
- `/health/live`;
- correlation-ID verification.

---

## 7. Identity architecture correction — Clerk

**STATUS: APPROVED DESIGN / IMPLEMENTATION NOW**

The local Platform password system from Increment B is transitional implementation debt.

Target boundary:

```text
Clerk = human authentication
Security = Verigence authorization/governance
```

Clerk owns human sign-in/password/MFA/recovery/session identity.

Security owns:

- Security USER and Clerk-subject mapping;
- Platform/Tenant roles;
- memberships;
- Groups;
- permissions;
- onboarding approval;
- maker-checker;
- device/geo/schedule/network policy;
- Verigence access JWTs.

Clerk Organizations/RBAC is not used as the authorization authority.

Detailed authority: `docs/SECURITY_CLERK_IDENTITY_BOUNDARY_DESIGN_v1.4.1.md`.

---

## 8. First Platform Super Admin — approved target sequence

```text
1. Operator creates intended first Super Admin as a normal Clerk user.
2. Clerk owns all credentials/MFA/recovery.
3. Operator records immutable Clerk user ID.
4. Railway/Security receives bootstrap-enabled configuration + Clerk user ID.
5. Intended Super Admin signs in through Clerk.
6. Client calls one-time Security bootstrap claim with Clerk session JWT.
7. Security verifies Clerk token and requires JWT subject == configured bootstrap Clerk user ID.
8. Security requires zero ACTIVE Platform Super Admin assignments.
9. Security transactionally creates/resolves Security USER + CLERK external identity + platform.super_admin assignment + audit.
10. Bootstrap permanently closes while an ACTIVE Super Admin exists.
11. Operator removes/disables bootstrap configuration.
12. Future Platform Admins use Clerk authentication + normal Security Platform-role administration.
```

No Security password is required in the target model.

---

## 9. Current execution pointer

**NOW: Clerk live integration.**

Implement only the frozen identity boundary:

1. Clerk deployment/configuration contract;
2. Clerk-backed one-time Platform Super Admin bootstrap claim;
3. Clerk-backed Platform Admin authentication/authorization;
4. disable normal local Platform password login after cutover;
5. live Clerk identity in invitation acceptance;
6. live Clerk identity in self-onboarding;
7. Security USER/external identity uniqueness;
8. real Neon tests;
9. Security CI;
10. Railway DEV deployment;
11. deployed Clerk -> Security E2E;
12. evidence/tracker update.

**PAUSED:** Increment G maker-checker until Clerk integration is green.

**NEXT AFTER CLERK:** Increment G privileged maker-checker.

---

## 10. Known blockers/deferred items unchanged

- persistent cross-replica idempotency storage;
- complete SEC-032 Tenant activation prerequisite catalogue;
- device `BLOCKED` versus `REVOKED` business semantics;
- old unavailable v1.3 lifecycle OpenAPI for legacy lifecycle routes;
- exact Clerk webhook-to-Security lifecycle mutation semantics;
- exact recent-MFA freshness threshold for sensitive Admin mutations;
- machine authentication for SYSTEM/SERVICE_INTEGRATION actors.

Do not implement these by assumption.

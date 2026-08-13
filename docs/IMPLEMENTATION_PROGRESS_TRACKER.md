# Verigence Security — Implementation Progress Tracker

**Purpose:** Single operational recovery view of completed, partial, pending and blocked Security implementation work.  
**Repository:** `verigence/verigence-security`  
**Integration branch:** `dev`  
**Approved baseline:** Security v1.3 + Admin Control Plane v1.4 extensions  
**Current promoted DEV commit:** `f1fb7c9dab8a11773b85d9fbc09b7c14ec705ea4`  
**Last updated:** 2026-08-13

This tracker is operational only. Approved design artifacts remain authoritative.

## 1. Execution rules

- Do not invent APIs, permissions, errors, statuses, database objects, thresholds or Security semantics.
- Do not modify normative v1.3 artifacts to make implementation easier.
- v1.4 Admin implementation must follow `SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`, `SECURITY_CONTROL_REGISTRY_DESIGN_v1.4.md` and `SECURITY_SELF_ONBOARDING_DESIGN_v1.4.md`.
- A capability is `DONE` only after applicable Neon/CI/PR/Railway evidence exists.
- Runtime authorization uses permissions, not role names.
- Business modules publish permissions/templates; Security owns authoritative Tenant roles, Groups, assignments and effective permissions.

Status values: `DONE`, `PARTIAL`, `PENDING`, `BLOCKED`, `NOT STARTED`.

## 2. Executive status

| Area | Status | Evidence / current position |
|---|---|---|
| Phase 1 — CI quality gate | DONE | GitHub design/static/compile/Ruff/Mypy/tests/package/dependency gates established |
| Phase 2 — Neon DEV | DONE | Approved v1.3 Security schema + real PostgreSQL validation |
| Phase 3 — Railway DEV | DONE | Immutable build/deploy + readiness/liveness/correlation + deployed USER E2E |
| Phase 4 — USER device/session lifecycle | SUBSTANTIALLY DONE | Internal device/session/refresh/revoke enforcement deployed; legacy public-contract gaps remain tracked |
| Phase 5 — internal Security administration foundation | DONE / DEPLOYED | Policy, retention, location, schedule, membership, RBAC persistence, USER onboarding persistence and fail-closed readiness foundation |
| Admin Control Plane v1.4 design | DONE / VERSIONED | Roles, Groups, module catalogue, onboarding, approvals, Admin APIs and audit model frozen |
| Admin Increment A — schema/control-plane persistence | DONE / DEPLOYED | v1.4 migration + standard Admin catalogue/control-plane persistence |
| Admin Increment B — Platform Super Admin + direct Tenant admin | DONE / DEPLOYED | PR #41; `dev@44a3a868...` |
| Admin Increment C — Module Catalogue + DI synchronization | DONE / DEPLOYED | PR #43; `dev@5ae78f90...` |
| Admin Increment D — Groups + effective RBAC | DONE / DEPLOYED | PR #44; `dev@f1fb7c9d...` |
| Admin Increment E — Tenant Role Admin APIs | DONE / DEPLOYED | PR #44; `dev@f1fb7c9d...` |
| Admin Increment F — team/self-onboarding | NOW | Invitation + human acceptance + token-gated self-registration + Admin approval |
| Clerk live integration | NEXT AFTER F | Bind live Clerk identity/onboarding to stable USER/Tenant/RBAC/onboarding model |
| Admin Increment G — maker-checker | PENDING | Privileged role/access approval |
| Admin Increment H — remaining Admin/control APIs | PENDING | Control Registry runtime/API + policy/location/schedule/device API completion |
| Admin Increment I — DI authorization alignment | PENDING | Actor-type/Tenant-route/permission coverage corrections |
| Admin Increment J — deployed Security → DI E2E | PENDING | Cross-module deployed proof |
| Tenant activation mutation | BLOCKED | Complete SEC-032 prerequisite catalogue still unfrozen |
| Persistent cross-replica idempotency | BLOCKED | Approved persistence model required |
| UAT/Production | NOT STARTED | Production approval not yet reached |

## 3. Key promoted evidence

### Phase 3

```text
Runtime/health validation:       31668584825 — PASS
Deployed USER E2E:               31668795264 — PASS
```

### Phase 4

```text
Device/session persistence:      31671140316 — PASS
Device-limit concurrency:        31671542390 — PASS
Refresh/revoke lifecycle:        31672322586 — PASS
```

### Admin Increment B

```text
Final feature head:              6bff994... / promoted through PR #41
Promoted DEV commit:             44a3a868d82d03cdb4bca9250a6ce14769d9db8a
Real Neon:                       PASS
Security CI:                     PASS
Railway DEV:                     PASS
```

Detailed evidence: `ADMIN_CONTROL_PLANE_INCREMENT_B_VALIDATION.md`.

### Admin Increment C — Module Catalogue + DI synchronization

Implemented:

- Platform Module Catalogue list/detail/update APIs;
- module namespace ownership;
- canonical permission validation;
- explicit `ACTIVE`, `DEPRECATED`, `RETIRED` lifecycle;
- omission does not imply deletion/deprecation;
- permission retirement blocked when an effective Tenant role depends on it;
- versioned module role templates;
- template changes never silently mutate existing Tenant roles;
- structured Admin audit;
- initial DI catalogue sync grounded in current DI `dev`: 28 `di.*` permissions and five approved USER-facing templates.

```text
Final feature head:              ada7fbe7a9fcb484dcafef78eba297bbc7025963
Real Neon:                       31697061424 — PASS
PR:                              #43
PR Security CI:                  31699750982 — PASS
Promoted DEV commit:             5ae78f90759c565e359e407cd032a83d7c18fe57
Post-merge Security CI:          31699886106 — PASS
Railway DEV:                     31699886154 — PASS
```

### Admin Increment D — Groups + effective RBAC

Implemented:

- Tenant Group create/list/get/update APIs;
- Group member add/remove;
- Group role assign/remove;
- no nested Groups;
- Group inheritance affects roles/permissions only, never location/schedule assignment;
- effective roles = direct ACTIVE roles + ACTIVE Group-inherited roles;
- effective permissions = union of ACTIVE permissions on effective roles;
- production USER access-session issuance is Group-aware;
- effective RBAC mutations increment `tenant_memberships.authorization_version` transactionally;
- Tenant Admin mutations resolve current Security identity/membership/effective permissions from PostgreSQL;
- structured Tenant Admin audit evidence.

### Admin Increment E — Tenant Role Admin APIs

Implemented:

- Role list/create/get/update;
- role permission add/remove;
- direct USER role assign/remove;
- permission and module-template discovery;
- role creation with explicit permissions + `templateKeys`;
- module-template permissions materialized into Tenant roles;
- applied catalogue-version provenance stored in `role_template_bindings`;
- template changes do not silently alter existing Tenant roles;
- explicit additive template upgrade with affected-user authorization-version bump;
- reserved `platform.*` and standard `tenant.*` keys protected from Tenant business-role creation.

Combined D/E evidence:

```text
Final feature head:              e84101cd0a7e838a4c7f9f0cc9ce702dbabb3fb3
Real Neon:                       31706796721 — PASS
PR:                              #44
PR Security CI:                  31706801264 — PASS
Promoted DEV commit:             f1fb7c9dab8a11773b85d9fbc09b7c14ec705ea4
Post-merge Security CI:          31706985353 — PASS
Railway DEV:                     31706985322 — PASS
```

Detailed evidence for C/D/E: `ADMIN_CONTROL_PLANE_INCREMENT_CDE_VALIDATION.md`.

## 4. Current authorization model

```text
MODULE
  -> canonical permissions
  -> optional versioned role templates

TENANT
  -> Security-owned Tenant roles
       -> explicit registered permissions
       -> optional materialized module-template provenance
  -> Groups
       -> USER memberships
       -> Tenant Role assignments
  -> direct USER Role assignments
  -> explicit USER location/schedule assignments

Effective USER Roles
  = Direct ACTIVE Tenant Roles
  + ACTIVE Tenant Roles inherited through ACTIVE Groups

Effective USER Permissions
  = union of ACTIVE permissions on Effective USER Roles
```

Modules authorize requests by permission key. Role names are not the runtime contract.

## 5. Admin roadmap from current point

```text
Increment A  v1.4 persistence foundation                         DONE
Increment B  Platform Super Admin + direct Tenant creation       DONE
Increment C  Module Catalogue API + DI synchronization           DONE
Increment D  Groups + effective RBAC                             DONE
Increment E  Tenant Role Admin APIs                              DONE
Increment F  Team-member + self-onboarding                       NOW
Clerk         Live identity/onboarding integration                NEXT AFTER F
Increment G  Privileged maker-checker                            PENDING
Increment H  Control Registry + remaining Admin APIs             PENDING
Increment I  DI authorization alignment                          PENDING
Increment J  Deployed Security -> DI E2E                         PENDING
```

### Increment F frozen behavior

Invitation and self-onboarding coexist.

Self-onboarding:

```text
Authenticated USER identity
  + valid Tenant onboarding token
  + self-onboarding enabled
        ↓
PENDING self-onboarding request / PENDING Tenant membership
        ↓
Tenant Admin reviews
        ↓
APPROVE or REJECT
        ↓
Only approval may activate Tenant membership and approved assignments
```

The Tenant onboarding token gates request submission; it does not grant access and is never a USER credential.

The user may not self-select roles, Groups, permissions or locations.

### Clerk placement

Clerk live integration happens immediately after Increment F, because F freezes the USER/onboarding/membership/RBAC states Clerk identities must bind to.

Clerk work will include:

- real Clerk DEV/pre-production configuration;
- live Clerk JWT verification through the existing adapter;
- Clerk subject → Security USER mapping;
- invitation/onboarding integration where applicable;
- self-onboarding identity binding;
- parity tests against deterministic DEV identity behavior;
- failure/unknown-user handling.

## 6. Open blockers / clarifications

| ID | Point | Status | Rule |
|---|---|---|---|
| OPEN-001 | Persistent idempotency store | BLOCKED | Do not claim cross-replica replay until persistence design is approved |
| OPEN-002 | Invalid correlation-ID rejection response | PARTIAL | Never propagate invalid caller value |
| OPEN-003 | Admin permission catalogue | RESOLVED BY v1.4 | Use frozen `security.*` catalogue |
| OPEN-004 | Cross-module session-idle semantics | BLOCKED | Do not invent heartbeat/introspection |
| OPEN-005 | Generic malformed-request normalization | BLOCKED | Do not invent a Security error code |
| OPEN-006 | Legacy v1.3 OpenAPI unavailable | PARTIAL BLOCKER | Blocks unresolved old lifecycle route shapes, not v1.4 Admin Control Plane |
| OPEN-007 | Refresh approved-location movement | RESOLVED | Use approved clarification CLAR-004-001 |
| OPEN-008 | Free-form `security_events.event_type` taxonomy | OPEN | Admin changes use structured `admin_change_records` |
| OPEN-009 | Device `BLOCKED` vs `REVOKED` business distinction | OPEN | Both are non-ACTIVE until mutation semantics are frozen |
| OPEN-010 | Complete SEC-032 activation prerequisite catalogue | BLOCKED | Readiness remains fail-closed; activation mutation disabled |
| OPEN-011 | RBAC authorization-version mutation | RESOLVED BY v1.4 | Increment transactionally when effective RBAC changes |

## 7. Current execution pointer

**NOW:** Admin Control Plane v1.4 **Increment F — team-member onboarding and token-gated self-onboarding**.

**NEXT:** **Clerk live integration immediately after F**, then Increment G maker-checker.

Do not move Phase 6 machine actors ahead of the Admin Control Plane primary workstream.

## 8. Context-reset recovery

Read in this order:

1. `docs/CONTEXT_AND_DESIGN_GROUNDING_POLICY.md`
2. `docs/SECURITY_ADMIN_CONTROL_PLANE_DESIGN_v1.4.md`
3. `docs/SECURITY_CONTROL_REGISTRY_DESIGN_v1.4.md`
4. `docs/SECURITY_SELF_ONBOARDING_DESIGN_v1.4.md`
5. `docs/IMPLEMENTATION_PROGRESS_TRACKER.md`
6. `docs/ADMIN_CONTROL_PLANE_INCREMENT_A_VALIDATION.md`
7. `docs/ADMIN_CONTROL_PLANE_INCREMENT_B_VALIDATION.md`
8. `docs/ADMIN_CONTROL_PLANE_INCREMENT_CDE_VALIDATION.md`
9. `docs/IMPLEMENTATION_STATUS.md`
10. `docs/NEXT_STEPS_AND_CONTEXT_RECOVERY.md`
11. `docs/APPROVED_SOURCE_REFERENCE.md`
12. applicable v1.3 decision/correlation/lifecycle artifacts
13. current Security `dev`, current DI `dev`, open PRs and current CI/Railway runs

Do not reconstruct Security behavior from chat history when repository recovery sources exist.

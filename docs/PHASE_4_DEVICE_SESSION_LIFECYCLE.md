# Phase 4 — USER Device and Session Lifecycle

**Status:** PARTIAL — increments 1–4 validated internally  
**Approved baseline:** Security Solution v1.3 + recorded Phase 4 clarifications  
**Latest Neon validation run:** `31673792244`

## Objective

Complete the approved USER device and access-session lifecycle without weakening the v1.3 access gates or inventing API, permission, error, persistence or event contracts that are not frozen by the approved design or explicitly recorded clarification.

## Approved lifecycle anchors

Phase 4 implementation is grounded in the existing v1.3 decisions/schema and `docs/PHASE_4_APPROVED_CLARIFICATIONS.md`:

- USER access requires an ACTIVE registered device.
- Unknown devices enter a PENDING enrollment/approval path before normal access.
- the canonical device identifier is the Verigence device UUID; MAC address is optional metadata rather than identity.
- the Tenant Security Policy controls `max_active_devices_per_user`.
- USER access-session refresh requires a new geo sample; missing geo returns normative `GEO_REQUIRED`.
- refresh geo must resolve to a currently ACTIVE/effective assigned Tenant location.
- if refresh geo resolves to a different approved/assigned location, the same ACTIVE session may move to that location only after full policy re-evaluation.
- if refresh geo is outside all approved/assigned locations, refresh is denied using existing location errors.
- at most one ACTIVE USER access session may exist for the same Tenant, user and device.
- revoking an access session blocks refresh/new issuance while an already-issued Phase-1 JWT remains valid until its existing `exp`.
- Tenant `OFFBOARDING` prevents new USER session creation/refresh and revokes ACTIVE sessions.
- persistent cross-replica `Idempotency-Key` replay remains blocked until an approved persistence model exists.

## Increment 1 — persistence primitives

`src/verigence_security/repositories/device_session_repository.py` adds PostgreSQL primitives for PENDING enrollment persistence, device approval transitions, active-device counting/serialization and scoped USER session locking/revocation.

Validation run `31670840296`: **SUCCESS — 6/6 PostgreSQL tests passed**.

## Increment 2 — active-device-limit enforcement

`src/verigence_security/services/device_lifecycle.py` enforces the ACTIVE Tenant Security Policy's `max_active_devices_per_user` after a Tenant/user serialization lock. Concurrent approvals cannot both consume the same remaining capacity.

Validation run `31671542390`: **SUCCESS — 7/7 PostgreSQL tests passed**.

## Increment 3 — deterministic USER refresh/revoke boundaries

`src/verigence_security/services/session_lifecycle.py` enforces mandatory refresh geo (`GEO_REQUIRED`) and transactional scoped USER session `ACTIVE → REVOKED` behavior. Revocation does not attempt to invalidate an already-issued JWT before its existing `exp`.

Validation run `31672322586`: **SUCCESS — 8/8 Phase 4 PostgreSQL integration tests passed**.

## Increment 4 — USER refresh policy re-evaluation and approved location-context move

The previously open refresh-location transition is resolved by `CLAR-004-001` in `docs/PHASE_4_APPROVED_CLARIFICATIONS.md`.

`src/verigence_security/services/session_refresh_service.py` now performs the internal USER refresh lifecycle:

1. requires fresh geo;
2. evaluates network risk before entering the database row-lock window;
3. requires an ACTIVE Tenant and effective USER membership;
4. locks the scoped ACTIVE USER access session;
5. rejects a revoked/non-ACTIVE session and an already-expired session;
6. requires the session's device to remain ACTIVE;
7. validates geo freshness, accuracy and integrity;
8. matches geo only against currently ACTIVE/effective assigned Tenant locations;
9. evaluates the matched location's ACTIVE schedule, time window and override;
10. re-evaluates Tenant network policy and effective RBAC;
11. recalculates expiry as the minimum of access-token TTL, geo revalidation interval, the original session maximum-duration end and the newly matched schedule authorization end;
12. updates the same ACTIVE session's location/source-IP/network/authz/geo timestamps;
13. records successful access-context evidence;
14. issues a refreshed Security JWT whose `location_id` is the location that passed the current refresh evaluation;
15. commits only after token signing succeeds.

Behavior now covered explicitly:

- same approved location → refresh the existing session in place;
- different approved/assigned location → move the same session to that approved location after full re-evaluation;
- geo outside all approved/assigned locations → deny; no session context update, evidence write or token issuance;
- the original session maximum-duration cap is preserved and cannot be extended by refreshing from another approved location.

`src/verigence_security/repositories/session_refresh_repository.py` provides the scoped `FOR UPDATE` session lock and ACTIVE-session context update.

Unit tests cover same-location refresh, approved different-location movement and unapproved-location denial.

Real Neon PostgreSQL validation initially exposed only a test-representation mismatch (`inet` rendered a host as `/32`); production logic was unchanged. The corrected test uses PostgreSQL `host(inet)` and the complete Phase 4 suite passed.

Validation run `31673792244`: **SUCCESS — 9/9 Phase 4 PostgreSQL integration tests passed**.

## Validated behavior to date

1. PENDING enrollment persistence creates only PENDING device/enrollment state.
2. active-device counting ignores PENDING/BLOCKED/REVOKED devices.
3. concurrent device approvals cannot exceed `max_active_devices_per_user`.
4. PENDING device approval updates the device and enrollment request together.
5. USER session revocation is scoped and transactional.
6. PostgreSQL enforces one ACTIVE USER session for the same Tenant/user/device.
7. missing USER refresh geo is rejected with normative `GEO_REQUIRED`.
8. refresh to the same approved location is supported.
9. refresh to another approved/assigned location moves the same ACTIVE session only after full policy re-evaluation.
10. refresh geo outside every approved/assigned location is rejected without mutating the session context.
11. refreshed token/evidence/session context use the newly approved matched location.
12. refresh retains the original session maximum-duration cap.

The PostgreSQL tests use the real Neon DEV database and clean temporary fixtures after execution.

## Intentionally not yet implemented

- public device-enrollment request/response models and route wiring;
- public/admin device approval/block/revoke route wiring;
- USER access-session refresh/revoke public route wiring;
- denial-event persistence for lifecycle denials;
- deployed Railway Phase 4 lifecycle E2E through the missing public contracts;
- persistent cross-replica idempotency replay.

## Current grounding constraint

The checksum-referenced authoritative `SECURITY_OPENAPI_v1.3.yaml` was never committed to this repository; repository history shows no delete/change commit for it. Its exact endpoint request/response/security shapes remain unavailable in the active sources.

Therefore the internal lifecycle can continue from approved decisions/clarifications, but public lifecycle route shapes must not be invented until the checksum-matching OpenAPI is recovered or a replacement contract is explicitly approved and versioned.

## Next safe increment

Promote Increment 4 through standard Security CI and Railway DEV. After promotion, continue deterministic lifecycle work that does not require missing public request/response shapes, especially denial/security-event persistence where the existing schema and catalogue make the behavior deterministic.

Public route wiring remains gated on the authoritative OpenAPI artifact.

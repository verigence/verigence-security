# Phase 4 — USER Device and Session Lifecycle

**Status:** PARTIAL — increments 1–3 validated  
**Approved baseline:** Security Solution v1.3  
**Latest Neon validation run:** `31672322586`

## Objective

Complete the approved USER device and access-session lifecycle without weakening the v1.3 access gates or inventing API, permission, error, persistence or event contracts that are not frozen by the approved design.

## Approved lifecycle anchors

Phase 4 implementation is grounded in the existing v1.3 decisions and schema:

- USER access requires an ACTIVE registered device.
- Unknown devices enter a PENDING enrollment/approval path before normal access.
- the canonical device identifier is the Verigence device UUID; MAC address is optional metadata rather than identity.
- the Tenant Security Policy controls `max_active_devices_per_user`.
- USER access-session refresh requires a new geo sample; missing geo returns normative `GEO_REQUIRED`.
- at most one ACTIVE USER access session may exist for the same Tenant, user and device.
- equivalent concurrent session creation is serialized on the registered-device row.
- revoking an access session immediately blocks refresh/new issuance for that session context, while an already-issued Phase-1 JWT remains cryptographically valid until its existing `exp`.
- Tenant `OFFBOARDING` prevents new USER session creation/refresh and revokes ACTIVE sessions.
- persistent cross-replica `Idempotency-Key` replay remains blocked until an approved persistence model exists.

## Increment 1 — persistence primitives

`src/verigence_security/repositories/device_session_repository.py` adds PostgreSQL primitives for:

- creating a registered device in `PENDING` state together with a `PENDING` device-enrollment request;
- locking the Tenant membership row to serialize active-device-limit decisions for the same Tenant/user;
- counting only `ACTIVE` registered devices;
- locking a PENDING device row for approval work;
- atomically transitioning the matching PENDING device and PENDING enrollment request to `ACTIVE` / `APPROVED` inside the caller transaction;
- locking a USER access-session row by access-session/Tenant/user scope;
- transitioning an ACTIVE USER access session to `REVOKED` without changing the lifetime of an already-issued JWT.

Validation run `31670840296`: **SUCCESS — 6/6 PostgreSQL tests passed**.

## Increment 2 — active-device-limit enforcement

`src/verigence_security/services/device_lifecycle.py` adds `DeviceApprovalService`, which:

1. acquires the Tenant/user membership row lock;
2. requires the membership to be ACTIVE using existing normative membership errors;
3. loads the ACTIVE Tenant Security Policy;
4. locks the target PENDING device;
5. counts ACTIVE devices only after acquiring the serialization lock;
6. raises normative `DEVICE_LIMIT_REACHED` when the configured limit is exhausted;
7. otherwise atomically activates the PENDING device and approves the matching enrollment request.

This prevents two simultaneous approvals for the same Tenant/user from both observing spare capacity and exceeding the configured device limit.

Validation run `31671542390`: **SUCCESS — 7/7 PostgreSQL tests passed**.

The concurrency test created two simultaneous approval attempts against a Tenant policy of one active device. Exactly one approval succeeded; the other returned `DEVICE_LIMIT_REACHED`, and PostgreSQL ended with one ACTIVE and one PENDING device.

## Increment 3 — deterministic USER refresh/revoke boundaries

`src/verigence_security/services/session_lifecycle.py` introduces only the session lifecycle behavior that v1.3 freezes unambiguously:

- `require_refresh_geo(...)` rejects a missing refresh geo sample with normative `GEO_REQUIRED`;
- `revoke(...)` locks the USER session by access-session/Tenant/user scope and persists `ACTIVE → REVOKED` transactionally;
- a non-ACTIVE or absent scoped session is not mutated by the revoke service;
- revocation does not attempt to invalidate an already-issued JWT before its existing `exp`, matching SEC-033.

`tests/unit/test_session_lifecycle.py` verifies the mandatory refresh-geo guard and transactional revoke service behavior.

`tests/integration/test_phase4_session_lifecycle.py` verifies the service-level ACTIVE→REVOKED transition against real Neon PostgreSQL and confirms a repeated revoke does not perform a second transition.

Validation run `31672322586`: **SUCCESS — 8/8 Phase 4 PostgreSQL integration tests passed**.

### Important non-claim for refresh

Increment 3 does **not** claim the full USER refresh algorithm is complete. In particular, committed v1.3 sources available in this repository do not deterministically state the refresh transition when a fresh valid geo sample resolves to a different assigned location than the location stored on the ACTIVE session. That behavior is not guessed here.

The full refresh policy re-evaluation, expiry recalculation, evidence persistence and token response must remain aligned to the exact approved contract before being declared complete.

## Validated behavior to date

1. PENDING enrollment persistence creates only PENDING device/enrollment state.
2. active-device counting ignores PENDING/BLOCKED/REVOKED devices.
3. membership-row `FOR UPDATE` serializes device-limit decisions.
4. PENDING device approval updates device and enrollment request together.
5. concurrent approvals cannot exceed `max_active_devices_per_user`.
6. USER session revocation is scoped by access-session/Tenant/user and transactional.
7. repeated revoke does not mutate an already non-ACTIVE session.
8. PostgreSQL enforces one ACTIVE USER session for the same Tenant/user/device.
9. missing USER refresh geo is rejected with normative `GEO_REQUIRED` at the service boundary.

The PostgreSQL tests use the real Neon DEV database and clean temporary fixtures after execution.

## Intentionally not yet implemented

- public device-enrollment request/response models and route wiring;
- device administration approval/block/revoke API wiring;
- complete USER access-session refresh policy re-evaluation and token issuance;
- the unresolved refresh-context transition when fresh geo maps to a different assigned location;
- USER access-session refresh/revoke public route wiring;
- denial-event persistence for lifecycle denials;
- deployed Railway Phase 4 lifecycle E2E;
- persistent cross-replica idempotency replay.

## Current grounding constraint

The repository contains the approved v1.3 decision, lifecycle and database artifacts, but authoritative `SECURITY_OPENAPI_v1.3.yaml` is referenced by checksum rather than stored in the repository. The exact endpoint request/response/security shapes must be recovered from the checksum-matching approved artifact before adding public lifecycle routes beyond endpoint details already explicitly frozen in committed decisions.

This is a source-availability constraint, not permission to infer or redesign the API.

## Next safe increment

Continue only with USER refresh behavior that can be deterministically derived from approved v1.3 sources and existing policy components. Record any unresolved refresh transition before implementation rather than choosing a behavior by convenience.

Public route wiring remains gated on recovery of the authoritative OpenAPI artifact.

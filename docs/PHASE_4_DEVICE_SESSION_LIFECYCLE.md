# Phase 4 — USER Device and Session Lifecycle

**Status:** PARTIAL — increments 1–2 validated on Neon DEV  
**Approved baseline:** Security Solution v1.3  
**Latest validation run:** `31671542390`

## Objective

Complete the approved USER device and access-session lifecycle without weakening the v1.3 access gates or inventing API, permission, error, persistence or event contracts that are not frozen by the approved design.

## Approved lifecycle anchors

Phase 4 implementation is grounded in the existing v1.3 decisions and schema:

- USER access requires an ACTIVE registered device.
- Unknown devices enter a PENDING enrollment/approval path before normal access.
- the canonical device identifier is the Verigence device UUID; MAC address is optional metadata rather than identity.
- the Tenant Security Policy controls `max_active_devices_per_user`.
- USER session refresh requires fresh geo.
- at most one ACTIVE USER access session may exist for the same Tenant, user and device.
- equivalent concurrent session creation is serialized on the registered-device row.
- revoking an access session blocks future refresh/new issuance for that session context, while an already-issued JWT remains cryptographically valid until its existing `exp`.
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
2. requires the membership to be ACTIVE using the existing normative membership errors;
3. loads the ACTIVE Tenant Security Policy;
4. locks the target PENDING device;
5. counts ACTIVE devices only after acquiring the serialization lock;
6. raises the normative `DEVICE_LIMIT_REACHED` when the configured limit is exhausted;
7. otherwise atomically activates the PENDING device and approves the matching enrollment request.

This prevents two simultaneous approvals for the same Tenant/user from both observing spare capacity and exceeding the configured device limit.

The Phase 4 Neon workflow now covers `feature/device-*` branches so subsequent device-lifecycle increments receive the same real-PostgreSQL validation.

Validation run `31671542390`: **SUCCESS — 7/7 PostgreSQL tests passed**.

The concurrency test created two simultaneous approval attempts against a Tenant policy of one active device. Exactly one approval succeeded; the other returned the existing normative `DEVICE_LIMIT_REACHED`, and PostgreSQL ended with one ACTIVE and one PENDING device.

## Validated behavior to date

1. PENDING enrollment persistence creates only PENDING device/enrollment state.
2. active-device counting ignores PENDING/BLOCKED/REVOKED devices.
3. membership-row `FOR UPDATE` serializes device-limit decisions.
4. PENDING device approval updates device and enrollment request together.
5. concurrent approvals cannot exceed `max_active_devices_per_user`.
6. USER session revocation is scoped by access-session/Tenant/user and idempotent at the persistence layer.
7. PostgreSQL enforces one ACTIVE USER session for the same Tenant/user/device.

The tests use the real Neon DEV PostgreSQL database and clean temporary fixtures after execution.

## Intentionally not yet implemented

- public device-enrollment request/response models and route wiring;
- device administration approval/block/revoke API wiring;
- USER access-session refresh service and API;
- mandatory fresh-geo refresh flow;
- USER access-session revoke API wiring;
- denial-event persistence for lifecycle denials;
- deployed Railway Phase 4 lifecycle E2E;
- persistent cross-replica idempotency replay.

## Current grounding constraint

The repository contains the approved v1.3 decision, lifecycle and database artifacts, but the authoritative `SECURITY_OPENAPI_v1.3.yaml` is referenced by checksum rather than stored in this repository. Exact endpoint request/response/security shapes must be recovered from the approved artifact before adding public lifecycle routes beyond endpoint details already explicitly frozen in committed decisions.

This is a source-availability constraint, not permission to infer or redesign the API.

## Next safe increment

Continue with session lifecycle behavior that is deterministic from v1.3 and existing access-policy components:

- USER session state handling for refresh/revoke;
- mandatory fresh-geo re-evaluation on refresh;
- PostgreSQL tests for refresh/revoke transitions and concurrency.

Public route wiring remains gated on the authoritative OpenAPI shapes.

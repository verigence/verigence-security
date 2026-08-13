# Phase 4 — USER Device and Session Lifecycle

**Status:** PARTIAL — increment 1 validated on Neon DEV  
**Branch:** `feature/device-session-lifecycle`  
**Approved baseline:** Security Solution v1.3  
**Validation run:** `31670840296`

## Objective

Complete the approved USER device and access-session lifecycle without weakening the v1.3 access gates or inventing API, permission, error, persistence or event contracts that are not frozen by the approved design.

## Approved lifecycle anchors used by this increment

Phase 4 implementation is grounded in the existing v1.3 decisions and schema:

- USER access requires an ACTIVE registered device.
- Unknown devices enter a PENDING enrollment/approval path before normal access.
- the canonical device identifier is the Verigence device UUID; MAC address is optional metadata rather than identity.
- USER session refresh requires fresh geo.
- at most one ACTIVE USER access session may exist for the same Tenant, user and device.
- equivalent concurrent session creation is serialized on the registered-device row.
- revoking an access session blocks future refresh/new issuance for that session context, while an already-issued JWT remains cryptographically valid until its existing `exp`.
- persistent cross-replica `Idempotency-Key` replay remains blocked until an approved persistence model exists.

## Increment 1 implemented

`src/verigence_security/repositories/device_session_repository.py` adds PostgreSQL primitives for:

- creating a registered device in `PENDING` state together with a `PENDING` device-enrollment request;
- locking the Tenant membership row to serialize active-device-limit decisions for the same Tenant/user;
- counting only `ACTIVE` registered devices;
- locking a PENDING device row for approval work;
- atomically transitioning the matching PENDING device and PENDING enrollment request to `ACTIVE` / `APPROVED` inside the caller transaction;
- locking a USER access-session row by access-session/Tenant/user scope;
- transitioning an ACTIVE USER access session to `REVOKED` without changing the lifetime of an already-issued JWT.

No v1.3 schema migration was added or changed.

## Neon DEV validation

Workflow: `.github/workflows/phase4-neon-lifecycle.yml`  
Run: `31670840296`  
Result: **SUCCESS — 6/6 PostgreSQL integration tests passed**.

Validated behavior:

1. `create_pending_enrollment` persists only `PENDING` device/enrollment state.
2. active-device counting ignores PENDING/BLOCKED/REVOKED devices.
3. `SELECT ... FOR UPDATE` on the Tenant membership serializes concurrent device-limit decisions.
4. PENDING device approval persists `registered_devices.status=ACTIVE` and `device_enrollment_requests.status=APPROVED` together.
5. USER session revocation is scoped by access-session/Tenant/user and is idempotent at the persistence layer.
6. PostgreSQL rejects a second ACTIVE USER session for the same Tenant/user/device through the approved partial unique index.

The tests use the real Neon DEV PostgreSQL database and clean their temporary fixtures after each test.

## Intentionally not implemented in increment 1

The following are still Phase 4 work:

- public device-enrollment request/response models and route wiring;
- device administration approval/block/revoke API wiring;
- application-service enforcement of the configured active-device limit;
- USER access-session refresh service and API;
- mandatory fresh-geo refresh flow;
- USER access-session revoke API;
- denial-event persistence for lifecycle denials;
- deployed Railway Phase 4 E2E;
- persistent cross-replica idempotency replay.

## Current grounding constraint

The repository contains the approved v1.3 decision, lifecycle and database artifacts, but the authoritative `SECURITY_OPENAPI_v1.3.yaml` is referenced by checksum rather than stored in this repository. Its exact endpoint request/response/security shapes must be recovered from the approved artifact before adding public lifecycle routes beyond endpoint details already explicitly frozen in the committed decisions.

This is a source-availability constraint, not permission to infer or redesign the API.

## Next safe increment

Continue with service-level lifecycle behavior that is deterministic from v1.3 and the approved schema, especially:

- serialized active-device-limit enforcement using the Tenant policy value;
- session-state handling needed by refresh/revoke;
- fresh-geo refresh policy evaluation using the existing USER access-policy components;
- PostgreSQL tests for concurrent approval/session state transitions.

Public route wiring remains gated on the authoritative OpenAPI shapes.

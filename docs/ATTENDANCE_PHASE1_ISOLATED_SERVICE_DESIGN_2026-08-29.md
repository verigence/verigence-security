# Verigence Attendance Phase 1 — Isolated Service Design

Date: 29-Aug-2026
Status: Implementation baseline
Repository: `verigence-security`

## 1. Decision

Attendance is implemented in the `verigence-security` repository, but **not inside the existing Security runtime process**.

The repository contains two independently deployable applications:

- existing Security service — identity, authentication, authorization, device/session security
- new Attendance service — check-in/check-out, attendance records, geofence validation, reminders/policy, reporting

The Attendance application has its own entry point, deployment/service, health check and database connection pool. The existing Security application must not import or start Attendance runtime code.

## 2. Non-regression principle

Attendance must never become a dependency of Booking, Delivery, Review, DI processing or normal project navigation.

Required guarantees:

1. No Attendance API call is allowed on existing Booking/Delivery/Review critical paths.
2. Attendance service failure must not block the existing Verigence application.
3. Web Attendance components are lazy-loaded and fail independently.
4. Attendance uses its own DB schema/tables and connection pool.
5. Attendance downstream requests use strict bounded timeouts.
6. Existing Security authentication/token flows are not redesigned.
7. Existing Audit Core and DI hot paths remain untouched.
8. Rollback is repository/service specific.

## 3. Pre-Attendance baselines

Exact rollback branches created before Attendance implementation:

- `verigence-security`: `baseline/pre-attendance-phase1-20260828` @ `3ee90dc2c8e498a9629417f5f2a9895e76279ecf`
- `verigence-web`: `baseline/pre-attendance-phase1-20260828` @ `2b59f455539a5e9c50da4cbed9c3b5a17148ad9e`
- `verigence-audit-core`: `baseline/pre-attendance-phase1-20260828` @ `605d097eb92e36009f884ebf4cd1cdb76ed864fe`
- `verigence-di`: `baseline/pre-attendance-phase1-20260828` @ `86713488d7811ab6b9cb7d049bf04aa6fa004201`

Feature branches:

- Security/Attendance service: `feature/attendance-phase1-service`
- Web: `feature/attendance-phase1-web`
- Audit Core read-only location contract: `feature/attendance-phase1-location-contract`

DI requires no Attendance change in Phase 1.

## 4. Runtime topology

```text
Verigence Web
   |
   +-- existing business modules ------------------------------> Audit Core / DI
   |
   +-- Attendance UI (lazy loaded) ----------------------------> Attendance Service
                                                                  |
                                                                  +--> Security Auth/AuthZ
                                                                  |
                                                                  +--> Audit Core read-only assignment/location lookup
```

Attendance is a sibling application from the Web user's perspective, not middleware around existing application traffic.

## 5. Security responsibilities

Security remains source of truth for:

- authenticated global Verigence USER identity
- Tenant/project memberships
- normal operating role (`PC`, `TL`, `PM`, `CRM`, `Executive`)
- global secondary Attendance role `HRADMIN`
- Attendance permissions
- existing device/session observation where useful

### 5.1 HRADMIN is global, not Tenant-scoped

`HRADMIN` is a **secondary global Attendance module role**.

It is deliberately independent of Tenant/Project membership:

- assigning HRADMIN does not require a Tenant ID
- the HRADMIN assignment row contains no Tenant foreign key
- HRADMIN can authorize Attendance administration with no Tenant context
- HRADMIN can administer Attendance data across Tenants/Projects
- HRADMIN does not replace or alter the user's normal operating role
- HRADMIN grants no Audit Core, DI or other module authority

A user may therefore be `TL + HRADMIN`, `PM + HRADMIN`, `PC + HRADMIN`, or HRADMIN without an operating role, while the normal operating-role model remains unchanged.

The global secondary-role persistence is isolated from existing primary roles:

- `security.module_roles`
- `security.module_role_permissions`
- `security.user_module_role_assignments`

These tables are only consulted for permissions belonging to the same module. For `attendance.*`, Security may resolve `HRADMIN`; for Audit/DI permissions it continues through the existing authorization path.

HRADMIN assignment/removal is a platform-level Security administration change and is audited with `scope_type='PLATFORM'` and no Tenant ID.

### 5.2 Tenant-scoped operating roles remain unchanged

PC/TL/PM/CRM/Executive stay Tenant/Project scoped through the existing operating-role model. Attendance permissions for those roles are materialized per Tenant so normal operating users cannot escape their project scope.

Role intent:

- PC: self attendance; geofence enforced from active Dealer/Outlet assignment
- TL: self attendance + assigned-team view when enabled
- PM: self attendance + Tenant/project-wide read-only attendance
- CRM: self attendance
- Executive: self attendance + Tenant/project-wide read-only attendance
- HRADMIN: global all-Tenant Attendance administration

### 5.3 Phase 1 permissions

- `attendance.self.read`
- `attendance.self.checkin`
- `attendance.self.checkout`
- `attendance.team.read`
- `attendance.all.read`
- `attendance.location.read`
- `attendance.exception.read`
- `attendance.exception.resolve`
- `attendance.correction.write`
- `attendance.policy.read`
- `attendance.policy.manage`
- `attendance.report.read`
- `attendance.report.export`

## 6. Attendance service responsibilities

The isolated Attendance service owns:

- daily attendance state
- check-in/check-out event persistence
- fresh location evidence
- geofence calculation
- Attendance policy and reminder metadata
- exception evidence and correction history
- HR/PM/Executive Attendance reporting

It does not own employee identity, Dealer/Outlet master data or business assignments.

Attendance rows retain their Tenant/Project reference because PC geofence resolution and PM/Executive project reporting depend on that operational context. This does **not** scope HRADMIN itself to a Tenant.

## 7. Location and geofence rules

### PC

PC work locations are derived from existing Dealer/Outlet assignments. Attendance must not introduce a duplicate employee-to-location master.

At Check-In/Check-Out:

1. Web captures fresh location only after the employee explicitly initiates the action.
2. Attendance resolves the active PC work context through the read-only Audit Core contract.
3. Audit Core returns assigned active Outlet(s) and existing Outlet coordinates.
4. Attendance performs geofence validation server-side.
5. Matched Outlet and distance are stored as attendance evidence.

Phase 1 geofence radius is controlled by Attendance policy unless an Outlet-specific radius is introduced later.

Outside-geofence check-in requires exception handling according to policy. Outside-geofence checkout can be recorded as an exception instead of leaving the employee permanently checked in.

### TL and PM

Fresh location is captured at Check-In and Check-Out, but geofence is not enforced in Phase 1.

### Executive / HRADMIN

Fresh location may be captured for their own attendance where an operational Attendance context exists; geofence is not enforced in Phase 1.

## 8. Audit Core boundary

Audit Core remains source of truth for:

- Dealer
- Outlet
- Outlet latitude/longitude
- effective Dealer/Outlet business assignments

Only a small read-only current-user contract is allowed for Attendance:

`GET /v1/tenants/{tenant_id}/attendance-context/me`

The contract reuses authenticated user identity plus existing `auditcore.business_assignments` and `auditcore.dealer_outlets`. For PC it returns active assigned Outlet(s) and coordinates. For TL/PM/other non-PC operating roles it returns the role but no geofence Outlet requirement.

It must not modify Booking/Delivery/Review queries or add work to existing hot endpoints.

## 9. Web isolation

Attendance UI is another application inside the common Verigence shell.

Rules:

- Attendance pages/chunks are lazy-loaded.
- Attendance is not added to Booking/Delivery/Review preload paths.
- Existing role landing pages do not wait for Attendance.
- Initial authenticated page rendering does not wait for Attendance status.
- Attendance reminder/status loads asynchronously after the primary page is interactive.
- Attendance requests use timeout, caching/backoff and independent error handling.
- Attendance failures never redirect the user or block business actions.
- Browser/native geolocation is requested only for explicit Check-In/Check-Out.

## 10. Reminder model

The Web shell may show asynchronous reminders from Attendance status and the applicable Attendance policy:

- check-in reminder
- current checked-in state
- end-of-day checkout reminder

Reminder retrieval is not part of authentication, project-context resolution or business-data loading.

## 11. Attendance persistence

Operational Attendance data uses the separate `attendance` schema and its own migration set.

Phase 1 entities:

- `attendance.policy`
- `attendance.daily_attendance`
- `attendance.attendance_event`
- `attendance.correction`

Dealer/Outlet data and Security identity/RBAC data are not duplicated into this schema.

## 12. Performance safeguards

Before merge, validate:

- existing Security login/onboarding/token flows contain no Attendance runtime calls
- existing Security `main.py` does not start the Attendance process
- no Attendance call exists in Web Booking/Delivery/Review services or preloaders
- Web Attendance page/widget bundles are code-split
- initial authenticated page rendering does not await Attendance
- existing Security authorization regression tests remain green
- Audit Core existing endpoint regression tests remain green
- Attendance downstream calls are bounded by strict timeouts
- Attendance DB pool is independently configurable
- Attendance service can be stopped while Security, Audit Core, DI and normal Web business flows continue operating

## 13. Rollback

Independent rollback paths:

1. disable/remove Web Attendance navigation/widget
2. roll back Attendance service deployment only
3. revert additive Attendance Security permissions/global HRADMIN support
4. revert Audit Core Attendance read-only context independently

The baseline branches in section 3 remain the pre-Attendance restore points.

## 14. Phase 1 scope

Included:

- isolated Attendance service in `verigence-security`
- global Tenant-independent HRADMIN secondary role
- Check-In / Check-Out
- fresh location capture
- PC geofence using existing Dealer/Outlet mapping
- TL/PM location capture without geofence
- asynchronous Attendance shell reminder/status
- self history
- HRADMIN all-Tenant Attendance administration/correction/exception handling
- PM and Executive Tenant/project-wide read-only Attendance visibility
- basic reports

Out of scope:

- continuous GPS tracking
- payroll
- biometric attendance
- facial recognition
- complex shift rostering
- DI dependency
- Attendance gating of normal Verigence business work

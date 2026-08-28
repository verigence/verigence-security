# Verigence Attendance Phase 1 — Isolated Service Design

Date: 29-Aug-2026
Status: Implementation baseline
Repository: `verigence-security`

## 1. Decision

Attendance will be implemented in the `verigence-security` repository, but **not inside the existing Security runtime process**.

The repository will contain two independently deployable applications:

- existing Security service — identity, authentication, authorization, device/session security
- new Attendance service — check-in/check-out, attendance records, geofence validation, reminders/policy, reporting

The Attendance application must have a separate entry point, deployment/service, health check and database connection pool. The existing Security `main.py` must not import or start Attendance runtime code.

This preserves one source repository for closely related employee/security capabilities while maintaining runtime isolation.

## 2. Non-regression principle

Attendance must never become a dependency of Booking, Delivery, Review, DI processing or normal project navigation.

Required guarantees:

1. No Attendance API call is allowed on existing Booking/Delivery/Review critical paths.
2. Attendance service failure must not block the existing Verigence application.
3. Web attendance components must be lazy-loaded and fail independently.
4. Attendance uses its own DB schema/tables and connection pool.
5. Attendance requests must have strict timeouts for downstream lookups.
6. Existing Security authentication/authorization endpoints are reused but not redesigned.
7. Existing Audit Core and DI hot paths are untouched.
8. Rollback is repository/service specific.

## 3. Pre-Attendance baselines

Exact rollback branches were created before implementation:

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
                                                                  +--> Security authorization
                                                                  |
                                                                  +--> Audit Core read-only assignment/location lookup
```

Attendance is a sibling application from the Web user's perspective, not middleware around existing application traffic.

## 5. Security responsibilities

Security remains source of truth for:

- authenticated human identity
- tenant/project membership
- operating role (PC/TL/PM/CRM/EXECUTIVE)
- secondary Attendance role `HRADMIN`
- Attendance permissions
- existing device/session observation where useful

`HRADMIN` is a **secondary module role**, not an operating role. A user may be `TL + HRADMIN`, `PM + HRADMIN`, etc. without changing normal operating-role behavior.

### Phase 1 permissions

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

Role intent:

- PC/TL/PM and other employees: self attendance capture/read
- TL: optional assigned-team attendance visibility when enabled
- PM: organization/project-wide read-only attendance visibility
- EXECUTIVE: organization/project-wide read-only attendance visibility
- HRADMIN: all attendance, corrections, exceptions, policy and reporting

## 6. Attendance service responsibilities

The Attendance service owns:

- daily attendance state
- check-in/check-out event persistence
- fresh location evidence
- geofence calculation
- attendance policy and reminder metadata
- exceptions and correction history
- HR/PM/Executive attendance reporting

It must not own dealer/outlet master data or PC business assignments.

## 7. Location and geofence rules

### PC

PC work locations are derived from the existing Dealer/Outlet assignment. Attendance must not introduce a duplicate employee-to-location master.

At Check-In/Check-Out:

1. Web captures a fresh location.
2. Attendance resolves the user's active PC assignment through the read-only Audit Core contract.
3. Audit Core returns assigned outlet(s) with outlet latitude/longitude.
4. Attendance performs server-side geofence validation.
5. The matched outlet and distance are stored with the attendance event.

Phase 1 geofence radius is an Attendance policy/default radius unless an outlet-specific radius is introduced later.

Check-in outside the geofence is an exception, not a normal accepted check-in. Operational escape handling may capture a reason according to policy.

Checkout outside the geofence may be recorded as a checkout exception rather than leaving a user permanently checked in.

### TL and PM

Fresh location is captured at Check-In and Check-Out, but no geofence is enforced in Phase 1.

### Executive / HRAdmin

Fresh location may be captured for their own attendance; no geofence enforcement in Phase 1.

## 8. Audit Core boundary

Audit Core remains source of truth for:

- Dealer
- Outlet
- outlet latitude/longitude
- effective PC Dealer/Outlet assignment

Only a small read-only service contract is allowed for Attendance, returning the current subject's effective attendance location context. It must not modify Booking/Delivery/Review queries or add work to existing hot endpoints.

The Attendance service calls this contract only during explicit attendance actions or Attendance screens.

## 9. Web isolation

Attendance UI will be treated as another application within the common Verigence shell.

Rules:

- Attendance pages/chunks are lazy-loaded.
- Existing role landing pages do not wait for Attendance.
- Initial Web route/render must not wait for Attendance status.
- A small attendance indicator/reminder may load asynchronously after the primary page is interactive.
- Attendance errors render only inside the Attendance widget/page.
- No Attendance failure redirects the user or blocks business actions.
- Browser/native geolocation is requested only when the user performs Check-In/Check-Out, not during normal page load.

## 10. Reminder model

The Web shell can show asynchronous reminders based on Attendance status and tenant attendance policy, for example:

- working-day check-in reminder
- checked-in status
- end-of-day checkout reminder

The reminder query must occur after primary application rendering and must use caching/backoff. It is not part of authentication or project-context resolution.

## 11. Attendance persistence

Attendance data uses a separate schema, proposed `attendance`, with its own migration set.

Core entities:

- `attendance.policy`
- `attendance.daily_attendance`
- `attendance.attendance_event`
- `attendance.exception`
- `attendance.correction`

Attendance data must not be placed in Security identity/RBAC tables.

## 12. Performance safeguards

Before merge, validate:

- no new Attendance imports in existing Security `main.py`
- no Attendance call in Web Booking/Delivery/Review services
- Web attendance bundle is code-split
- Security baseline authorization latency unaffected
- Audit Core existing endpoint regression tests green
- Attendance downstream call timeout bounded
- Attendance DB pool independently configurable
- Attendance service can be stopped while Security, Web business flows, Audit Core and DI remain operational

## 13. Rollback

Attendance has independent rollback paths:

1. disable/remove Web Attendance navigation/widget
2. roll back Attendance service deployment only
3. revert Attendance permission/catalog migration if required
4. revert the Audit Core read-only attendance-location contract independently

The baseline branches listed in section 3 are the pre-Attendance restore points.

## 14. Phase 1 scope

Phase 1 includes:

- isolated Attendance service in `verigence-security` repository
- HRADMIN secondary role/permissions
- Check-In / Check-Out
- fresh location capture
- PC geofence using existing Dealer/Outlet mapping
- TL/PM location capture without geofence
- Attendance shell reminder/status
- self history
- HRAdmin all-employee view/correction/exception handling
- PM and Executive all-employee read-only view
- basic reports

Out of scope:

- continuous GPS tracking
- payroll
- biometric attendance
- facial recognition
- complex shift rostering
- DI dependency
- Attendance gating of normal Verigence business work

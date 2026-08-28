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
6. Existing Security authentication/authorization endpoints and RBAC constructs are reused; no parallel Attendance identity/RBAC model is allowed.
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
                                                                  +--> existing Security Auth/AuthZ
                                                                  |
                                                                  +--> Audit Core read-only assignment/location lookup
```

Attendance is a sibling application from the Web user's perspective, not middleware around existing application traffic.

## 5. Security responsibilities and reuse

Security remains the source of truth for:

- authenticated human identity
- Tenant/project membership
- operating role (`PC`, `TL`, `PM`, `CRM`, `Executive`)
- secondary Attendance administration role `HRAdmin`
- Attendance permissions
- existing device/session observation where useful

Attendance must reuse the existing Security v2 constructs rather than introduce Attendance-specific RBAC tables:

- `security.permissions` — canonical `attendance.*` permissions
- `security.role_definitions` — canonical `HRAdmin` role definition
- `security.user_admin_role_assignments` — Tenant-scoped HRAdmin assignment
- `security.platform_role_permission_defaults` — role permission defaults
- `security.tenant_role_permissions` — materialized Tenant role permissions
- `security.user_tenant_operating_roles` — unchanged source of the user's normal operating role
- existing Security human JWT, service-integration token and `/security/v1/authorization/check` contracts

`HRAdmin` is an **ADMIN role using the existing Security admin-assignment machinery**, but its authorization semantics are secondary and Attendance-only. A user may therefore be `TL + HRAdmin`, `PM + HRAdmin`, `PC + HRAdmin`, etc. The HRAdmin assignment must not replace, suppress or broaden the user's normal Audit/DI operating-role authority.

For an `attendance.*` permission, an active Tenant-scoped HRAdmin assignment may grant the permission through the existing Tenant role-permission bundle. For non-Attendance permissions, HRAdmin is ignored and normal existing SuperAdmin/TenantAdmin/ModuleAdmin/TestUser/operating-role resolution continues unchanged.

No `module_roles`, `module_role_permissions`, `user_module_role_assignments`, or equivalent parallel Attendance RBAC tables are permitted.

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

- PC/TL/PM/CRM/Executive: self attendance capture/read
- TL: assigned-team attendance visibility when the team-read endpoint is implemented
- PM: Tenant/project-wide read-only attendance visibility
- Executive: Tenant/project-wide read-only attendance visibility
- HRAdmin: Tenant-wide attendance administration, corrections, exception handling, policy and reporting

## 6. Attendance service responsibilities

The Attendance service owns:

- daily attendance state
- check-in/check-out event persistence
- fresh location evidence
- geofence calculation
- attendance policy and reminder metadata
- exception evidence and correction history
- HR/PM/Executive attendance reporting

It must not own employee identity, Security role assignments, Dealer/Outlet master data or PC business assignments.

## 7. Location and geofence rules

### PC

PC work locations are derived from the existing Dealer/Outlet assignment. Attendance must not introduce a duplicate employee-to-location master.

At Check-In/Check-Out:

1. Web captures a fresh location only after the employee explicitly initiates the attendance action.
2. Attendance resolves the user's active PC assignment through the read-only Audit Core contract.
3. Audit Core returns assigned active Outlet(s) with existing Outlet latitude/longitude.
4. Attendance performs server-side geofence validation.
5. The matched Outlet and distance are stored with the attendance event.

Phase 1 geofence radius is an Attendance policy/default radius unless an Outlet-specific radius is introduced later.

Check-in outside the geofence is an exception, not a normal accepted check-in. If exception handling is enabled by policy, a reason is required.

Checkout outside the geofence may be recorded as a checkout exception rather than leaving a user permanently checked in.

### TL and PM

Fresh location is captured at Check-In and Check-Out, but no geofence is enforced in Phase 1.

### Executive / HRAdmin

Fresh location may be captured for their own attendance; no geofence is enforced in Phase 1.

## 8. Audit Core boundary

Audit Core remains source of truth for:

- Dealer
- Outlet
- Outlet latitude/longitude
- effective Dealer/Outlet business assignments

Only a small read-only current-user contract is allowed for Attendance:

`GET /v1/tenants/{tenant_id}/attendance-context/me`

The contract reuses the authenticated user's existing `auditcore.business_assignments` and `auditcore.dealer_outlets`. For a PC it returns the currently effective assigned Outlet(s) and coordinates. For TL/PM/other non-PC operating roles it returns the role but no geofence Outlets.

The contract must not modify Booking/Delivery/Review queries or add work to existing hot endpoints. Attendance calls it only during explicit attendance actions or Attendance-specific screens.

## 9. Web isolation

Attendance UI is another application within the common Verigence shell.

Rules:

- Attendance pages/chunks are lazy-loaded.
- Attendance is not added to existing Booking/Delivery/Review preloading.
- Existing role landing pages do not wait for Attendance.
- Initial Web route/render does not wait for Attendance status.
- A small attendance indicator/reminder may load asynchronously only after the primary page is interactive.
- Attendance status requests use bounded timeout, caching/backoff and fail independently.
- Attendance errors render only inside the Attendance widget/page.
- No Attendance failure redirects the user or blocks business actions.
- Browser/native geolocation is requested only when the user explicitly performs Check-In/Check-Out, never during login or normal page load.

## 10. Reminder model

The Web shell can show asynchronous reminders based on Attendance status and Tenant attendance policy, for example:

- working-day check-in reminder
- checked-in status
- end-of-day checkout reminder

The reminder query occurs after primary application rendering and uses caching/backoff. It is not part of authentication, project-context resolution or any business-data request.

## 11. Attendance persistence

Attendance operational data uses the separate `attendance` schema and its own migration set.

Phase 1 entities are:

- `attendance.policy`
- `attendance.daily_attendance`
- `attendance.attendance_event`
- `attendance.correction`

Geofence/exception evidence is recorded in the daily record and append-only attendance events; no duplicate Security identity/RBAC or Dealer/Outlet tables are created in the Attendance schema.

## 12. Performance safeguards

Before merge, validate:

- no Attendance import in existing Security `main.py`
- no Attendance call in Security login/onboarding/token hot paths
- no Attendance call in Web Booking/Delivery/Review services or their preloader
- Web Attendance page/widget chunks are code-split
- initial authenticated page rendering does not await Attendance
- Security existing authorization tests remain green
- Audit Core existing endpoint regression tests remain green
- Attendance downstream calls have strict bounded timeouts
- Attendance DB pool is independently configurable
- Attendance service can be stopped while Security, Web business flows, Audit Core and DI remain operational

## 13. Rollback

Attendance has independent rollback paths:

1. disable/remove Web Attendance navigation/widget
2. roll back Attendance service deployment only
3. revert the additive Attendance permission/HRAdmin Security migration if required
4. revert the Audit Core read-only attendance-location contract independently

The baseline branches listed in section 3 are the pre-Attendance restore points and remain untouched.

## 14. Phase 1 scope

Phase 1 includes:

- isolated Attendance service in `verigence-security` repository
- HRAdmin through existing Security role/admin-assignment/permission constructs
- Check-In / Check-Out
- fresh location capture
- PC geofence using existing Dealer/Outlet mapping
- TL/PM location capture without geofence
- Attendance shell reminder/status
- self history
- HRAdmin all-employee attendance administration/correction/exception handling
- PM and Executive all-employee read-only attendance visibility
- basic reports

Out of scope:

- continuous GPS tracking
- payroll
- biometric attendance
- facial recognition
- complex shift rostering
- DI dependency
- Attendance gating of normal Verigence business work

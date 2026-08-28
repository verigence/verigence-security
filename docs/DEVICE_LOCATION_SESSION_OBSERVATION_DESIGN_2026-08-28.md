# Device, Location and Session Observation Design — 2026-08-28

## Status

Approved implementation direction for the first observation release. The objective is to capture device/session/location evidence now without adding user-visible latency, while leaving a clean path to location and device enforcement later.

## Frozen recovery baseline

Before this work, the current DEV heads were frozen on the same recovery branch name in all four repositories:

`baseline/stable-2026-08-28-pre-device-location-session`

| Module | Repository | Frozen DEV SHA |
|---|---|---|
| Security | `verigence/verigence-security` | `0f282cfc864c0c33c4ad68665b8d9e00036b37b1` |
| Web / Mobile | `verigence/verigence-web` | `12027800a8ade2ecc2705da786081767a45a52d1` |
| Audit Core | `verigence/verigence-audit-core` | `605d097eb92e36009f884ebf4cd1cdb76ed864fe` |
| Document Intelligence | `verigence/verigence-di` | `86713488d7811ab6b9cb7d049bf04aa6fa004201` |

The connected GitHub automation used for this change does not expose creation of `refs/tags/*`, therefore the recovery points are immutable-intent snapshot branches rather than Git tags. They must not be moved.

Audit Core and DI are outside the implementation scope of this increment.

## Non-negotiable performance rule

The existing application journey must not wait for device persistence, GPS, location matching, risk analysis, or session-observation persistence.

The login critical path remains:

1. Web/Mobile reads a persistent local installation/browser UUID.
2. The existing login request sends credentials plus that already-available UUID and cheap device metadata.
3. Security validates credentials through Clerk and resolves the Verigence human user.
4. Security generates a Verigence `session_id` in memory and issues the Verigence JWT.
5. Web stores the token and navigates immediately to the normal landing/work page.

The following work is post-login and best-effort/asynchronous from the UI:

- persist/update the device record;
- activate the new observation session and mark a previous session `SUPERSEDED`;
- record source IP;
- acquire browser/native geolocation;
- attach the geo sample to the observation session;
- record device-limit/location observations.

No Work Queue, Booking, Delivery, DI or Audit Core request gains a new Security database/network round trip.

## Identity-provider boundary

Clerk remains the credential authority only. Security remains the Verigence token/session authority.

- Clerk is called on credential login.
- Security issues and verifies the Verigence JWT.
- Security token refresh does not repeat Clerk credential authentication.
- No Clerk heartbeat/session mechanism is introduced.

## Device identity

### Web

Generate a cryptographically random UUID once and persist it in browser storage as the Verigence browser installation ID. Clearing browser storage/incognito/new browser is naturally observed as a new installation.

### Mobile

Use a Verigence installation UUID. The same contract is shared with the Capacitor application; storage can be strengthened to native secure storage without changing the Security API.

Do not use IMEI, SIM identity, invasive browser fingerprinting, canvas/WebGL fingerprinting, or MAC address as the primary identifier.

## Human JWT extension

The active global human JWT is extended with:

- `session_id`
- `device_id`

The token remains global-human identity authority only. Tenant/role/permission/location authorization is not copied into this token by this increment.

Normal business services continue validating the signed JWT without checking the Security session database on every request.

## Global observation persistence

The existing legacy `security.registered_devices` and `security.access_sessions` are tenant-scoped and the USER access-session constraint requires tenant membership, device and matched location. The active global human login occurs before project/tenant context is selected. Therefore this increment does not distort those tenant-scoped tables to satisfy global login.

A small global-human observation layer is added:

### `security.human_devices`

One record per Verigence browser/mobile installation per user.

Stores:

- canonical `device_id` (the installation UUID carried by Web/Mobile);
- user;
- WEB/MOBILE type;
- platform and optional browser/app/device metadata;
- first/last source IP;
- first/last seen timestamps;
- status (`ACTIVE`, `BLOCKED`, `REVOKED`).

### `security.human_access_sessions`

One record per successful Verigence login observation session.

Stores:

- `access_session_id`;
- user and device;
- status (`ACTIVE`, `SUPERSEDED`, `ENDED`, `REVOKED`);
- start, token-expiry, superseded/end timestamps;
- source IP;
- latest login geo evidence when supplied (`latitude`, `longitude`, `accuracy`, source, captured timestamp, observation result).

There is at most one `ACTIVE` observation session per global user. A new observation registration marks the previous active session `SUPERSEDED` and activates the new session atomically.

## Simultaneous login behaviour

The new login always proceeds. The previous session is not interrupted mid-token.

1. Device B logs in successfully.
2. Device B receives its Security JWT immediately.
3. The asynchronous observation registration marks Device A's session `SUPERSEDED` and Device B's session `ACTIVE`.
4. Device B may show: `You're already signed in on another device. Your previous session will end automatically soon.`
5. Device A continues until its current Security JWT reaches the normal renewal point.
6. Refresh checks the session carried by that JWT.
7. `SUPERSEDED`, `ENDED`, or `REVOKED` sessions cannot renew and Web signs out through its existing renewal gate.

There is no heartbeat, WebSocket or SSE requirement.

## Device-registration limit

A configurable observation limit is introduced. Initial mode is `OBSERVE`:

- devices are still recorded;
- exceeding the configured active-device count is recorded and returned as observation metadata;
- login is not denied;
- no employee is blocked in this release.

The same data can later support enforcement without changing the Web device identity contract.

## Location capture

Location is requested from browser/native capabilities and is deliberately outside the login critical path.

Captured evidence:

- latitude;
- longitude;
- accuracy metres;
- source (`BROWSER` or `NATIVE`);
- captured timestamp;
- source IP already observed server-side.

Initial policy is `OBSERVE`. Location unavailable, denied, stale, inaccurate, or mismatched must never delay or deny login in this increment.

The current tenant locations and user-location assignments remain the future source for assigned-location enforcement. When enforcement is enabled later, Security can evaluate fresh geo against assigned locations at renewal/authorization boundaries instead of adding a Security call to every business API.

## Observation modes and future progression

- `OBSERVE`: capture and record; never deny for device count/location.
- `WARN`: capture, record and surface warnings; operational access still allowed.
- `ENFORCE`: future release; require policy-compliant device/location before renewal/operational access.

This increment implements only the foundation required for `OBSERVE` and session supersession at refresh.

## Failure behaviour

Performance and availability take precedence over observation telemetry in this release:

- login does not wait for GPS;
- login does not wait for observation persistence;
- failure of the post-login observation call does not invalidate an otherwise valid login;
- Web can retry observation once when appropriate;
- refresh fails closed only for a session that is explicitly known as `SUPERSEDED`, `ENDED` or `REVOKED`;
- an observation record missing because the asynchronous call failed does not create a new outage path during the observation phase.

## Acceptance criteria

1. The four frozen baseline refs remain at the SHAs listed above.
2. Audit Core and DI receive no code changes from this increment.
3. Existing credential login/Clerk behaviour remains unchanged.
4. Login response contains a Security JWT with `device_id` and `session_id`.
5. Device and session evidence is persisted after login without blocking navigation.
6. Browser/native geo is acquired asynchronously and attached when available.
7. A second login supersedes the prior observation session and returns a non-blocking warning signal to the new client.
8. The superseded session continues until its existing JWT renewal boundary, then cannot refresh.
9. Device-limit/location observations do not deny access in this release.
10. No normal Audit Core/DI/business API gains a per-request Security session lookup.
11. Performance comparison must show no material user-facing regression in login-to-landing or landing-to-work-data timings.

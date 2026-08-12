# Verigence Security Decision Register v1.3

| ID | Decision |
|---|---|
| SEC-001 | Security is a separate authentication/authorization module. |
| SEC-002 | Initial infrastructure is Railway + Clerk + Neon PostgreSQL. |
| SEC-003 | One employee can belong to multiple Tenants. |
| SEC-004 | Roles are Tenant-scoped. |
| SEC-005 | Employee must be explicitly assigned to each allowed location. |
| SEC-006 | Employee may have multiple allowed locations within a Tenant. |
| SEC-007 | All Tenant operating locations are onboarded in Security. |
| SEC-008 | Unvalidated geo means no application access. |
| SEC-009 | Access is limited by configured time windows. |
| SEC-010 | Devices are registered and limited. |
| SEC-011 | Unknown devices use a pending enrollment/approval path before normal access. |
| SEC-012 | Canonical device identity is a Verigence UUID; MAC is nullable metadata. |
| SEC-013 | Source IP is captured from trusted ingress. |
| SEC-014 | VPN/network context is tracked through a provider-neutral adapter. |
| SEC-015 | Tenant policy defines DENY/FLAG handling for detected or unknown network risk. |
| SEC-016 | Schedules attach to employee-location assignments and use the location timezone. |
| SEC-017 | Clerk authenticates; Neon Security data is the authorization source of truth. |
| SEC-018 | Security issues a Verigence Access Token after all access gates pass. |
| SEC-019 | DI/WPM validate Security token and never query Security tables. |
| SEC-020 | Security thresholds are mandatory Tenant configuration, not code defaults. |
| SEC-021 | Clerk Hobby is used until production-readiness; production plan is reassessed before go-live. |
| SEC-022 | Platform permissions use canonical module-prefixed dot notation: `<module>.<resource>.<action>`. Security owns the permission catalogue. DI migrates legacy values such as `document:upload` to `di.document.upload`; colon syntax is deprecated. |
| SEC-023 | LOCAL/CI/DEV may expose `POST /security/v1/dev/mock-auth/token` for an existing Security user. The mock identity token substitutes only the authentication-provider boundary and carries no caller-supplied roles or privileges. |
| SEC-024 | DEV may use mock identity and mock network-risk adapters to remove external hooks while retaining real Tenant membership, device, geo, time-window and RBAC evaluation. UAT/Production prohibit mock authentication; Production refuses startup if it is enabled. |
| SEC-025 | Security Principal is the common identity abstraction. `actor_type` is exactly USER, SYSTEM or SERVICE_INTEGRATION and is asserted by Security from the registered principal; callers cannot self-declare actor type. |
| SEC-026 | USER actors use the existing human access path: configured identity provider, Tenant membership, ACTIVE device, mandatory geo/location, time window, network policy and Tenant RBAC. |
| SEC-027 | SYSTEM actors are Verigence-controlled non-human principals (for example DI workers, schedulers and the WhatsApp ingestion adapter). They authenticate with machine credentials and receive explicit Tenant-scoped permissions; human device/geo/time controls do not apply. |
| SEC-028 | SERVICE_INTEGRATION actors represent external applications/systems such as DMS/ERP/API integrations. They authenticate with registered machine credentials, must be explicitly scoped to a Tenant and receive explicit permissions; human roles/device/geo controls do not apply. |
| SEC-029 | For USER access-session refresh, a new geo sample is mandatory. Missing geo returns `GEO_REQUIRED`; machine actors do not use the USER refresh endpoint and obtain a new machine access token instead. |
| SEC-030 | At most one ACTIVE USER access session exists for the same Tenant + user + device. Creation is serialized on the registered-device row and is idempotent; a concurrent equivalent request reuses the active session after policy re-evaluation rather than creating a duplicate. |
| SEC-031 | `POST /security/v1/device-enrollments` is a bootstrap endpoint authenticated by the configured USER identity token (Clerk in UAT/Production, DEV mock identity in permitted DEV). It does not require a Verigence Access Token and can create only PENDING enrollment state. |
| SEC-032 | Administrators can query Tenant activation readiness. The readiness response lists each prerequisite as PASS/FAIL and `POST .../activate` returns the same missing-item detail if activation cannot proceed. |
| SEC-033 | Phase 1 uses locally validated short-lived Security JWTs. Revoking an access session immediately blocks refresh/new issuance but an already-issued JWT remains cryptographically valid until `exp`; the maximum revocation window is therefore bounded by configured token TTL. Immediate pre-expiry revocation/introspection is not part of Phase 1. |
| SEC-034 | SYSTEM and SERVICE_INTEGRATION tokens are issued through a machine-access-token endpoint after client credential validation. Machine credentials are registered, status/validity controlled, stored only as non-reversible hashes, and independently rotatable. |
| SEC-035 | WhatsApp ingestion is represented as a SYSTEM principal. The WhatsApp adapter verifies the external webhook separately, then calls Verigence APIs using a Tenant-scoped SYSTEM token with only the required canonical permissions. |
| SEC-036 | JWKS rotation uses overlapping old/new public keys and unique `kid` values. New key is published before signing begins; old key remains published until all tokens signed with it have expired plus verifier cache/skew allowance. Verifiers refresh JWKS once on unknown `kid` before rejecting. |
| SEC-037 | Detailed access-context/session/security-event data is retained according to explicit Tenant Security retention policy. Retention periods are configuration, not hidden code defaults. An ACTIVE retention policy is required by Tenant activation readiness. `access_context_evaluations` is immutable while retained but may be deleted only by the controlled Security maintenance retention process after the configured period. |
| SEC-038 | Tenant offboarding is a controlled Security lifecycle. OFFBOARDING prevents new/refresh USER sessions and new machine-token issuance, revokes active Security sessions and machine Tenant scopes/credentials as applicable, and retains or purges Security-owned data only according to retention policy. Security does not delete DI/WPM-owned data. |
| SEC-039 | Geo is mandatory for USER access, but Phase 1 does not claim cryptographic proof against location spoofing. Explicit platform/runtime mock-location or spoof indicators, when available, are recorded as SUSPECTED and cause denial. When no integrity indicator is available, integrity is UNKNOWN and normal freshness/accuracy/assignment/radius checks continue. |
| SEC-040 | `X-Correlation-ID` is the Verigence end-to-end correlation header. Callers may supply a valid safe opaque value; if absent, the first Verigence service generates a UUIDv4. The same value is returned in the response and propagated unchanged across internal service calls, machine actors and supported provider adapters, and is recorded in structured logs/security evidence. Scheduled work generates a new correlation ID at execution start. `X-Correlation-ID` is distinct from any future trace/span identifier. |

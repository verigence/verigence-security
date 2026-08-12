# Verigence Security Operational Lifecycle v1.3

## Security retention
Detailed Security evidence is not retained indefinitely by default. Each Tenant must have an ACTIVE Security retention policy before Tenant activation. The architecture does not invent day counts.

`security_retention_policies` contains:
- `access_context_retention_days`
- `access_session_retention_days`
- `security_event_retention_days`

The Railway Security maintenance job purges eligible records in bounded batches. Records are immutable while retained. Each purge run emits a `SECURITY_RETENTION_PURGE` event with correlation ID and aggregate counts; raw deleted detail is not copied back into the event.

## Tenant offboarding
Tenant states are `CONFIGURING | ACTIVE | SUSPENDED | OFFBOARDING | OFFBOARDED`.

Offboarding is idempotent:
1. Mark Tenant `OFFBOARDING` transactionally.
2. Block all new USER access-session creation/refresh and all new machine-token issuance for the Tenant.
3. Mark ACTIVE access sessions REVOKED.
4. End machine principal Tenant scopes and revoke Tenant-specific machine credentials where the credential is Tenant-dedicated; shared principal credentials are not globally revoked unless explicitly requested.
5. Suspend/end Tenant memberships and Tenant-specific role/location assignments according to the offboarding application service.
6. Preserve/purge Security-owned data according to retention policy.
7. Mark `OFFBOARDED` after Security-owned offboarding steps complete.

Security does not delete DI/WPM-owned data. Platform-wide offboarding orchestration is outside this module.

Because Phase 1 uses locally validated short-lived JWTs (SEC-033), already-issued tokens remain cryptographically valid until `exp`; offboarding prevents refresh/new issuance immediately and bounds residual validity by configured token TTL.

## Geo integrity / spoofing
Phase 1 does not claim spoof-proof location attestation.

Security records:
- `geo_source = NATIVE | BROWSER`
- `geo_integrity_status = NORMAL | SUSPECTED | UNKNOWN`
- `geo_integrity_reason` nullable

Policy:
- Missing/stale/inaccurate/out-of-assigned-area geo -> DENY under existing rules.
- Explicit platform/runtime mock-location or spoof indication, when available -> `SUSPECTED` -> DENY with `GEO_INTEGRITY_FAILED`.
- No integrity indication available -> `UNKNOWN`; continue normal geo validation. `UNKNOWN` is not proof of spoofing.

The integrity signal is a risk indicator, not cryptographic attestation; therefore the design avoids claiming physical-presence proof.

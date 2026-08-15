# Verigence Security — Cross-Module Authentication Design

**Document ID:** VSEC-SD-INT-001  
**Version:** 1.0  
**Status:** APPROVED ARCHITECTURE INPUT  
**Date:** 2026-08-15  
**Initial consumer:** Verigence Audit Core -> Verigence Document Intelligence (DI)  
**Owner decision:** System integration for module-owned/admin execution; OAuth delegated authorization for user-driven business workflows

## 1. Purpose

Security is the authority that authenticates actors and issues the effective authorization context used between Verigence modules.

This design defines the Security capabilities required when Audit Core calls DI. The same pattern may be reused by other modules only where their own approved design requires it.

Security SHALL prevent two unsafe shortcuts:

1. a module minting its own downstream permissions or JWTs; and
2. a module using a privileged service identity to bypass the authorization of a user-driven business action.

## 2. Platform role and permission model

A Security role is a convenience bundle that may contain permissions belonging to multiple Verigence modules. Security SHALL resolve the user's Tenant-scoped role assignments and approved direct grants into one authoritative effective `permissions[]` set.

The normal Security user access token therefore represents the user's **effective platform authorization for that Tenant**, not authorization for only the first module the user calls.

For example, an approved PC role may resolve to a combination of Audit Core permissions plus DI permissions needed for PC activities performed indirectly through Audit Core. The exact PC/TL/PM/CRM/Executive permission names and contents belong to the canonical Security permission catalogue; this cross-module design does not invent them.

Rules:

- `roles[]` is informational/convenience metadata.
- `permissions[]` is authoritative for enforcement.
- Permission names SHALL be module/domain namespaced so each module can enforce only the permissions it owns.
- A module SHALL NOT need to understand another module's role definitions.
- Audit Core checks the Audit Core permission required for the incoming business action.
- If that business action requires DI, Audit Core asks Security for the specific downstream DI permission(s).
- The original platform token may contain permissions for several modules; the downstream DI token SHALL be narrowed and SHALL NOT simply copy the whole platform permission bundle.

This gives Security one canonical answer to what a user may do across the Verigence platform while retaining least privilege at each downstream call.

## 3. Two supported flows

### 3.1 System integration / service flow

Use this flow for module-owned administrative/system operations and for background continuation/retry of an operation that was already authorized and durably accepted under a user context.

```text
Audit Core workload
    -> Security system-integration authentication
    -> Security-issued short-lived SERVICE token
    -> DI
```

Security SHALL:

- authenticate the Audit Core workload/service identity;
- issue a short-lived downstream JWT with `actor_type=SERVICE` for Tenant-scoped DI work;
- include the applicable `tenant_id` for Tenant-scoped operations;
- issue only the downstream `permissions[]` assigned to the Audit Core integration identity and requested for the operation;
- audit service-token issuance and the requesting service identity;
- support revocation/rotation of the workload credential used to obtain tokens.

The service token SHALL NOT be used for a new PC/TL/PM/CRM/Executive workflow action merely because Audit Core is the module making the HTTP call.

### 3.2 OAuth delegated user flow

Use this flow when a user-driven synchronous business action requires Audit Core to call DI, including booking, delivery, evidence and review workflows.

The approved pattern is OAuth 2.0 delegated token exchange / on-behalf-of semantics:

```text
User -> Security user token -> Audit Core
Audit Core -> Security token exchange -> delegated downstream token
Audit Core -> DI with delegated downstream token
```

Security SHALL validate both the requesting Audit Core client/service and the subject user token before issuing a downstream token.

The downstream delegated token SHALL:

- preserve the initiating user in `sub`;
- preserve the Tenant in `tenant_id`;
- carry authoritative effective downstream `permissions[]`;
- identify Audit Core as the authorized calling/delegating client using the canonical Security delegation claim;
- be short-lived and suitable only for the downstream operation/context;
- not grant broader authority than the user and the Audit Core integration are jointly allowed to exercise.

Audit Core SHALL NOT need to store user refresh tokens or long-lived delegated credentials.

## 4. Permission calculation

For delegated issuance, Security SHALL calculate downstream authority as no broader than:

```text
user effective platform authority
INTERSECT Audit Core integration authority
INTERSECT requested downstream operation authority
```

A requested permission outside that result is denied.

This rule is essential for Audit Core. For example, a PC who may capture/upload evidence must not gain DI verification-write permission through token exchange unless Security has explicitly authorized that action for the user.

The downstream token carries only the requested/approved downstream subset, even though the subject user's original Security token may contain a larger platform permission bundle.

## 5. Background continuation

When a user-driven operation has already been authorized and Audit Core has durably accepted/committed it, later background polling, retry, recovery or processing continuation may use the Audit Core `SERVICE` identity.

This is a continuation of existing authorized work, not a new user authorization decision.

Security is not required to keep the original user access token alive for this purpose. Audit Core retains the initiating actor/correlation/operation linkage in its own durable audit metadata.

## 6. Fail-closed rules

Security SHALL NOT permit Audit Core to silently substitute a service token when delegated issuance for a new user-driven action is denied or unavailable.

If delegated token exchange is denied, the downstream operation is denied. If Security is unavailable, Audit Core handles the dependency failure according to its error/retry contract.

No direct shared API-key bypass between Audit Core and DI is part of this design.

## 7. JWT compatibility contract

The current DI implementation validates Security-issued JWTs through Security JWKS and currently expects:

- issuer: `verigence-security`;
- audience: `verigence-platform`;
- `sub`;
- `tenant_id` for Tenant-scoped tokens;
- `actor_type` supporting `USER`, `SERVICE`, `SYSTEM`;
- authoritative `permissions[]`;
- optional informational `roles[]` and existing session/device/location claims where applicable.

Security implementation SHALL remain compatible with that contract unless Security and DI deliberately version the contract together.

For delegated tokens, the canonical caller/delegation attribution is the OAuth token-exchange actor claim `act`, with `act.sub` identifying the requesting service/client (initially `audit-core`). DI may ignore the additional claim for authorization but it remains available for audit attribution.

## 8. Phase-1 token endpoint contract

Security SHALL expose one internal OAuth token endpoint for confidential module clients:

```text
POST /oauth/token
```

Phase 1 supports:

1. `grant_type=client_credentials` for module-owned/admin/background `SERVICE` tokens; and
2. `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with a Security user access token as `subject_token` for user-driven delegated calls.

The requesting module authenticates as a confidential client. For the initial Railway deployment, client credentials are supplied through managed environment secrets and HTTP Basic client authentication. No client secret is committed to source control. This is an implementation bootstrap mechanism, not a private Audit Core-to-DI bypass: Security validates the client and Security alone issues the downstream JWT.

Requested downstream permissions are supplied as OAuth `scope` values. Security denies the request if any requested scope is outside the permitted intersection; it does not silently elevate or substitute authority.

Security signs JWTs with RS256 using a managed private key and exposes the public key through:

```text
GET /.well-known/jwks.json
```

Role-to-permission bundles and module-integration permission bundles are configuration-driven in this first implementation so that no unapproved business permission catalogue is hard-coded.

## 9. Credential handling

Security owns the mechanism by which Audit Core proves its workload identity to obtain service or delegated tokens. The implementation must use managed secret/workload credentials and rotation; Audit Core must not contain a hard-coded shared credential.

The initial confidential-client secret and signing key are deployment secrets. A future workload-identity mechanism may replace the bootstrap credential without changing the token semantics defined here.

## 10. Required Security audit events

At minimum, Security SHALL retain safe audit records for:

- service-token issuance/denial;
- delegated token-exchange issuance/denial;
- requesting client/service identity;
- subject user for delegated exchange;
- Tenant;
- requested/effective permission set or permission-set reference;
- correlation/request identifier where available;
- issuance/expiry timestamps and outcome.

Raw bearer tokens and secrets SHALL NOT be logged.

## 11. Implementation dependency

This design creates Security implementation task `SEC-INT-001` in `docs/SECURITY_IMPLEMENTATION_TASKS.md`.

Audit Core G-01 cannot be implementation-complete until that Security task is implemented and a controlled Audit Core -> Security -> DI authentication test passes for both the service flow and delegated user flow.

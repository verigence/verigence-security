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

## 2. Two supported flows

### 2.1 System integration / service flow

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
- issue only the downstream `permissions[]` assigned to the Audit Core integration identity;
- audit service-token issuance and the requesting service identity;
- support revocation/rotation of the workload credential used to obtain tokens.

The service token SHALL NOT be used for a new PC/TL/PM/CRM/Executive workflow action merely because Audit Core is the module making the HTTP call.

### 2.2 OAuth delegated user flow

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
- identify Audit Core as the authorized calling/delegating client using the canonical Security delegation/authorized-party claim;
- be short-lived and suitable only for the downstream operation/context;
- not grant broader authority than the user and the Audit Core integration are jointly allowed to exercise.

Audit Core SHALL NOT need to store user refresh tokens or long-lived delegated credentials.

## 3. Permission calculation

For delegated issuance, Security SHALL calculate downstream authority as no broader than:

```text
user effective authority
INTERSECT Audit Core integration authority
INTERSECT requested downstream operation authority
```

A requested permission outside that result is denied.

This rule is essential for Audit Core. For example, a PC who may capture/upload evidence must not gain DI verification-write permission through token exchange unless Security has explicitly authorized that action for the user.

Roles may remain informational/convenience bundles; `permissions[]` is authoritative for enforcement.

## 4. Background continuation

When a user-driven operation has already been authorized and Audit Core has durably accepted/committed it, later background polling, retry, recovery or processing continuation may use the Audit Core `SERVICE` identity.

This is a continuation of existing authorized work, not a new user authorization decision.

Security is not required to keep the original user access token alive for this purpose. Audit Core retains the initiating actor/correlation/operation linkage in its own durable audit metadata.

## 5. Fail-closed rules

Security SHALL NOT permit Audit Core to silently substitute a service token when delegated issuance for a new user-driven action is denied or unavailable.

If delegated token exchange is denied, the downstream operation is denied. If Security is unavailable, Audit Core handles the dependency failure according to its error/retry contract.

No direct shared API-key bypass between Audit Core and DI is part of this design.

## 6. JWT compatibility contract

The current DI implementation validates Security-issued JWTs through Security JWKS and currently expects:

- issuer: `verigence-security`;
- audience: `verigence-platform`;
- `sub`;
- `tenant_id` for Tenant-scoped tokens;
- `actor_type` supporting `USER`, `SERVICE`, `SYSTEM`;
- authoritative `permissions[]`;
- optional informational `roles[]` and existing session/device/location claims where applicable.

Security implementation SHALL remain compatible with that contract unless Security and DI deliberately version the contract together.

For delegated tokens, Security SHALL additionally define one canonical caller/delegation attribution claim. The implementation may use the standard OAuth/JWT authorized-party/actor representation, but the selected claim must be documented once and emitted consistently.

## 7. Credential handling

Security owns the mechanism by which Audit Core proves its workload identity to obtain service or delegated tokens. The implementation must use managed secret/workload credentials and rotation; Audit Core must not contain a hard-coded shared credential.

Exact token TTLs, credential bootstrap mechanism and endpoint paths belong to the Security implementation/API contract and are not invented in Audit Core.

## 8. Required Security audit events

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

## 9. Implementation dependency

This design creates Security implementation task `SEC-INT-001` in `docs/SECURITY_IMPLEMENTATION_TASKS.md`.

Audit Core G-01 cannot be implementation-complete until that Security task is implemented and a controlled Audit Core -> Security -> DI authentication test passes for both the service flow and delegated user flow.

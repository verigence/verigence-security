# Verigence Security — Cross-Module Authentication Design

**Document ID:** VSEC-SD-INT-001  
**Version:** 1.2  
**Status:** APPROVED ARCHITECTURE INPUT  
**Date:** 2026-08-15  
**Updated:** 2026-08-16  
**Initial consumer:** Verigence Audit Core -> Verigence Document Intelligence (DI)  
**Owner decision:** Security owns the complete Verigence authentication/OAuth lifecycle; modules are OAuth clients; system integration is used for module-owned/admin execution and OAuth delegation is used for user-driven downstream workflows

## 1. Purpose

Security is the authority that authenticates actors and issues the effective authorization context used between Verigence modules.

This design defines both:

1. the user-facing authentication/OAuth boundary through which Verigence modules obtain a Security user token; and
2. the downstream service/delegated token flows used when one Verigence module calls another.

Security SHALL prevent three unsafe shortcuts:

1. a module implementing its own independent Verigence authentication/authorization authority;
2. a module minting its own downstream permissions or JWTs; and
3. a module using a privileged service identity to bypass the authorization of a user-driven business action.

## 2. Security ownership boundary

Security owns the complete Verigence authentication and OAuth authorization lifecycle.

Verigence business modules such as Audit Core are OAuth clients of Security. They do not implement password/identity-provider logic, role resolution, permission calculation, JWT signing or token issuance.

Security owns the canonical endpoints/behaviours for:

```text
/auth/login
/auth/callback
/auth/logout
/session
/oauth/authorize
/oauth/token
/.well-known/jwks.json
```

The exact HTTP payloads and session-storage mechanism are implementation contracts and may be versioned independently, but ownership does not move out of Security.

An upstream identity provider such as Clerk may be used by Security to perform primary human authentication, MFA, SSO or social login. That provider is behind the Security boundary: other Verigence modules SHALL NOT need Clerk-specific validation or Clerk-specific authorization logic.

The browser/mobile client may be redirected through Security for the normal OAuth authorization flow, but privileged token operations and confidential-client credentials SHALL NOT be exposed to browser JavaScript.

A module may have its own OAuth redirect/callback endpoint solely to receive an authorization code from Security. That callback does not authenticate the user or calculate permissions; it completes the module's OAuth-client flow with Security.

## 3. Initial user authentication and Verigence session

The approved initial user flow is the standard OAuth authorization-code model with Security acting as the Verigence Authorization Server and authentication broker.

Conceptually:

```text
User
  -> Verigence module
  -> Security /oauth/authorize
  -> Security /auth/login when no valid Security session exists
  -> upstream IdP through Security when required
  -> Security /auth/callback
  -> Security resolves Verigence user + Tenant membership + roles + effective permissions
  -> Security establishes/uses the Verigence authentication session
  -> Security returns an authorization code to the registered module redirect URI
  -> module backend exchanges the code at Security /oauth/token
  -> Security issues the Verigence USER access token
```

Rules:

- Security is the only Verigence component that turns an authenticated human identity into a Verigence user authorization context.
- The module SHALL NOT submit trusted `roles[]` or `permissions[]` for Security to copy into a token.
- Security SHALL resolve the Verigence user, permitted Tenant membership, role assignments and approved direct grants from authoritative Security-owned data/configuration.
- Security SHALL resolve role templates for the selected Tenant and calculate authoritative `permissions[]` before issuing a USER token.
- A requested/selected Tenant must be validated against the authenticated user's membership; the caller cannot self-assert Tenant access.
- `/auth/logout` terminates the applicable Security authentication session. Already-issued short-lived access tokens are not silently extended by that session and expire according to their own `exp`; a separate token-revocation mechanism is not introduced by this design.
- `/session` reports the applicable Security authentication/session state without becoming an authorization bypass.
- Public clients that cannot safely hold a secret SHALL use the approved authorization-code protection mechanism (PKCE); confidential module backends authenticate according to the registered OAuth-client contract.

## 4. Platform role and permission model

A Security role is a convenience bundle that may contain permissions belonging to multiple Verigence modules. Security SHALL resolve the user's Tenant-scoped role assignments and approved direct grants into one authoritative effective `permissions[]` set.

The normal Security user access token therefore represents the user's **effective platform authorization for that Tenant**, not authorization for only the first module the user calls.

For example, an approved PC role may resolve to a combination of Audit Core permissions plus DI permissions needed for PC activities performed indirectly through Audit Core. The approved PC/TL/PM/CRM defaults are defined in the canonical Security role-template design and remain Tenant-customizable under the approved administration rules.

Rules:

- `roles[]` is informational/convenience metadata.
- `permissions[]` is authoritative for enforcement.
- Permission names SHALL be module/domain namespaced so each module can enforce only the permissions it owns.
- A module SHALL NOT need to understand another module's role definitions.
- Audit Core checks the Audit Core permission required for the incoming business action.
- If that business action requires DI, Audit Core asks Security for the specific downstream DI permission(s).
- The original platform token may contain permissions for several modules; the downstream DI token SHALL be narrowed and SHALL NOT simply copy the whole platform permission bundle.

This gives Security one canonical answer to what a user may do across the Verigence platform while retaining least privilege at each downstream call.

## 5. Downstream OAuth/service flows

### 5.1 System integration / service flow

Use this flow for module-owned administrative/system operations and for background continuation/retry of an operation that was already authorized and durably accepted under a user context.

```text
Audit Core workload
    -> Security /oauth/token using client_credentials
    -> Security-issued short-lived SERVICE token
    -> DI
```

Security SHALL:

- authenticate the Audit Core workload/service identity as a registered confidential OAuth client;
- require a Security-known active Tenant for Tenant-scoped service issuance rather than signing an arbitrary caller-supplied Tenant string;
- issue a short-lived downstream JWT with `actor_type=SERVICE` for Tenant-scoped DI work;
- include the applicable `tenant_id` for Tenant-scoped operations;
- issue only the downstream `permissions[]` assigned to the Audit Core integration identity and requested for the operation;
- audit service-token issuance/denial and the requesting service identity;
- support revocation/rotation of the workload credential used to obtain tokens.

A typical Tenant-scoped SERVICE token therefore identifies the caller in `sub` (for example `audit-core`), the Tenant in `tenant_id`, `actor_type=SERVICE`, and only the requested approved downstream `permissions[]`.

The service token SHALL NOT be used for a new PC/TL/PM/CRM/Executive workflow action merely because Audit Core is the module making the HTTP call.

### 5.2 OAuth delegated user flow

Use this flow when a user-driven synchronous business action requires Audit Core to call DI, including booking, delivery, evidence and review workflows.

The approved pattern is OAuth 2.0 delegated token exchange / on-behalf-of semantics:

```text
User -> Security USER token -> Audit Core
Audit Core -> Security token exchange -> delegated downstream token
Audit Core -> DI with delegated downstream token
```

Security SHALL validate both the requesting Audit Core client/service and the subject Security user token before issuing a downstream token.

The downstream delegated token SHALL:

- preserve the initiating user in `sub`;
- preserve the Tenant in `tenant_id`;
- carry authoritative effective downstream `permissions[]`;
- identify Audit Core as the authorized calling/delegating client using the canonical Security delegation claim;
- be short-lived and suitable only for the downstream operation/context;
- not grant broader authority than the user and the Audit Core integration are jointly allowed to exercise.

Audit Core SHALL NOT need to store user refresh tokens or long-lived delegated credentials for downstream DI delegation.

## 6. Permission calculation

For delegated issuance, Security SHALL calculate downstream authority as no broader than:

```text
user effective platform authority
INTERSECT Audit Core integration authority
INTERSECT requested downstream operation authority
```

A requested permission outside that result is denied.

This rule is essential for Audit Core. For example, a PC who may capture/upload evidence must not gain DI verification-write permission through token exchange unless Security has explicitly authorized that action for the user.

The downstream token carries only the requested/approved downstream subset, even though the subject user's original Security token may contain a larger platform permission bundle.

For `client_credentials`, the equivalent least-privilege rule is:

```text
registered integration-client authority
INTERSECT requested downstream operation authority
```

and the requested Tenant must also be known/active in Security for Tenant-scoped issuance.

## 7. Background continuation

When a user-driven operation has already been authorized and Audit Core has durably accepted/committed it, later background polling, retry, recovery or processing continuation may use the Audit Core `SERVICE` identity.

This is a continuation of existing authorized work, not a new user authorization decision.

Security is not required to keep the original user access token alive for this purpose. Audit Core retains the initiating actor/correlation/operation linkage in its own durable audit metadata.

## 8. Fail-closed rules

Security SHALL NOT permit Audit Core to silently substitute a service token when delegated issuance for a new user-driven action is denied or unavailable.

If delegated token exchange is denied, the downstream operation is denied. If Security is unavailable, Audit Core handles the dependency failure according to its error/retry contract.

No direct shared API-key bypass between Audit Core and DI is part of this design.

A Verigence module SHALL NOT bypass Security by accepting an upstream IdP token as sufficient Verigence authorization unless a separately approved Security design explicitly introduces such a contract.

## 9. Resource-module token validation contract

Resource modules such as DI SHALL validate Security-issued access tokens locally using Security's published JWKS. Security is not called synchronously for every protected API request.

For a Security JWT, a resource module SHALL fail closed unless all applicable checks pass:

- the JWT signature validates against the Security JWKS key identified by `kid` using the approved signing algorithm;
- `iss` is the approved Security issuer;
- `aud` contains/is the approved Verigence platform/resource audience;
- `exp` is valid and the token is not expired;
- `sub` is present;
- Tenant-scoped USER/SERVICE operations contain a valid `tenant_id` and the request is constrained to that Tenant;
- `actor_type` is recognized for the endpoint/context;
- authoritative `permissions[]` contains the permission required by the resource operation.

`roles[]` remains informational and SHALL NOT replace `permissions[]` enforcement in the resource module.

A resource module does not need the calling module's OAuth client secret. The confidential client credential is used only between the calling module and Security; the resource module needs the Security trust configuration/JWKS and its own permission checks.

For delegated tokens, `act.sub` identifies the calling/delegating module for audit attribution while `sub` remains the initiating user. For SERVICE tokens, `sub` identifies the service/client itself.

## 10. JWT compatibility contract

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

## 11. OAuth token endpoint contract

Security SHALL expose:

```text
POST /oauth/token
```

The approved OAuth responsibilities are:

1. `grant_type=authorization_code` for the initial module OAuth flow after Security-owned user authentication/authorization;
2. `grant_type=client_credentials` for module-owned/admin/background `SERVICE` tokens; and
3. `grant_type=urn:ietf:params:oauth:grant-type:token-exchange` with a Security USER access token as `subject_token` for user-driven delegated downstream calls.

The requesting confidential module authenticates as a registered OAuth client. For the initial Railway deployment, confidential-client credentials may be supplied through managed environment secrets and HTTP Basic client authentication. No client secret is committed to source control.

Requested downstream permissions for service/delegated flows are supplied as OAuth `scope` values. Security denies the request if any requested scope is outside the permitted authority; it does not silently elevate or substitute authority.

Security signs JWTs with RS256 using a managed private key and exposes the public key through:

```text
GET /.well-known/jwks.json
```

## 12. Credential and session handling

Security owns:

- the mechanism by which a module proves its OAuth-client/workload identity;
- Security's upstream IdP credentials/configuration;
- Security signing keys;
- Security authentication/session state and its expiry/termination rules;
- OAuth authorization-code issuance/validation; and
- service/delegated token issuance.

Managed secrets and rotation are required. Modules must not contain a hard-coded shared credential.

Raw session tokens and authorization codes SHALL be stored only in non-recoverable/hash form where Security persists them. Authorization codes are short-lived and single-use.

A future workload-identity mechanism may replace bootstrap client secrets without changing the token semantics defined here.

## 13. Required Security audit events

At minimum, Security SHALL retain safe audit records for:

- interactive login success/denial;
- logout/session termination where applicable;
- authorization-code issuance/denial;
- authorization-code token exchange success/denial;
- service-token issuance/denial;
- delegated token-exchange issuance/denial;
- requesting client/service identity;
- subject user for user/delegated flows;
- Tenant;
- requested/effective permission set or permission-set reference;
- correlation/request identifier where available;
- issuance/expiry timestamps and outcome.

Raw bearer tokens, authorization codes, session secrets and client secrets SHALL NOT be logged.

## 14. Implementation dependencies

`SEC-INT-001` is the completed implementation for platform permission JWTs, `client_credentials`, JWKS and downstream delegated token exchange.

`SEC-RBAC-001` is the completed implementation for the default PC/TL/PM/CRM cross-module role templates and Tenant customization.

`SEC-AUTH-001` implements the Security-owned interactive authentication/session and OAuth authorization-code flow, including persisted Verigence user/Tenant membership and Clerk as the configured upstream identity provider behind Security.

`SEC-DEPLOY-001` remains the operational gate: the current verified code, database schema and managed deployment configuration must be present in DEV and the live OAuth/authentication flows must be proven before Audit Core cross-module DEV readiness is closed.

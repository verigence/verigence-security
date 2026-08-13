# Phase 3 — Railway DEV Validation

**Status:** DONE  
**Date:** 2026-08-13  
**Environment:** Railway DEV + Neon DEV  
**Repository:** `verigence/verigence-security`

## Objective

Prove that the Security service can run end-to-end in DEV on Railway against the approved Neon Security schema without Clerk or another external authentication hook.

## Deployment evidence

- Railway project: `a6808842-2e90-44f8-9172-63a905b24b5c`
- Railway DEV environment: `09e12bb5-9781-4b01-974b-fde54d01e37c`
- Railway service: `cfc90262-4b33-419d-a874-4592de9e8db1`
- Environment-specific service instance was established and validated.
- Exact immutable GHCR image deployment was proven using the Railway environment service-instance `source.image` configuration.
- Initial exact-image deployment `c7f10093-378a-46ab-825c-23656ef853cb` reached `SUCCESS` with runtime instance `RUNNING`.
- Runtime configuration redeployment `68729a4c-c323-412c-999d-326248bea34c` reached `SUCCESS`.

The permanent DEV deployment workflow now follows this proven sequence:

```text
Security CI for exact dev SHA
        ↓
Docker build in GitHub Actions
        ↓
GHCR immutable sha256 digest
        ↓
Railway DEV environment service-instance source.image = exact digest
        ↓
Railway creates latestDeployment
        ↓
latestDeployment SUCCESS
        ↓
/health/ready
        ↓
/health/live
        ↓
X-Correlation-ID verification
```

Railway autodeploy/build is not used as the source of the application artifact. GitHub Actions builds the artifact and Railway runs the exact immutable image reference.

## Runtime configuration validation

GitHub Actions run `31668584825` configured the DEV runtime without printing secret values and validated the resulting deployment.

Validated runtime configuration included:

- DEV environment mode;
- Neon runtime database URL sourced from the existing GitHub database secret;
- Security RSA signing private/public keys;
- Security token issuer/audience/key ID;
- DEV mock-auth adapter with an explicit DEV-only signing secret and TTL;
- mock network-risk adapter with `NOT_DETECTED` response;
- trusted Railway ingress IP header.

Run `31668584825` proved:

```text
Railway runtime deployment: 68729a4c-c323-412c-999d-326248bea34c
/health/ready: PASS
  databaseReady: true
  signingKeyReady: true
/health/live: PASS
X-Correlation-ID over HTTPS: PASS
```

## Deployed USER end-to-end validation

GitHub Actions run `31668795264` validated the real deployed application path using temporary, approved-shape Neon fixture data.

The test sequence was:

```text
Temporary ACTIVE Tenant / USER / membership / device
        ↓
Tenant policy + location + active schedule context
        ↓
Tenant role mapped to canonical di.document.upload permission
        ↓
POST /security/v1/dev/mock-auth/token
        ↓
DEV mock identity token
        ↓
POST /security/v1/access-sessions
        ↓
Railway-hosted Security API
        ↓
Neon-backed Tenant/device/geo/schedule/network/RBAC evaluation
        ↓
Security USER access token returned
        ↓
response Tenant/device/location/role/permission validated
        ↓
fixture removed from Neon
```

Validated response properties included:

- `actorType = USER`;
- expected Tenant ID;
- expected registered device ID;
- expected matched location ID;
- expected temporary Tenant role;
- canonical `di.document.upload` permission;
- non-empty Security access-session ID;
- non-empty Security access token;
- exact `X-Correlation-ID` preservation.

Fixture cleanup completed successfully in the same run.

## Security handling

- Railway tokens, Neon credentials, RSA private key material and DEV mock signing secret were not committed to source.
- Secret values were not intentionally printed by the validation workflows.
- The runtime bootstrap used repository GitHub Secrets and Railway environment configuration.
- DEV-only mock authentication/network behavior remains prohibited by application safety rules in UAT/Production.

## Phase 3 exit criterion

> Security API runs end-to-end in DEV on Railway against Neon without external authentication hooks.

**Result: PASS. Phase 3 is complete.**

# Verigence Security — Build, Test & Deployment Policy

**Status:** Mandatory engineering policy for Security implementation and delivery  
**Applies to:** `verigence/verigence-security`  
**Design authority:** Approved Security v1.3 artifacts and recorded design decisions  
**Integration branch:** `dev`  
**Stable/release branch:** `main`

---

## 1. Purpose

This document defines the minimum engineering discipline required before any Verigence Security implementation increment, build or deployment can be called complete or ready.

The governing lifecycle is:

```text
DESIGN
  ↓
CODE
  ↓
AUTOMATED TESTS
  ↓
IMMUTABLE BUILD
  ↓
GITHUB ACTIONS DEPLOYMENT
  ↓
POST-DEPLOYMENT VALIDATION
  ↓
DONE
```

A phase, feature or release is **not DONE** merely because code exists or because a deployment starts successfully.

A build is **not READY** while any applicable mandatory gate is failing, skipped without an approved reason, or not yet implemented.

This policy does not replace Security Design v1.3. If this document conflicts with an approved Security design artifact, the approved design wins.

---

## 2. Non-negotiable engineering rules

### 2.1 Design is the implementation reference

All implementation and tests must be derived from the approved Security design/decision artifacts.

Do not invent APIs, fields, permission names, error codes, statuses, database objects, thresholds, provider behavior, lifecycle states or security rules merely to make implementation or tests pass.

If the approved design does not deterministically answer a required implementation question:

1. record the gap;
2. mark the affected capability `BLOCKED`, `PARTIAL` or `OPEN DESIGN DECISION`;
3. do not implement an assumed business/security behavior;
4. obtain and record an approved decision before completing that behavior.

### 2.2 File changes require task justification

Do not create, edit, move or delete repository files unless the current approved task explicitly requires the change.

Before committing, the PR diff must be reviewed to confirm that only task-required files changed.

Unrelated cleanup, opportunistic refactoring or documentation rewriting must not be bundled into an implementation increment unless separately authorized.

### 2.3 Feature work must use controlled branch promotion

Normal implementation flow is:

```text
feature/* or docs/*
      ↓
Pull Request
      ↓
dev
      ↓
reviewed release promotion
      ↓
main
```

Unfinished implementation must not be pushed directly to `main`.

### 2.4 Deployment is GitHub-Actions-only

Application and controlled environment deployments must be initiated and executed through approved GitHub Actions workflows.

Manual deployment through Railway UI/CLI, developer workstation commands or ad-hoc scripts is not an accepted release process.

A deployment workflow must depend on the required build/test gates. If a mandatory gate fails, the deployment job must not proceed.

### 2.5 Build once; promote the same immutable artifact

The target deployment model is **build once, promote the same immutable artifact**.

When container/image deployment is introduced:

- a successful CI workflow builds one versioned immutable artifact;
- the artifact is identified by an immutable digest/SHA;
- DEV, UAT and Production promotion must use that same artifact digest;
- environment-specific configuration and secrets remain external to the artifact;
- UAT/Production must not silently rebuild source into a different binary/image.

Until immutable container/image publication is implemented, a Security build cannot claim this part of the production-readiness policy is complete.

### 2.6 Secrets never belong in source or build artifacts

Live credentials, database URLs, Clerk secrets, signing private keys and provider secrets must be supplied through approved secret stores such as GitHub Actions/Railway environment secrets.

They must not be committed to source, embedded in container images, printed in workflow logs or copied into test evidence.

### 2.7 Fail closed

Security quality, migration, readiness and deployment gates must fail closed.

Unknown or incomplete validation must not be converted into PASS merely to continue a build or deployment.

### 2.8 DONE requires evidence

A capability or phase may be marked DONE only when applicable evidence exists for:

- approved design traceability;
- code review;
- automated tests;
- static/design-integrity checks;
- database/infrastructure validation where relevant;
- successful immutable build where relevant;
- GitHub Actions deployment where relevant;
- post-deployment validation where relevant.

---

## 3. Current enforcement versus required target state

This section records what is actually enforced today so that the policy does not claim controls that do not yet exist.

### 3.1 Currently enforced by `.github/workflows/ci.yml`

The current Security CI workflow runs on PRs to `dev`/`main`, pushes to `dev`, and manual dispatch. It currently enforces:

- Python 3.12 setup;
- approved design/static safety checks through `scripts/ci_static_checks.py`;
- Python compilation;
- Ruff;
- Mypy;
- Pytest;
- Python package build;
- dependency consistency through `pip check`.

These are mandatory pre-merge quality gates.

### 3.2 Currently enforced by `.github/workflows/neon-dev-schema.yml`

The current Neon workflow validates the approved Security v1.3 PostgreSQL baseline against Neon DEV and includes:

- secure database-secret resolution;
- approved migration SHA-256 verification;
- fail-closed detection of empty/complete/partial schema state;
- transactional application of the approved migration when required;
- exact Security table-set validation;
- expected index validation;
- foreign-key and CHECK-constraint validation;
- real PostgreSQL repository integration tests.

### 3.3 Not yet implemented — therefore not yet claimable

The following policy controls are mandatory targets but are not yet implemented as of this baseline:

- Railway deployment through GitHub Actions;
- immutable container/image publication and digest-based promotion;
- automated DEV post-deployment smoke tests;
- deployed end-to-end USER access-session test;
- UAT promotion workflow;
- Production promotion workflow;
- automated rollback/promotion policy based on immutable artifact digest.

They must be implemented and validated before the corresponding readiness claim is made.

---

## 4. Standard delivery pipeline

Every implementation phase should converge on the following pipeline.

### Gate A — Design integrity

Before implementation is considered reviewable:

- applicable approved v1.3 artifact is identified;
- new behavior is traceable to an approved requirement/decision;
- open design questions are recorded rather than assumed;
- normative approved artifacts have not been silently modified.

**Failure result:** STOP.

### Gate B — Source quality

Required checks:

- compilation;
- lint;
- strict/static typing as configured;
- secret/static safety scans;
- package/dependency consistency;
- PR diff limited to authorized scope.

**Failure result:** STOP.

### Gate C — Automated behavior tests

Run all applicable unit, API and negative tests for the changed behavior.

Tests must prove both allowed and denied paths. Security tests that only exercise happy paths are insufficient.

**Failure result:** STOP.

### Gate D — Real infrastructure integration

Where the change depends on PostgreSQL, identity/provider adapters, deployment environment or other infrastructure, run applicable integration tests against the approved DEV implementation.

**Failure result:** STOP.

### Gate E — Immutable build

Build one deployment artifact from the exact tested commit.

The future container/image implementation must publish an immutable digest that becomes the promotion identity.

**Failure result:** STOP.

### Gate F — DEV deployment through GitHub Actions

Deploy only after Gates A-E pass.

No manual Railway deployment is accepted as release evidence.

**Failure result:** STOP.

### Gate G — Post-deployment validation

Validate the deployed service over its real HTTPS endpoint, including health/readiness and applicable end-to-end Security behavior.

**Failure result:** deployment is NOT READY and must not be promoted.

### Gate H — Promotion

Only a build that passed all applicable prior gates may be promoted.

When immutable artifacts are implemented, UAT/Production promotion must use the same digest that passed prior environment validation.

---

## 5. Build acceptance matrix — current Security module

### Status meanings

- **NOW** — applicable to the currently implemented Security baseline and should be automated/executed before the current build is called ready.
- **DEPLOYMENT PHASE** — becomes mandatory as soon as Railway DEV deployment is introduced.
- **FUTURE CAPABILITY** — mandatory when the approved feature exists; must not be faked or marked PASS before implementation.
- **BLOCKED BY DESIGN** — no completion test may be invented until the recorded design gap is resolved.

A mandatory applicable test has only two release outcomes: **PASS** or **BUILD NOT READY**.

### 5.1 Design, source and build integrity

| ID | Applicability | Test | Expected result |
|---|---|---|---|
| SEC-BLD-001 | NOW | Approved normative artifact hash verification | All approved v1.3 copies match recorded hashes |
| SEC-BLD-002 | NOW | Secret/private-key scan | No live DB URL, provider secret, Clerk secret or private signing key in source |
| SEC-BLD-003 | NOW | Legacy permission scan | Runtime source does not introduce deprecated colon-style permissions |
| SEC-BLD-004 | NOW | Python compile | `src`, `tests` and CI scripts compile successfully |
| SEC-BLD-005 | NOW | Ruff | Zero blocking lint errors |
| SEC-BLD-006 | NOW | Mypy | Zero blocking configured type errors |
| SEC-BLD-007 | NOW | Automated regression suite | All committed applicable tests pass |
| SEC-BLD-008 | NOW | Package build | Clean package build succeeds |
| SEC-BLD-009 | NOW | Dependency consistency | `pip check` succeeds |
| SEC-BLD-010 | NOW | Authorized-diff review | PR contains only files required by the approved task |
| SEC-BLD-011 | DEPLOYMENT PHASE | Immutable deployment build | One image/artifact created from exact tested commit |
| SEC-BLD-012 | DEPLOYMENT PHASE | Artifact identity | Immutable digest/SHA recorded as deployment identity |
| SEC-BLD-013 | FUTURE CAPABILITY | Environment promotion | Same immutable digest promoted DEV → UAT → Production |

### 5.2 Neon/PostgreSQL integrity

| ID | Applicability | Test | Expected result |
|---|---|---|---|
| SEC-DB-001 | NOW | Neon connectivity from controlled workflow | Connection succeeds using secret; secret value is not printed |
| SEC-DB-002 | NOW | Security schema existence | `security` schema exists |
| SEC-DB-003 | NOW | Approved table baseline | Exact approved table-name set exists; current v1.3 baseline contains 27 tables |
| SEC-DB-004 | NOW | Explicit index validation | All explicit indexes declared by approved migration exist |
| SEC-DB-005 | NOW | Foreign-key validation | Approved FK structure/count derived from migration is present |
| SEC-DB-006 | NOW | CHECK-constraint validation | Approved CHECK structure/count derived from migration is present |
| SEC-DB-007 | NOW | Repository user context read | Tenant/user context loads correctly from real PostgreSQL |
| SEC-DB-008 | NOW | Device row-lock concurrency | `SELECT ... FOR UPDATE` serializes competing device access |
| SEC-DB-009 | NOW | Invalid actor type | DB rejects actor type outside USER/SYSTEM/SERVICE_INTEGRATION |
| SEC-DB-010 | NOW | USER/principal integrity | USER row without required Security Principal relationship is rejected |
| SEC-DB-011 | NOW | Partial/drifted baseline handling | Workflow fails closed and does not silently rewrite approved schema |

### 5.3 Authentication and environment safety

| ID | Applicability | Test | Expected result |
|---|---|---|---|
| SEC-AUTH-001 | NOW | Valid DEV mock identity | Existing eligible Security USER can authenticate through DEV mock boundary |
| SEC-AUTH-002 | NOW | Caller privilege injection attempt | Caller cannot inject roles, permissions, Tenant authorization or `actor_type` |
| SEC-AUTH-003 | NOW | Mock authentication enabled in Production mode | Application startup is refused |
| SEC-AUTH-004 | NOW | Mock network-risk adapter enabled in Production mode | Application startup is refused |
| SEC-AUTH-005 | NOW | Invalid/expired identity token | Request denied; no Security access token issued |
| SEC-AUTH-006 | FUTURE CAPABILITY | Live Clerk identity verification | Valid Clerk identity maps to the registered Verigence USER without changing downstream authorization rules |
| SEC-AUTH-007 | FUTURE CAPABILITY | Clerk failure/invalid token | Access denied without privilege fallback |

### 5.4 Tenant isolation and membership

| ID | Applicability | Test | Expected result |
|---|---|---|---|
| SEC-TEN-001 | NOW | Active USER membership in requested Tenant | Access evaluation continues |
| SEC-TEN-002 | NOW | USER lacks requested Tenant membership | Access denied |
| SEC-TEN-003 | NOW | One USER belongs to multiple Tenants | Effective authorization is evaluated independently per Tenant |
| SEC-TEN-004 | NOW | Cross-Tenant RBAC leakage | Tenant A role/permission is not included in Tenant B token/context |
| SEC-TEN-005 | NOW | Cross-Tenant device context | Device is not treated as authorized for another Tenant unless independently valid there |

### 5.5 Device controls

| ID | Applicability | Test | Expected result |
|---|---|---|---|
| SEC-DEV-001 | NOW | ACTIVE registered USER device | Device gate passes and evaluation continues |
| SEC-DEV-002 | NOW | Unknown device used for normal access-session creation | Normal access is denied; unknown device is not silently promoted to ACTIVE |
| SEC-DEV-003 | NOW | Inactive/blocked/revoked device | Access denied |
| SEC-DEV-004 | FUTURE CAPABILITY | Device enrollment bootstrap | Configured USER identity token can create PENDING enrollment only |
| SEC-DEV-005 | FUTURE CAPABILITY | Enrollment without valid USER identity | Enrollment denied |
| SEC-DEV-006 | FUTURE CAPABILITY | Device approval | Only approved administrative path can transition eligible PENDING device |
| SEC-DEV-007 | FUTURE CAPABILITY | Active device limit concurrency | Concurrent enroll/approval cannot exceed approved Tenant/user device limit |

### 5.6 Geo/location controls

| ID | Applicability | Test | Expected result |
|---|---|---|---|
| SEC-GEO-001 | NOW | Missing geo for USER access | Access denied |
| SEC-GEO-002 | NOW | Stale geo | Denied according to configured Tenant threshold; no hidden code default |
| SEC-GEO-003 | NOW | Accuracy outside configured threshold | Access denied |
| SEC-GEO-004 | NOW | Geo outside assigned location radius | Access denied |
| SEC-GEO-005 | NOW | Geo inside an explicitly assigned active location | Geo gate passes |
| SEC-GEO-006 | NOW | Explicit spoof/mock-location signal | Integrity marked SUSPECTED and access denied |
| SEC-GEO-007 | NOW | Platform supplies no spoof-integrity signal | Integrity remains UNKNOWN; normal geo checks continue; no false spoof claim |
| SEC-GEO-008 | FUTURE CAPABILITY | USER access-session refresh without fresh geo | `GEO_REQUIRED` behavior as approved |
| SEC-GEO-009 | FUTURE CAPABILITY | USER refresh with fresh valid geo | Refresh continues through full applicable policy evaluation |

### 5.7 Time-window controls

| ID | Applicability | Test | Expected result |
|---|---|---|---|
| SEC-TIME-001 | NOW | Request inside allowed location schedule | Schedule gate passes |
| SEC-TIME-002 | NOW | Request outside allowed schedule | Access denied |
| SEC-TIME-003 | NOW | Overnight schedule crossing midnight | Evaluation remains correct across day boundary |
| SEC-TIME-004 | NOW | Location timezone usage | Schedule evaluation uses approved location timezone semantics |

### 5.8 Network/VPN policy

| ID | Applicability | Test | Expected result |
|---|---|---|---|
| SEC-NET-001 | NOW | Network-risk adapter returns allowed context | Evaluation continues |
| SEC-NET-002 | NOW | Adapter returns detected/unknown risk | Configured Tenant policy outcome is applied; no hidden threshold/default |
| SEC-NET-003 | NOW | Network provider invocation ordering | External provider call does not occur while device DB row lock/transaction is held |
| SEC-NET-004 | FUTURE CAPABILITY | Production network-risk adapter | Selected approved provider obeys same provider-neutral Security contract |

### 5.9 RBAC and permissions

| ID | Applicability | Test | Expected result |
|---|---|---|---|
| SEC-RBAC-001 | NOW | Effective authorized permission | Canonical Tenant-scoped permission appears in issued Security token/context |
| SEC-RBAC-002 | NOW | Required authorization missing | Access denied; permission is not inferred |
| SEC-RBAC-003 | NOW | Canonical permission syntax | Value such as `di.document.upload` is accepted where granted |
| SEC-RBAC-004 | NOW | Legacy colon-style permission | Deprecated value such as `document:upload` is not issued as canonical Security permission |
| SEC-RBAC-005 | BLOCKED BY DESIGN | Exact administration endpoint permission catalogue | Do not invent `security.*` endpoint permissions before approved catalogue exists |

### 5.10 USER access-session behavior

| ID | Applicability | Test | Expected result |
|---|---|---|---|
| SEC-SES-001 | NOW | Valid new USER access-session request | One ACTIVE session/evidence result is persisted and Security JWT issued |
| SEC-SES-002 | NOW | Equivalent request for same Tenant + USER + device | Existing active session may be reused only according to approved policy re-evaluation semantics |
| SEC-SES-003 | NOW | Concurrent equivalent requests | Database serialization prevents duplicate active USER sessions for same Tenant + USER + device |
| SEC-SES-004 | NOW | Existing session with conflicting location context | Conflict is rejected rather than silently changing active session context |
| SEC-SES-005 | NOW | Reused session token expiry | Reuse cannot extend beyond original configured session maximum |
| SEC-SES-006 | NOW | JWT signing fails after policy evaluation | Uncommitted session/evidence DB transaction rolls back |
| SEC-SES-007 | BLOCKED BY DESIGN | Cross-replica `Idempotency-Key` replay | Do not claim until persistent idempotency model is approved and implemented |
| SEC-SES-008 | FUTURE CAPABILITY | USER refresh | Full approved refresh behavior including mandatory fresh geo |
| SEC-SES-009 | FUTURE CAPABILITY | USER revoke | New issuance/refresh blocked according to approved revocation semantics |

### 5.11 JWT/JWKS

| ID | Applicability | Test | Expected result |
|---|---|---|---|
| SEC-JWT-001 | NOW | Security access JWT signature | Token validates with configured Verigence RSA public key |
| SEC-JWT-002 | NOW | Security access JWT claims | Approved subject, Tenant, actor type, permissions and expiry semantics are correct |
| SEC-JWT-003 | NOW | Caller attempts actor-type spoof | Caller cannot convert USER into SYSTEM or SERVICE_INTEGRATION |
| SEC-JWKS-001 | NOW | JWKS endpoint | Current public signing key is exposed with matching key identity |
| SEC-JWKS-002 | FUTURE CAPABILITY | Overlapping key rotation | Old/new public keys coexist according to approved rotation window |
| SEC-JWKS-003 | FUTURE CAPABILITY | Unknown `kid` verifier behavior | Verifier refreshes JWKS once before rejecting, per approved decision |

### 5.12 Correlation and traceability

| ID | Applicability | Test | Expected result |
|---|---|---|---|
| SEC-COR-001 | NOW | Valid caller `X-Correlation-ID` | Same safe value returned and used through request evidence |
| SEC-COR-002 | NOW | Header absent | First Verigence service generates a UUIDv4 correlation ID |
| SEC-COR-003 | NOW | Security error response | Correlation ID remains present |
| SEC-COR-004 | NOW | Unexpected HTTP 500 | Correlation ID remains present |
| SEC-COR-005 | DEPLOYMENT PHASE | Deployed HTTPS round trip | Supplied correlation ID is returned unchanged by deployed service |
| SEC-COR-006 | FUTURE CAPABILITY | Cross-module propagation | DI/WPM/internal providers receive the same end-to-end correlation value |

### 5.13 Health/readiness

| ID | Applicability | Test | Expected result |
|---|---|---|---|
| SEC-HLT-001 | NOW | Process liveness | `/health/live` reports service process alive |
| SEC-HLT-002 | NOW | DB unavailable | `/health/ready` fails closed |
| SEC-HLT-003 | NOW | Signing key unavailable | `/health/ready` fails closed |
| SEC-HLT-004 | DEPLOYMENT PHASE | Deployed liveness | Railway HTTPS `/health/live` succeeds |
| SEC-HLT-005 | DEPLOYMENT PHASE | Deployed readiness | Railway HTTPS `/health/ready` succeeds against configured Neon/signing keys |

### 5.14 Deployment and post-deployment validation

| ID | Applicability | Test | Expected result |
|---|---|---|---|
| SEC-DEP-001 | DEPLOYMENT PHASE | Deployment initiation | Deployment occurs only through approved GitHub Actions workflow |
| SEC-DEP-002 | DEPLOYMENT PHASE | Failed pre-deployment gate | Deployment job does not execute |
| SEC-DEP-003 | DEPLOYMENT PHASE | Secrets handling | Railway/DB/signing secrets are injected from secret stores and not printed |
| SEC-DEP-004 | DEPLOYMENT PHASE | Immutable artifact deploy | Railway receives exact tested artifact digest/SHA |
| SEC-DEP-005 | DEPLOYMENT PHASE | Post-deploy liveness | PASS over deployed HTTPS |
| SEC-DEP-006 | DEPLOYMENT PHASE | Post-deploy readiness | PASS over deployed HTTPS |
| SEC-DEP-007 | DEPLOYMENT PHASE | Post-deploy correlation | Correlation header behavior matches approved contract over deployed HTTPS |
| SEC-DEP-008 | DEPLOYMENT PHASE | DEV mock-auth end-to-end | DEV mock USER → real Neon authorization gates → Verigence Security JWT succeeds without Clerk |
| SEC-DEP-009 | DEPLOYMENT PHASE | Negative deployed access case | At least one policy denial is verified end-to-end against deployed service |
| SEC-DEP-010 | DEPLOYMENT PHASE | Failed smoke/E2E result | Deployment marked NOT READY and cannot be promoted |
| SEC-DEP-011 | FUTURE CAPABILITY | UAT promotion | Same immutable artifact digest promoted through GitHub Actions |
| SEC-DEP-012 | FUTURE CAPABILITY | Production promotion | Same approved immutable artifact digest promoted through GitHub Actions |

### 5.15 Information leakage and isolation

| ID | Applicability | Test | Expected result |
|---|---|---|---|
| SEC-ISO-001 | NOW | Cross-Tenant access attempt | Denied without exposing Tenant B authorization/data |
| SEC-ISO-002 | NOW | Error-response inspection | No DB URL, credentials, signing key, stack trace or sensitive internal data returned |
| SEC-ISO-003 | DEPLOYMENT PHASE | Workflow-log inspection | No live secret emitted by build/deployment/post-deploy jobs |

---

## 6. Capabilities that must not have fake completion tests yet

The following approved scope is not complete in the current runtime baseline. Acceptance tests become mandatory when implementation begins, but they must not be represented as currently passing:

- persistent cross-replica idempotency;
- device enrollment/approval/block/revoke administration;
- USER access-session refresh/revoke;
- complete denied-event persistence;
- SYSTEM machine credentials and token issuance;
- SERVICE_INTEGRATION credentials and token issuance;
- Tenant activation readiness/activation service;
- full user/RBAC/location/schedule/policy administration APIs;
- Tenant retention maintenance and offboarding execution;
- overlapping JWKS rotation;
- live Clerk onboarding/integration;
- DI/WPM Security-token integration;
- UAT and Production deployment/promotion.

Where an exact design decision remains open, the corresponding acceptance criterion remains blocked rather than being invented.

---

## 7. Definition of Build Ready

For the currently applicable scope:

```text
BUILD READY =
    approved design integrity          PASS
AND authorized diff scope              PASS
AND secret/static safety               PASS
AND compile                            PASS
AND Ruff                               PASS
AND Mypy                               PASS
AND unit/API regression                PASS
AND applicable Neon integration        PASS
AND applicable security negative tests PASS
AND applicable concurrency tests       PASS
AND package/build integrity            PASS
AND immutable artifact                 PASS   [once deployment phase starts]
AND GitHub Actions deployment          PASS   [once deployment phase starts]
AND post-deployment smoke tests         PASS   [once deployment phase starts]
AND deployed E2E Security tests         PASS   [once deployment phase starts]
```

If any applicable mandatory gate fails:

```text
BUILD NOT READY
```

There is no percentage-based waiver for a mandatory Security gate.

A test that does not apply because its approved feature has not yet been implemented is not a PASS; it remains FUTURE/BLOCKED and cannot be used as evidence for that capability.

---

## 8. Definition of Phase DONE

A phase may be marked DONE only when:

1. approved phase scope is identifiable;
2. implementation matches the approved design;
3. required automated tests exist and pass;
4. applicable integration/infrastructure tests pass;
5. CI quality gates pass on the exact promoted commit;
6. deployment, when part of the phase, occurs through GitHub Actions only;
7. post-deployment checks, when part of the phase, pass;
8. required evidence (commit, PR, workflow run and artifact/digest where applicable) is recorded in the progress/evidence documentation;
9. no unresolved design blocker is hidden by an implementation assumption.

---

## 9. Required evidence for every deployment-ready build

For each deployed build, retain at minimum:

- Git commit SHA;
- PR number/reference;
- CI workflow run ID and result;
- applicable integration-test workflow run ID and result;
- immutable artifact/image digest once supported;
- deployment workflow run ID;
- target environment;
- post-deployment validation run/result;
- known deferred capabilities explicitly distinguished from passed scope.

Evidence must never contain live secret values.

---

## 10. Railway DEV implementation requirement

Phase 3 must not bypass this policy.

Before Railway DEV can be declared DONE, the implementation must add the minimum approved GitHub Actions deployment path necessary to:

1. consume the exact tested Security source/build;
2. deploy to Railway DEV without a manual Railway release step;
3. supply runtime secrets externally;
4. run with approved DEV mock identity and mock network-risk modes;
5. connect to the approved Neon DEV runtime database configuration;
6. verify deployed liveness/readiness;
7. verify `X-Correlation-ID` over deployed HTTPS;
8. execute at least one successful and one denied end-to-end USER access-policy scenario;
9. fail the deployment readiness result if any mandatory post-deployment validation fails.

Immutable image/digest publication should be implemented as part of the deployment pipeline before the build/promotion process is considered suitable for UAT/Production.

---

## 11. Policy maintenance

This policy is intentionally stable and should not be rewritten casually for each phase.

A future change to this file is justified only when one of the following occurs:

- an approved Security design decision changes the required testing/deployment behavior;
- a new implemented capability needs its acceptance gate added;
- CI/deployment tooling changes the actual enforcement model;
- an identified gap requires a stronger mandatory control.

Any such change follows the same controlled PR/CI process as implementation changes.

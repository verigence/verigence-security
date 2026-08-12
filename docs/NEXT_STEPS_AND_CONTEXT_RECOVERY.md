# Verigence Security — Implementation Next Steps & Context Recovery Guide

**Document status:** Execution reference  
**Repository:** `verigence/verigence-security`  
**Primary working branch:** `dev`  
**Approved design baseline:** Security Solution v1.3  
**Current reviewed implementation baseline:** v0.1  
**Purpose:** This is the first document to read before continuing implementation after a context reset. It defines what is already approved, what is already implemented, what remains incomplete, and the order in which work should proceed.

---

## 1. Governing rule

Implementation must remain grounded in the approved **Security Design v1.3** and the reviewed code already committed to `dev`.

This document does **not** supersede the approved design. It is an execution plan.

When this document, chat history, implementation code, or an assumption conflict, use this priority order:

1. Approved Security v1.3 design artifacts and their verified hashes.
2. `docs/SECURITY_DECISION_REGISTER_v1.3.md`.
3. `docs/SECURITY_CORRELATION_STANDARD_v1.3.md`.
4. `docs/SECURITY_OPERATIONAL_LIFECYCLE_v1.3.md`.
5. `docs/DESIGN_TRACEABILITY_REVIEW_v0.1.md`.
6. `docs/IMPLEMENTATION_STATUS.md`.
7. This execution plan.
8. Chat history or implementation assumptions.

If a required behavior is not deterministic from the sources above, **do not invent it in code**. Record the gap and obtain/record an approved design decision first.

---

## 2. Approved-source integrity

The approved v1.3 sources are tracked by `docs/APPROVED_SOURCE_REFERENCE.md`.

Important verified references:

| Artifact | Approved SHA-256 |
|---|---|
| `SECURITY_OPENAPI_v1.3.yaml` | `07f2be9acdf0638647a42d9536bb4575bfdbc72111d9d0b285af64162da98c37` |
| `SECURITY_POSTGRESQL_SCHEMA_v1.3.sql` | `175d10780659c54f402980b08ea209cd34139c9ad28df6c4a758d521c7ca606d` |
| `SECURITY_DECISION_REGISTER_v1.3.md` | `a05b5e0f04cc63e5d76f54a3a120161aa8ce2172e7c810534c36445e85608070` |
| `SECURITY_CORRELATION_STANDARD_v1.3.md` | `fa0f0886eaf6482e52c00ea612550d0674e5ed7b099bc6e9e2e71a84c1a1e1e0` |
| `SECURITY_OPERATIONAL_LIFECYCLE_v1.3.md` | `0c7c83ae08d4488951ff90e8c95c34eff7220b55da17329dc65699f91288cceb` |

Any future design change must be explicit and versioned. Do not silently edit a v1.3 normative artifact to make implementation easier.

---

## 3. Non-negotiable architecture baseline

Unless a later approved design explicitly changes it:

- Security is an independent Verigence platform module.
- Phase-1 infrastructure remains **Railway + Clerk + Neon PostgreSQL**.
- Clerk authenticates human USER identities; Verigence Security remains the authorization source of truth.
- Security data is stored in the dedicated PostgreSQL `security` schema.
- One employee can belong to multiple Tenants.
- Roles are Tenant-scoped.
- USER access requires an ACTIVE registered device.
- USER access requires explicit employee-to-location assignment.
- One employee can be assigned to multiple locations in a Tenant.
- USER access requires valid geo, configured accuracy/freshness, permitted radius and allowed time window.
- Security recognizes `actor_type = USER | SYSTEM | SERVICE_INTEGRATION`.
- SYSTEM and SERVICE_INTEGRATION actors are not modeled as human users and do not inherit human geo/device controls.
- Canonical permissions use `<module>.<resource>[.<subresource>].<action>`, e.g. `di.document.upload`.
- Security asserts `actor_type`, Tenant, roles/permissions and access context; callers cannot self-assert them.
- DEV may use mock authentication/network adapters; UAT/Production must prohibit them.
- `X-Correlation-ID` is the canonical end-to-end trace header.
- DI/WPM validate Security-issued Access JWTs rather than querying Security tables.
- No numeric security policy value is to be invented as a hidden code default.

---

## 4. Current implementation baseline

The reviewed v0.1 implementation on `dev` already provides the implementation foundation documented in `docs/IMPLEMENTATION_STATUS.md` and `docs/DESIGN_TRACEABILITY_REVIEW_v0.1.md`.

Key completed areas include:

- FastAPI/Railway service foundation;
- environment safety for DEV mock adapters;
- Clerk USER identity-verification adapter;
- DEV mock identity token flow;
- Security Principal USER type/status validation;
- correlation-ID middleware and traceable unexpected 500 responses;
- Security RSA Access JWT issuance/verification and single-key JWKS;
- canonical permission validation;
- geo freshness/accuracy/integrity/radius checks;
- schedule/overnight-window evaluation;
- provider-neutral network-risk adapter;
- reusable SQLAlchemy/Neon runtime engine/session factory;
- USER identity/Tenant/device/location/schedule/RBAC repository queries;
- core USER `POST /security/v1/access-sessions` flow;
- active-session context safeguards;
- access evidence persistence for successful USER access;
- health/live and fail-closed readiness endpoints;
- exact v1.3 PostgreSQL baseline as initial migration source;
- exact v1.3 Security domain error catalogue;
- reviewed unit/API test suite.

The v0.1 review gate reported:

- `pytest`: 30 passed;
- Python compile/AST: PASS;
- approved normative source hashes: PASS;
- Security error catalogue: 42/42 exact match;
- static design gates: 24/24 PASS.

`ruff`, `mypy`, package build, live Neon migration and live Clerk integration remain environment/CI gates and must not be described as already completed.

---

## 5. Open design clarifications — do not code by assumption

These items remain explicitly unresolved in v0.1 and must stay visible until resolved:

### O-01 Persistent idempotency

The approved contract requires same-key replay semantics across stateless replicas, but v1.3 has no persistent idempotency-record data model.

**Rule:** Do not claim persistent idempotency complete until an approved design addition defines the persistence model and lifecycle.

### O-02 Invalid correlation-ID rejection response

The implementation currently generates a new server correlation UUID solely to trace a `CORRELATION_ID_INVALID` rejection; it does not propagate the caller's invalid value.

**Rule:** Preserve this safe behavior unless/until the next design baseline states otherwise.

### O-03 Security administration permission catalogue

Permission syntax is frozen, but exact `security.*` permission keys are not yet frozen for every admin endpoint.

**Rule:** Do not invent endpoint permission names.

### O-04 Cross-module session idle-timeout semantics

`session_idle_timeout_minutes` is mandatory configuration, but DI/WPM locally validate Security JWTs and Security does not automatically observe every downstream request.

**Rule:** Do not introduce an unapproved heartbeat/introspection dependency merely to enforce an assumed meaning of activity.

### O-05 Generic request-validation error normalization

The v1.3 OpenAPI documents `400 Problem` for bad requests, while the approved Security error catalogue does not define a generic malformed-request code. FastAPI/Pydantic may emit framework `422` errors.

**Rule:** Do not invent a new Security error code until the contract is baselined.

---

## 6. Execution roadmap

The sequence below is intentional. A later phase must not be used to bypass an incomplete earlier foundation unless an explicit decision changes the sequence.

### Phase 1 — CI quality gate

**Objective:** Make quality checks repeatable on every development change.

Tasks:

- add GitHub Actions CI for supported Python version(s);
- install project with dev dependencies;
- run `pytest`;
- run `ruff check`;
- run `mypy`;
- run Python compile/package build validation;
- add a secret-pattern/static-safety scan equivalent to the reviewed pre-commit gates;
- keep CI free of real Clerk/Neon secrets for unit-test jobs.

Entry criteria:

- reviewed v0.1 exists on `dev`.

Exit criteria:

- CI runs automatically for `dev`/feature PRs;
- all local/static checks are reproducible in CI;
- no merge to `main` while required CI is failing.

**Immediate next task after reading this document: Phase 1.**

---

### Phase 2 — Neon DEV integration

**Objective:** Prove the approved PostgreSQL design executes and the repository layer behaves against real PostgreSQL.

Tasks:

- create/configure Neon DEV PostgreSQL;
- use a direct Neon connection for migration execution;
- use the pooled Neon connection for runtime API tests;
- execute `migrations/0001_security_baseline_v1.3.sql` unchanged unless an approved design revision requires a new migration;
- validate constraints, indexes and transaction behavior;
- add integration tests for implemented repository functions;
- test device-row locking/session concurrency behavior on PostgreSQL;
- ensure test data is DEV-only and deterministic.

Exit criteria:

- migration succeeds from an empty DEV database;
- repository integration tests pass on Neon;
- no schema drift from the approved v1.3 baseline.

---

### Phase 3 — Railway DEV deployment

**Objective:** Run the current Security service end-to-end in the selected DEV infrastructure without requiring external authentication hooks.

DEV configuration:

- Railway Security API service;
- Neon DEV database;
- DEV mock identity provider enabled;
- DEV mock network-risk adapter enabled;
- real Security authorization/geo/time/RBAC logic;
- real Security Access JWT/JWKS;
- no production credentials.

Tasks:

- deploy the service from `dev`;
- configure Railway environment variables/secrets;
- validate `/health/live` and `/health/ready`;
- perform end-to-end mock-auth → access-session → JWT/JWKS verification test;
- verify correlation-ID behavior through Railway ingress;
- capture deployment/runbook details in repository docs.

Exit criteria:

- reproducible Railway DEV deployment;
- live DEV Security API can authenticate through the mock boundary and exercise real authorization controls.

---

### Phase 4 — v0.2 USER device and session lifecycle

**Objective:** Complete the major USER-runtime lifecycle omitted from v0.1.

Planned functional scope:

- device enrollment bootstrap flow;
- PENDING device registration;
- device approval;
- device block/revoke;
- configured active-device-limit enforcement;
- USER access-session refresh;
- fresh geo required on USER refresh;
- USER session revoke;
- deterministic same-user/Tenant/device concurrency behavior;
- denial-event persistence for the implemented flows.

Important dependency:

- persistent idempotency across replicas cannot be completed until O-01 is resolved and an approved persistence model exists.

Exit criteria:

- device lifecycle and USER session refresh/revoke are fully covered by unit + PostgreSQL integration tests;
- no authorization path bypasses the v1.3 USER access gates.

---

### Phase 5 — Security administration foundation

**Objective:** Make Security configuration operational through controlled administrator APIs.

Planned scope:

- employee/user onboarding administration;
- Tenant memberships;
- Tenant roles;
- role-permission mapping;
- user-role mapping;
- Tenant locations;
- employee-location mapping;
- access schedules/windows;
- temporary schedule overrides;
- Tenant Security Policy configuration;
- activation-readiness endpoint;
- Tenant activation application service.

Dependency:

- endpoint authorization must not invent `security.*` permission keys while O-03 is unresolved.

Exit criteria:

- a Tenant can be configured from CONFIGURING to activation-ready using supported APIs;
- readiness clearly reports missing configuration rather than returning a generic failure.

---

### Phase 6 — SYSTEM and SERVICE_INTEGRATION actors

**Objective:** Implement the approved three-actor Security model beyond USER.

Planned scope:

- machine Security Principal lifecycle;
- SYSTEM principal administration;
- SERVICE_INTEGRATION principal administration;
- machine credential registration/storage contract;
- credential rotation/revocation;
- Tenant-scoped machine access-token endpoint;
- explicit permission grants for machine actors;
- no human role/geo/device policy leakage into machine actors;
- WhatsApp ingestion SYSTEM actor;
- internal DI/WPM workers as SYSTEM actors where applicable;
- external partner/DMS/API connections as SERVICE_INTEGRATION actors where applicable.

Exit criteria:

- USER, SYSTEM and SERVICE_INTEGRATION use the same canonical Security token/permission contract while authenticating and authorizing through their actor-appropriate controls.

---

### Phase 7 — Operational security lifecycle

**Objective:** Complete operational obligations already defined by the approved design.

Planned scope:

- Tenant retention-policy application;
- controlled maintenance purge;
- Tenant OFFBOARDING/OFFBOARDED execution;
- prevention of new USER/SYSTEM/SERVICE_INTEGRATION tokens during offboarding;
- active Security-session/machine-access revocation behavior defined by the approved Phase-1 revocation semantics;
- complete Security event persistence;
- geo integrity evidence retention;
- scheduled maintenance process on Railway;
- operational reconciliation/error recovery.

Exit criteria:

- retention and Tenant offboarding are testable, idempotent and auditable;
- Security never deletes DI/WPM-owned Tenant data as part of Security offboarding.

---

### Phase 8 — JWKS rotation and production-grade adapters

**Objective:** Harden external/provider boundaries before UAT.

Planned scope:

- overlapping old/new JWKS key rotation;
- unique `kid` lifecycle;
- verifier refresh behavior for unknown `kid`;
- selected production network-risk provider adapter when formally selected;
- adapter failure → approved `UNKNOWN` policy behavior;
- credential/key rotation runbook.

Exit criteria:

- key rotation does not reject otherwise valid in-flight tokens;
- provider outage behavior remains deterministic.

---

### Phase 9 — Clerk integration

**Objective:** Replace only the DEV USER authentication boundary with the real Clerk adapter while keeping authorization unchanged.

Plan policy:

- Clerk Hobby is acceptable during development/pre-production;
- production Clerk plan is reassessed before production go-live.

Tasks:

- configure Clerk DEV environment;
- validate Clerk session JWT integration;
- implement/validate employee invitation/onboarding calls;
- verify Clerk subject → Verigence user mapping;
- run live integration tests;
- confirm DEV mock endpoint remains unavailable in UAT/Production configurations.

Exit criteria:

- same Security authorization flow works with real Clerk USER authentication;
- no DI/WPM dependency on Clerk is introduced.

---

### Phase 10 — DI/WPM Security integration

**Objective:** Prove the platform authorization boundary end-to-end.

Tasks:

- DI/WPM validate Security JWT locally using Security JWKS;
- enforce Tenant claim/resource consistency;
- DI adopts canonical dot permissions such as `di.document.upload`;
- remove/deprecate legacy colon-style permission checks;
- propagate `X-Correlation-ID` end-to-end;
- represent actor lineage using Security `sub` + `actor_type`;
- validate USER, SYSTEM and SERVICE_INTEGRATION scenarios applicable to each module.

Exit criteria:

- no downstream module uses Security database directly;
- permission contract is identical between Security token issue and downstream enforcement.

---

### Phase 11 — UAT and promotion to `main`

**Objective:** Promote only a tested, reviewable release candidate.

Pre-main gates:

- all required CI checks green;
- live Neon migration/integration tests pass;
- Railway deployment verified;
- Clerk integration verified where required;
- SECURITY design traceability matrix updated;
- unresolved design gaps explicitly dispositioned;
- no DEV mock capability available in UAT/Production configuration;
- secret scan clean;
- no unapproved permission/error/policy values;
- release notes and migration instructions prepared.

`main` is for approved stable baselines. Development should continue on feature branches merged to `dev` first.

---

## 7. Recommended branch workflow

```text
main
  stable/reviewed releases only

  ↑ reviewed promotion

dev
  integrated development baseline

  ↑ reviewed PRs

feature/security-ci
feature/neon-integration
feature/railway-dev
feature/device-session-lifecycle
feature/security-admin
feature/machine-principals
feature/operational-lifecycle
feature/clerk-integration
```

Rules:

- do not develop directly on `main`;
- prefer one logical change per feature branch;
- merge to `dev` only after applicable tests/review pass;
- update `docs/IMPLEMENTATION_STATUS.md` after every milestone;
- update this document when sequencing or milestone status materially changes;
- design changes require a versioned design decision, not an undocumented code workaround.

---

## 8. Definition of done for any implementation increment

Before considering a work item complete:

1. Identify the exact approved design contract being implemented.
2. Confirm no unresolved design item blocks the behavior.
3. Implement without hidden policy defaults.
4. Add/update unit tests.
5. Add integration tests when DB/provider behavior is involved.
6. Run `pytest`.
7. Run `ruff`.
8. Run `mypy`.
9. Run build/compile validation.
10. Run secret and legacy-permission checks.
11. Confirm correlation-ID handling on new HTTP/service boundaries.
12. Confirm Tenant scoping on every Tenant-owned query/token.
13. Update traceability/status documentation.
14. Review the diff specifically for behavior not supported by v1.3.
15. Commit only after the above checks applicable to the increment pass.

No work item is marked complete merely because code compiles.

---

## 9. Context recovery procedure

After any conversation/context reset, perform these steps **before changing code**:

1. Open repository `verigence/verigence-security`.
2. Work from branch `dev` unless explicitly instructed otherwise.
3. Read this file: `docs/NEXT_STEPS_AND_CONTEXT_RECOVERY.md`.
4. Read `docs/IMPLEMENTATION_STATUS.md`.
5. Read `docs/DESIGN_TRACEABILITY_REVIEW_v0.1.md` or its latest successor.
6. Read `docs/APPROVED_SOURCE_REFERENCE.md`.
7. Read the v1.3 Decision Register, Correlation Standard and Operational Lifecycle documents relevant to the task.
8. Inspect the latest `dev` commit and any open PR/diff for the feature being continued.
9. Confirm the current roadmap phase and its entry/exit criteria.
10. Re-check the open-design section in this document.
11. Do not rely on remembered chat wording when repository/design sources are available.
12. If a new user decision changes architecture, record it in the appropriate versioned design/decision artifact before implementing the changed contract.

This procedure is intended to make implementation deterministic even when conversational context is cleared.

---

## 10. Current execution pointer

**Current milestone:** v0.1 reviewed implementation baseline is committed on `dev`.

**Next phase:** **Phase 1 — CI quality gate.**

After CI is green, proceed to **Phase 2 — Neon DEV integration**, followed by **Phase 3 — Railway DEV deployment** before expanding application scope.

Do not start SYSTEM/SERVICE_INTEGRATION implementation or broad administration APIs merely because they are interesting; follow the dependency sequence above unless an explicit decision changes it.

---

## 11. Maintenance of this document

This is a living execution reference, not a frozen design specification.

Update it when:

- a phase is completed;
- implementation order changes by explicit decision;
- an open design clarification is resolved;
- a new implementation blocker is found;
- the approved Security design baseline version changes.

When updating this document, preserve historical facts accurately: completed gates must be supported by actual CI/test/deployment evidence, not by expectation.

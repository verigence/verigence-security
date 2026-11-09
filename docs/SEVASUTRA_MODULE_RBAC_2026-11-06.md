# SevaSutra module and the ANALYST operating role

**Status:** Approved by the product owner, 6 November 2026
**Migration:** `migrations/0052_sevasutra_module_rbac.sql`
**Binding workflow:** `.github/workflows/sevasutra-security-bind.yml`

## Decision

SevaSutra is JBR's workshop (after-sales service) audit product. It signs people in through Security and
asks Security what each person may do in a Project. This is the same boundary Audit Core uses:

1. SevaSutra's own sign-in page sends the identifier and password to `POST /security/v1/auth/login`.
2. SevaSutra validates the Security human JWT locally, against `/.well-known/jwks.json`.
3. With its ServiceIntegration token (`aud=security`), it asks `POST /security/v1/authorization/check-batch`
   which `sevasutra.*` permissions the user holds in the Project.

Users, passwords, Projects and operating roles stay in Security. SevaSutra keeps no passwords. Outlet
scope stays in SevaSutra, as it stays in Audit Core.

## Roles

| Role | Key | Where it comes from | Holds |
| --- | --- | --- | --- |
| Analyst | `ANALYST` | New operating role (0052) | On site at one outlet. Captures evidence, audits it, raises observations. |
| Team Lead | `TL` | Existing operating role; SevaSutra permissions added | Approves observations before they reach the Dealer Principal, issues the daily report, verifies leakage. |
| PM | `PM` | Existing operating role; SevaSutra permissions added | Thresholds, labour benchmark, recurring schedules, team mapping; settles leakage. |

Whoever raises an observation never approves it, so the Analyst bundle holds no approve permission.

## Permissions (module `sevasutra`, catalogue `sevasutra-1.0`)

| Permission | ANALYST | TL | PM |
| --- | --- | --- | --- |
| `sevasutra.project.read` | yes | yes | yes |
| `sevasutra.evidence.upload` | yes | yes | |
| `sevasutra.evidence.verify` | yes | yes | |
| `sevasutra.observation.raise` | yes | yes | |
| `sevasutra.observation.approve` | | yes | yes |
| `sevasutra.report.issue` | | yes | yes |
| `sevasutra.leakage.verify` | | yes | yes |
| `sevasutra.leakage.settle` | | | yes |
| `sevasutra.risk.close` | | yes | yes |
| `sevasutra.benchmark.propose` | yes | | |
| `sevasutra.benchmark.approve` | | | yes |
| `sevasutra.task.assign` | | yes | yes |
| `sevasutra.task.schedule` | | | yes |
| `sevasutra.settings.manage` | | | yes |
| `sevasutra.team.manage` | | | yes |
| `sevasutra.analytics.read` | yes | yes | yes |

Existing Projects are backfilled with these permissions for ANALYST, TL and PM. Audit Core ignores
`sevasutra.*` keys, so a sales-audit Project is unaffected.

## ServiceIntegration `sevasutra`

SevaSutra generates its own client secret on its first deployment and keeps it as a Worker secret. It
publishes only the argon2id hash of that secret, at `GET https://sevasutra.jbrconsulting.in/api/platform/security-binding`.

The binding workflow:

1. reads that hash over HTTPS;
2. registers the `sevasutra` principal, integration and credential with it (in the shape of the DI binding);
3. asks SevaSutra to prove it can obtain a service token.

The plaintext secret never leaves SevaSutra's Worker. Running the workflow again rotates nothing unless
SevaSutra's secret changed.

## Client access and Super Admin oversight (product owner, 9 November 2026)

**Migration:** `migrations/0056_sevasutra_client_role.sql`

| Who | Key | Holds |
| --- | --- | --- |
| Client (analytics) | `CLIENT`, new operating role | People who are not JBR employees (dealer principal, service manager, OEM or other client people). The analytics of the Project's dealership and nothing else: `sevasutra.project.read`, `sevasutra.analytics.read`. |
| Super Admin | existing admin role | Oversees SevaSutra: every dealership, settings, rules, the platform console. Does **not** approve observations (`sevasutra.observation.approve`) or settle leakage (`sevasutra.leakage.settle`); those stay with the Team Lead and the PM, as payroll approval stays with the CEO. Enforced in `SUPER_ADMIN_EXCLUDED_PERMISSIONS`. |

- What `CLIENT` shows is set once per Project, through the Project's `CLIENT` bundle; the default is the
  analytics only. A client sees only figures from observations a Team Lead has approved.
- `CLIENT` carries no `audit.*` or `di.*` permission, so in a sales-audit Project it gives nothing.
- Internal roles (`ANALYST`, `TL`, `PM`) are not restricted to employees.
- Existing Projects are backfilled with the `CLIENT` bundle; new Projects receive it through provisioning,
  which seeds every `OPERATING` role's defaults.

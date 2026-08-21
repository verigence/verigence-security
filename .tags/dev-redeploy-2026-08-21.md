# Security DEV redeploy trigger — 2026-08-21

Operational redeploy marker requested after the previous Railway service disruption.

- Target branch: `dev`
- Source head before trigger: `2cefb7590d9760a476ae0435bad0afb26896a64e`
- Purpose: retrigger the approved GitHub Actions Security DEV deployment path
- Runtime/source behavior change: none

The resulting push is intended only to re-run the repository's mandatory CI/CD gates and deploy the current Security DEV tree through the approved GitHub-Actions-only process.

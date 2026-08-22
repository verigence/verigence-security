# UC02 Security DEV Release Baseline — 22-Aug-2026

This record identifies the Security UC02 DEV release baseline and the release gate used to deploy it.

## Release source

- Canonical integration branch: `dev`
- UC02 application baseline before this release record: `c79aca8165d3d3345540302b63887720423170df`
- Target runtime: Railway shared `dev` environment
- Railway service: `security`

## Required release gate

A Security DEV release is valid only when the `dev` push passes the existing `Security CI/CD` workflow in this order:

1. quality, static safety, route contract, tests and package build;
2. database migration validation and application;
3. immutable image build for the exact Git SHA;
4. deployment of that exact image to the approved Railway DEV service;
5. a new Railway deployment reaches `SUCCESS`;
6. live readiness, liveness, correlation-ID and JWKS checks pass.

The same high-level rule is used for DI and Audit Core: **DEV push -> CI/build pass -> deploy exact tested SHA -> fresh Railway deployment -> live smoke checks**.

This document changes no Security application behavior; its merge is also used to exercise the normal `dev` release pipeline from a real pull-request merge rather than a synthetic ref update.

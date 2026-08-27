# Customer Mobile PII Permission

**Status:** IMPLEMENTATION APPROVED  
**Date:** 2026-08-27

## Decision

Audit Core persists the complete normalized customer mobile number. Existing Customer APIs disclose that value according to the caller's resolved Security permissions; there is no separate reveal API.

Security remains authoritative for authorization. Audit Core shall not use role-name string checks to decide whether complete customer contact PII may be returned.

## Permission

Register the Audit Core permission:

`audit.customer.contact.full.read`

The permission is additive to ordinary Customer access. A caller must still be authorized for the Customer and Tenant/business scope; this permission only controls whether the complete mobile value is disclosed rather than masked.

## Default role policy

- **Executive** — granted by default.
- **SuperAdmin** — permitted through the existing Security v2 SuperAdmin full-authority rule for ACTIVE registered permissions, subject to the requested target-Tenant context.
- **PC** — not granted by default.
- **TL** — not granted by default.
- **PM** — not granted by default.
- **CRM** — not granted by default.

The Security permission claim/evaluation is authoritative. `roles[]` remains informational.

## Existing tenants

The migration adds the permission to existing Executive Tenant role bundles so an already-onboarded Executive receives the approved capability without requiring a new role name or API contract. No PC/TL/PM/CRM Tenant bundle is expanded.

## API expectation

For the same normal Audit Core Customer API call:

- caller without `audit.customer.contact.full.read` → masked `mobileNumber`, final four digits visible;
- caller with `audit.customer.contact.full.read` → complete stored `mobileNumber`.

Security does not mask data itself; it only supplies/evaluates the authorization capability used by Audit Core.

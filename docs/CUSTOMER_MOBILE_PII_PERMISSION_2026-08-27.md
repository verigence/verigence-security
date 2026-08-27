# Customer Mobile PII Permission

**Date:** 2026-08-27
**Status:** IMPLEMENTATION APPROVED

Audit Core persists the complete normalized customer mobile number. Ordinary customer readers receive a masked mobile value from the existing Customer APIs. Full mobile is revealed only when the caller has the dedicated Audit Core permission `audit.customer.contact.full.read` in addition to ordinary customer-read authorization.

Security remains authoritative for resolved permissions. Audit Core must not authorize full mobile disclosure by checking role-name strings.

Default policy:

- Executive: grant `audit.customer.contact.full.read`;
- Super Admin: grant the permission when operating in an authorized target-Tenant context;
- PC/TL/PM/CRM: do not grant by default.

The permission controls disclosure only; it does not independently authorize Customer access or expand Tenant/business scope.

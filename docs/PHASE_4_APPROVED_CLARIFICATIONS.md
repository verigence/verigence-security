# Phase 4 Approved Clarifications

**Status:** Approved implementation clarification  
**Date:** 2026-08-13  
**Applies to:** Security Solution v1.3 implementation, Phase 4 USER session lifecycle

This document records implementation clarifications explicitly approved during Phase 4. It does not silently modify the original v1.3 normative artifacts. A future consolidated Security design version may absorb these clarifications formally.

## CLAR-004-001 — USER refresh location-context transition

For USER access-session refresh, a new geo sample remains mandatory under SEC-029.

After normal geo freshness, accuracy and integrity validation:

1. Security evaluates the fresh geo against the USER's currently ACTIVE and effective Tenant location assignments.
2. If the geo does not fall within any currently approved/assigned ACTIVE location, refresh is denied using the existing location errors (`LOCATION_NOT_ASSIGNED` when no effective assignment exists, otherwise `LOCATION_NOT_ALLOWED`).
3. If the geo resolves to an approved/assigned location that is the same as the ACTIVE session location, Security refreshes the existing session context after normal policy re-evaluation.
4. If the geo resolves to a different approved/assigned location, Security may move the same ACTIVE access-session context to that newly matched approved location, but only after re-evaluating the matched location's schedule/time policy and all other normal USER access gates used by refresh.
5. The refreshed Security token must carry the location that passed the current refresh evaluation. Security must not continue to assert the old location after the session context has moved.
6. A location-context move does not bypass the original session maximum-duration cap; refresh must not extend the session beyond the configured maximum duration derived from the original session start.
7. Session-context movement is not permission to accept arbitrary geo. Only currently ACTIVE/effective assigned Tenant locations may become the refreshed session location.

## Source-control handling

The checksum-referenced `SECURITY_OPENAPI_v1.3.yaml` has no commit history in `verigence/verigence-security`; it was not deleted or changed in this repository. `docs/APPROVED_SOURCE_REFERENCE.md` was introduced with the original reviewed v0.1 baseline and references the authoritative OpenAPI as an external approved source.

Until the exact checksum-matching OpenAPI is recovered, public endpoint request/response/security shapes remain non-inferable. This clarification permits service/repository implementation of the refresh location transition; it does not authorize inventing the missing public API contract.

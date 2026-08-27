# Security UC-001 — Rejected USER Deletion Amendment

**Date:** 2026-08-27  
**Repository:** `verigence/verigence-security`  
**Target branch:** `dev`

## Decision

UC-001 administration requires a rejected onboarding USER to have exactly two SuperAdmin outcomes:

```text
REJECTED -> ACTIVE
REJECTED -> hard DELETE
```

The hard-delete option reuses the existing Security v2 deletion workflow. No direct deletion bypass is introduced.

## Authoritative deletion path

A rejected USER enters the existing deletion workflow through:

```text
REJECTED
   |
   | PATCH /security/v1/users/{userId}/status
   | status=DISABLED
   | reasonCode=DELETE_REQUEST
   v
DISABLED
   |
   | DELETE /security/v1/platform/users/{userId}
   v
DELETED
```

`DISABLED` remains an intermediate deletion-request state. The existing hard-delete preconditions, SuperAdmin authorization, Clerk identity deletion, live USER/principal cleanup, audit evidence and deletion tombstone behavior remain unchanged.

## Scope

This amendment changes only the deletion-request transition guard from:

```text
ACTIVE -> DISABLED
```

to:

```text
ACTIVE   -> DISABLED
REJECTED -> DISABLED
```

Both transitions require `reasonCode=DELETE_REQUEST`.

The following are unchanged:

- `PENDING` cannot be deleted directly; it must first be approved or rejected through the onboarding decision flow.
- `REJECTED -> ACTIVE` remains SuperAdmin-controlled.
- `DISABLED -> ACTIVE` remains the deletion-request cancellation/reactivation path.
- hard delete still requires an open deletion request and a `DISABLED` USER.
- `EXITED` is not reintroduced.
- no database migration or new endpoint is required.

## Rationale

A rejected registration is a retained live Security USER with no authorized access. Administration must be able either to reverse the rejection by activating the USER or permanently remove the rejected identity through the same governed deletion workflow used for active USERs. Requiring a temporary activation solely to delete a rejected registration would create an unnecessary and unsafe lifecycle transition.

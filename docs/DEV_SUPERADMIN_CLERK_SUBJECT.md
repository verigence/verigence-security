# DEV SuperAdmin Clerk subject

Canonical DEV SuperAdmin Clerk user ID:

`user_3I7FdD5Pkmydsp23OfjH9hBMxpN`

This value is the immutable Clerk `user_...` identifier for the current DEV SuperAdmin account. Security must bind this subject through `security.external_identities`; Web must not infer SuperAdmin from email.

If the Clerk user is deleted and recreated, or DEV is pointed at a different Clerk instance, a new Clerk user ID will be created and Security DEV must be reconciled explicitly.

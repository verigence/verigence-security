-- Verigence Security — v1.4.2 security-event lifecycle outcome compatibility
--
-- v1.3 defined security.security_events.outcome as varchar(20). Global USER onboarding
-- introduces explicit lifecycle outcomes such as PENDING_ADMIN_APPROVAL, which must be
-- retained without truncation in Security audit evidence. This migration is additive and
-- non-destructive; the immutable v1.3 baseline remains unchanged.

BEGIN;

ALTER TABLE security.security_events
  ALTER COLUMN outcome TYPE varchar(40);

COMMIT;

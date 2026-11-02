-- Verigence Security: a third feature switch, CHECKOUT_GATE_REGISTER (product owner 2026-11-02).
--
-- Before a PC checks out, the app checks that the previous day's gate register of each onsite
-- outlet of theirs is finished. Switched off (the default: no row), it is a warning and OK goes on
-- to check out; switched on, for everyone or for chosen people, check-out is not allowed until the
-- gate register is done. Like AUDIT and ANALYTICS it grants no data access; it only decides what
-- the web and mobile apps do. Additive and idempotent.

BEGIN;

ALTER TABLE security.feature_access DROP CONSTRAINT IF EXISTS feature_access_feature_key_check;
ALTER TABLE security.feature_access
  ADD CONSTRAINT feature_access_feature_key_check
  CHECK (feature_key IN ('AUDIT','ANALYTICS','CHECKOUT_GATE_REGISTER'));

COMMIT;

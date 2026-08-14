-- Verigence Security — Increment G privileged access maker-checker v1.4.7
-- Additive guard for the existing v1.4 privileged_access_requests table.

BEGIN;

CREATE UNIQUE INDEX IF NOT EXISTS uq_privileged_access_request_pending_assignment
ON security.privileged_access_requests(tenant_id,subject_user_id,role_id)
WHERE status='PENDING';

CREATE INDEX IF NOT EXISTS ix_privileged_access_requests_tenant_status_time
ON security.privileged_access_requests(tenant_id,status,requested_at_utc DESC);

COMMIT;

CREATE TABLE IF NOT EXISTS security_role_templates (
    scope_type TEXT NOT NULL CHECK (scope_type IN ('PLATFORM', 'TENANT')),
    tenant_id TEXT NOT NULL DEFAULT '',
    role_key TEXT NOT NULL,
    permissions JSONB NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    updated_by TEXT NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (scope_type, tenant_id, role_key),
    CHECK (
        (scope_type = 'PLATFORM' AND tenant_id = '')
        OR (scope_type = 'TENANT' AND tenant_id <> '')
    )
);

CREATE TABLE IF NOT EXISTS security_role_template_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    scope_type TEXT NOT NULL CHECK (scope_type IN ('PLATFORM', 'TENANT')),
    tenant_id TEXT NOT NULL DEFAULT '',
    role_key TEXT NOT NULL,
    previous_permissions JSONB NOT NULL,
    new_permissions JSONB NOT NULL,
    actor_sub TEXT NOT NULL,
    correlation_id TEXT NULL,
    changed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS security_role_template_audit_lookup_idx
    ON security_role_template_audit (scope_type, tenant_id, role_key, changed_at DESC);

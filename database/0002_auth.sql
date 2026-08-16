CREATE TABLE IF NOT EXISTS security_tenants (
    tenant_id TEXT PRIMARY KEY,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS security_users (
    user_id TEXT PRIMARY KEY,
    external_subject TEXT NOT NULL UNIQUE,
    email TEXT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS security_user_tenant_memberships (
    user_id TEXT NOT NULL REFERENCES security_users(user_id),
    tenant_id TEXT NOT NULL REFERENCES security_tenants(tenant_id),
    roles JSONB NOT NULL,
    direct_permissions JSONB NOT NULL DEFAULT '[]'::jsonb,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, tenant_id)
);

CREATE INDEX IF NOT EXISTS security_user_tenant_membership_lookup_idx
    ON security_user_tenant_memberships (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS security_auth_sessions (
    session_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES security_users(user_id),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS security_auth_sessions_user_idx
    ON security_auth_sessions (user_id, expires_at);

CREATE TABLE IF NOT EXISTS security_oauth_authorization_requests (
    request_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    state TEXT NOT NULL,
    tenant_id TEXT NOT NULL,
    code_challenge TEXT NULL,
    code_challenge_method TEXT NULL,
    upstream_state_hash TEXT NULL UNIQUE,
    upstream_nonce TEXT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS security_oauth_auth_request_expiry_idx
    ON security_oauth_authorization_requests (expires_at);

CREATE TABLE IF NOT EXISTS security_oauth_authorization_codes (
    code_hash TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES security_users(user_id),
    tenant_id TEXT NOT NULL REFERENCES security_tenants(tenant_id),
    code_challenge TEXT NULL,
    code_challenge_method TEXT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS security_oauth_code_expiry_idx
    ON security_oauth_authorization_codes (expires_at, used_at);

CREATE TABLE IF NOT EXISTS security_auth_audit (
    audit_id BIGSERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    outcome TEXT NOT NULL,
    user_id TEXT NULL,
    tenant_id TEXT NULL,
    client_id TEXT NULL,
    detail TEXT NULL,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS security_auth_audit_lookup_idx
    ON security_auth_audit (event_type, occurred_at DESC);

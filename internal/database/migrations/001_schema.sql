CREATE TABLE IF NOT EXISTS tenants (
    id text PRIMARY KEY,
    name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oidc_issuers (
    issuer text PRIMARY KEY,
    display_name text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS oidc_clients (
    tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    issuer text NOT NULL REFERENCES oidc_issuers(issuer) ON DELETE CASCADE,
    client_id text NOT NULL,
    client_secret text NOT NULL DEFAULT '',
    redirect_uris text[] NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, issuer)
);

CREATE TABLE IF NOT EXISTS account_members (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    display_name text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS account_members_tenant_idx ON account_members(tenant_id);

CREATE TABLE IF NOT EXISTS oidc_identities (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    issuer text NOT NULL,
    subject text NOT NULL,
    member_id uuid NOT NULL REFERENCES account_members(id) ON DELETE CASCADE,
    email text NOT NULL DEFAULT '',
    email_verified boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, issuer, subject)
);

CREATE TABLE IF NOT EXISTS oauth_flows (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    kind text NOT NULL CHECK (kind IN ('login', 'link')),
    tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    issuer text NOT NULL,
    client_id text NOT NULL,
    redirect_uri text NOT NULL,
    state_hash bytea NOT NULL UNIQUE,
    nonce_hash bytea NOT NULL,
    encrypted_code_verifier bytea NOT NULL,
    link_flow_id uuid REFERENCES link_flows(id) ON DELETE CASCADE,
    expected_leg smallint,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'consumed', 'failed', 'expired')),
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS oauth_flows_expires_idx ON oauth_flows(expires_at);

CREATE TABLE IF NOT EXISTS link_flows (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    issuer1 text NOT NULL,
    issuer2 text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'completed', 'abandoned')),
    completed_member_id uuid REFERENCES account_members(id) ON DELETE SET NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz
);

CREATE TABLE IF NOT EXISTS link_flow_identities (
    link_flow_id uuid NOT NULL REFERENCES link_flows(id) ON DELETE CASCADE,
    leg smallint NOT NULL CHECK (leg IN (1, 2)),
    issuer text NOT NULL,
    subject text NOT NULL,
    email text NOT NULL DEFAULT '',
    email_verified boolean NOT NULL DEFAULT false,
    auth_time timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (link_flow_id, leg)
);

CREATE TABLE IF NOT EXISTS sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash bytea NOT NULL UNIQUE,
    tenant_id text NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    member_id uuid NOT NULL REFERENCES account_members(id) ON DELETE CASCADE,
    issuer text NOT NULL,
    subject text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS sessions_expires_idx ON sessions(expires_at);

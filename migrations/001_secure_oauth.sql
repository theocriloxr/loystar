-- Production OAuth security upgrade.
--
-- This intentionally invalidates every authorization code and bearer token
-- created by the pre-production schema. Merchants must reconnect after it runs.
-- Run during a maintenance window before starting the upgraded application.

BEGIN;

DROP TABLE IF EXISTS oauth_authorization_codes;
DROP TABLE IF EXISTS oauth_access_tokens;

CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY,
    client_id VARCHAR(512) NOT NULL UNIQUE,
    client_secret_hash VARCHAR(64),
    client_name VARCHAR(255) NOT NULL,
    redirect_uris JSON NOT NULL,
    grant_types JSON NOT NULL,
    response_types JSON NOT NULL,
    token_endpoint_auth_method VARCHAR(50) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS ix_oauth_clients_client_id
    ON oauth_clients (client_id);

CREATE TABLE oauth_authorization_codes (
    id UUID PRIMARY KEY,
    code_hash VARCHAR(64) NOT NULL UNIQUE,
    encrypted_credentials TEXT NOT NULL,
    redirect_uri VARCHAR(512) NOT NULL,
    client_id VARCHAR(512) NOT NULL,
    code_challenge VARCHAR(128) NOT NULL,
    code_challenge_method VARCHAR(16) NOT NULL,
    scope VARCHAR(255) NOT NULL,
    resource VARCHAR(1024) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX ix_oauth_authorization_codes_code_hash
    ON oauth_authorization_codes (code_hash);
CREATE INDEX idx_oauth_code_expires
    ON oauth_authorization_codes (expires_at);

CREATE TABLE oauth_access_tokens (
    id UUID PRIMARY KEY,
    access_token_hash VARCHAR(64) NOT NULL UNIQUE,
    refresh_token_hash VARCHAR(64) UNIQUE,
    encrypted_credentials TEXT NOT NULL,
    merchant_uid VARCHAR(255) NOT NULL,
    client_id VARCHAR(512) NOT NULL,
    resource VARCHAR(1024) NOT NULL,
    scope VARCHAR(255) NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    refresh_expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX ix_oauth_access_tokens_access_token_hash
    ON oauth_access_tokens (access_token_hash);
CREATE INDEX ix_oauth_access_tokens_refresh_token_hash
    ON oauth_access_tokens (refresh_token_hash);
CREATE INDEX ix_oauth_access_tokens_client_id
    ON oauth_access_tokens (client_id);
CREATE INDEX ix_oauth_access_tokens_merchant_uid
    ON oauth_access_tokens (merchant_uid);
CREATE INDEX idx_oauth_token_merchant
    ON oauth_access_tokens (merchant_uid);
CREATE INDEX idx_oauth_token_expires
    ON oauth_access_tokens (expires_at);

CREATE TABLE IF NOT EXISTS connector_audit_events (
    id UUID PRIMARY KEY,
    event_id VARCHAR(96) NOT NULL UNIQUE,
    timestamp TIMESTAMPTZ NOT NULL,
    client_ip VARCHAR(64) NOT NULL,
    path VARCHAR(512) NOT NULL,
    method VARCHAR(16) NOT NULL,
    tool_name VARCHAR(255),
    merchant_uid VARCHAR(255),
    credential_source VARCHAR(50) NOT NULL,
    status VARCHAR(50) NOT NULL,
    error_code VARCHAR(100)
);

CREATE INDEX IF NOT EXISTS ix_connector_audit_events_event_id
    ON connector_audit_events (event_id);
CREATE INDEX IF NOT EXISTS ix_connector_audit_events_timestamp
    ON connector_audit_events (timestamp);
CREATE INDEX IF NOT EXISTS ix_connector_audit_events_status
    ON connector_audit_events (status);

COMMIT;

CREATE SCHEMA IF NOT EXISTS aiops;

CREATE TABLE IF NOT EXISTS aiops.incidents (
    id TEXT PRIMARY KEY,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS aiops.actions (
    id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    payload JSONB NOT NULL,
    proposed_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS aiops.audit_events (
    id TEXT PRIMARY KEY,
    incident_id TEXT NULL,
    action_id TEXT NULL,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_actions_incident ON aiops.actions (incident_id);
CREATE INDEX IF NOT EXISTS idx_audit_incident ON aiops.audit_events (incident_id);

CREATE TABLE IF NOT EXISTS aiops.users (
    id UUID PRIMARY KEY,
    identity_key VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(255) NULL,
    email VARCHAR(255) NULL,
    role VARCHAR(100) NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS aiops.chat_sessions (
    id UUID PRIMARY KEY,
    client_session_id VARCHAR(255) NULL UNIQUE,
    user_id UUID NULL REFERENCES aiops.users(id),
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    message_count INTEGER NOT NULL DEFAULT 0,
    last_user_message TEXT NULL,
    last_assistant_message TEXT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_chat_sessions_user ON aiops.chat_sessions (user_id);

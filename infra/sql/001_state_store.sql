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

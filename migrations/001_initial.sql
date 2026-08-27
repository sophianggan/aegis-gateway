BEGIN;

CREATE TABLE IF NOT EXISTS records (
    id UUID PRIMARY KEY,
    source TEXT NOT NULL CHECK (length(source) BETWEEN 1 AND 100),
    fields JSONB NOT NULL CHECK (jsonb_typeof(fields) = 'object'),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY,
    request_id UUID NOT NULL,
    sequence INTEGER NOT NULL CHECK (sequence >= 0),
    occurred_at TIMESTAMPTZ NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    decision TEXT NOT NULL CHECK (decision IN ('allow', 'filter', 'deny')),
    resource_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    details JSONB NOT NULL DEFAULT '{}'::jsonb,
    previous_hash TEXT NOT NULL,
    event_hash TEXT NOT NULL CHECK (length(event_hash) = 64),
    UNIQUE (request_id, sequence)
);

CREATE INDEX IF NOT EXISTS audit_events_request_order
    ON audit_events (request_id, sequence);
CREATE INDEX IF NOT EXISTS audit_events_occurred_at
    ON audit_events (occurred_at DESC);

CREATE TABLE IF NOT EXISTS revoked_tokens (
    token_id TEXT PRIMARY KEY,
    revoked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    reason TEXT NOT NULL DEFAULT 'administrative'
);

CREATE OR REPLACE FUNCTION reject_audit_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'audit_events is append-only';
END;
$$;

DROP TRIGGER IF EXISTS audit_events_no_update ON audit_events;
CREATE TRIGGER audit_events_no_update
BEFORE UPDATE OR DELETE ON audit_events
FOR EACH ROW EXECUTE FUNCTION reject_audit_mutation();

COMMIT;


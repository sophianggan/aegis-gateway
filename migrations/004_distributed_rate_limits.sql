BEGIN;

CREATE TABLE IF NOT EXISTS rate_limit_buckets (
    identity_hash TEXT PRIMARY KEY CHECK (length(identity_hash) = 64),
    window_start TIMESTAMPTZ NOT NULL,
    request_count INTEGER NOT NULL CHECK (request_count >= 1)
);

REVOKE ALL ON rate_limit_buckets FROM PUBLIC;
GRANT SELECT, INSERT, UPDATE ON rate_limit_buckets TO aegis_runtime;

COMMIT;

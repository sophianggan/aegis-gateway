BEGIN;

-- The runtime can mutate source records and revocation state through guarded API paths.
-- Audit events remain insert/select only and protected by the append-only trigger.
GRANT SELECT, INSERT, UPDATE, DELETE ON records TO aegis_runtime;
GRANT SELECT, INSERT, UPDATE ON revoked_tokens TO aegis_runtime;

COMMIT;

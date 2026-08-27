BEGIN;

DO $$
BEGIN
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'aegis_runtime') THEN
        CREATE ROLE aegis_runtime NOLOGIN;
    END IF;
    IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = 'aegis_auditor') THEN
        CREATE ROLE aegis_auditor NOLOGIN;
    END IF;
END
$$;

REVOKE ALL ON records, audit_events, revoked_tokens FROM PUBLIC;
GRANT SELECT, INSERT ON records TO aegis_runtime;
GRANT SELECT, INSERT ON audit_events TO aegis_runtime;
GRANT SELECT ON revoked_tokens TO aegis_runtime;
GRANT SELECT ON audit_events TO aegis_auditor;

COMMIT;


# Database migrations

Migrations are ordered, idempotent SQL files. Apply them with `aegis migrate` using a
database owner account. The runtime identity should inherit only `aegis_runtime`; an
audit export identity should inherit only `aegis_auditor`.

The database rejects updates and deletes on `audit_events`. The application additionally
links each event with an HMAC so unauthorized direct inserts are detectable.


# Database migrations

Migrations are ordered, idempotent SQL files. Apply them with `aegis migrate` using a
database owner account. The runtime identity should inherit only `aegis_runtime`; an
audit export identity should inherit only `aegis_auditor`.

The runtime role can update and retire source records and maintain token revocations only
through guarded application paths. It cannot update or delete audit evidence.

The database rejects updates and deletes on `audit_events`. The application additionally
links each event with an HMAC so unauthorized direct inserts are detectable.

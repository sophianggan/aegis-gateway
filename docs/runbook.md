# Operations runbook

## Service indicators

Track these signals without recording query or response bodies:

- availability and latency by route/status;
- policy allow/filter/deny counts;
- ingress finding counts by rule;
- egress blocks by finding kind;
- model failure/timeout rate;
- database pool saturation;
- audit-chain verification failures;
- rate-limit responses by route and identity class;
- supply-chain audit results and evidence retention.

A reasonable starting objective is 99.9% successful gateway availability per month,
excluding requests intentionally denied by policy. Alert on any audit verification failure
and any sustained increase in egress blocks.

## Deployment

1. Build and scan the immutable container image.
2. Apply migrations once using a database-owner identity.
3. Supply `aegis-secrets` from a managed secret store; do not commit a Kubernetes Secret.
4. Pin the image by digest in the deployment overlay.
5. Verify readiness, then send a public-data canary query.
6. Verify the canary request's audit chain with an auditor identity.
7. Archive the workflow's SBOM and checksum manifest with the deployed image digest.

Required secret values are `AEGIS_DATABASE_URL`, `AEGIS_JWT_SECRET`,
`AEGIS_AUDIT_HMAC_KEY`, and, when applicable, `AEGIS_MODEL_API_KEY`.

The `/metrics` endpoint contains route templates, status codes, counts, and durations only.
Scrape it from a protected monitoring network. Alert on sustained `429` responses, any
`409` audit-integrity response, egress blocks, or database-pool saturation.

## Key rotation

### Identity signing key

The bundled authenticator uses one symmetric key for local operation. Rotate by draining
old tokens, updating the secret, restarting all replicas, and issuing fresh tokens. For
zero-downtime production rotation, replace this adapter with a JWKS validator supporting
overlapping key identifiers.

### Audit signing key

Export and verify all active chain heads before rotation. Record the rotation timestamp
and old/new key identifiers in the external control log. Keep the old key in offline key
escrow for historical verification; never place key material in an audit event.

## Incident: suspected data leakage

1. Disable the affected model route or remove gateway ingress while preserving storage.
2. Revoke the involved token identifiers.
3. Export audit events and verify their chains before deeper investigation.
4. Use request/resource IDs to locate affected records; avoid copying values into tickets.
5. Add the attack form to the red-team corpus and reproduce it with synthetic values.
6. Patch the control, run the full gate, rotate exposed credentials, and restore a canary.

## Incident: audit verification failure

1. Treat a failure as integrity loss; do not rewrite or repair rows in place.
2. Snapshot the database and restrict database-owner access.
3. Compare the last externally stored chain head with the current event sequence.
4. Inspect administrative database and secret-manager access logs.
5. Start a new chain/key only after preserving evidence and documenting the boundary.

## Backup and recovery

Back up records and audit events with point-in-time recovery enabled. Encrypt backups with
a key administered separately from the database. A recovery exercise is successful only
when restored audit chains verify and a canary query passes all policy controls.

# API and SDK guide

The HTTP surface is versioned under `/v1`; operational metrics use the conventional
unversioned `/metrics` path. Generated interactive documentation is available at `/docs`
and the OpenAPI document at `/openapi.json`.

## Authentication claims

All protected endpoints require a signed bearer token. The gateway derives access only
from validated claims, never from request-body fields.

```json
{
  "sub": "service-or-user-identity",
  "clearance": "CONFIDENTIAL",
  "compartments": ["operations"],
  "roles": ["auditor"],
  "jti": "unique-token-reference",
  "iss": "aegis.local",
  "aud": "aegis-gateway",
  "iat": 1787875200,
  "exp": 1787878800
}
```

Classifications are ordered as `PUBLIC` (0), `INTERNAL` (10), `CONFIDENTIAL` (20), and
`RESTRICTED` (30). Every required compartment must be present. A non-exportable field is
never sent to the model regardless of clearance.

The bundled symmetric token issuer exists for local development. Production deployments
should replace it with managed identity validation as described in the threat model.

## Query

`purpose` is an authorization input, not free-form model context. The gateway normalizes
it to a stable slug and rejects values outside `AEGIS_ALLOWED_QUERY_PURPOSES` before
retrieving records. The environment value accepts a JSON list or comma-separated slugs.

`POST /v1/query`

```json
{
  "query": "Which inspection is due?",
  "record_ids": ["11111111-1111-4111-8111-111111111111"],
  "purpose": "maintenance planning",
  "metadata": {"workflow": "weekly-review"}
}
```

The response includes the safe answer, disclosed field names by record, the count of
filtered fields, and the request ID used to retrieve audit evidence. It never enumerates
the names or values of fields the caller could not access.

## Classified record ingestion

`POST /v1/records` requires the `data-admin` role. Classification names and numeric values
are both accepted.

```json
{
  "source": "maintenance-ledger",
  "fields": {
    "summary": {
      "value": "inspection complete",
      "classification": "INTERNAL"
    },
    "site": {
      "value": "north facility",
      "classification": "CONFIDENTIAL",
      "compartments": ["operations"]
    },
    "local_key": {
      "value": "example-control-value",
      "classification": "RESTRICTED",
      "exportable": false
    }
  }
}
```

The receipt carries a separate audit request ID, record ID, field count, highest
classification, and a canonical keyed integrity digest. The digest is independent of
JSON field ordering and is anchored in the signed audit event so operators can detect
record mutation without copying any field values into the trail.

## Audit evidence

These endpoints require the `auditor` role and apply revocation and rate-limit checks:

- `GET /v1/audit/{request_id}` returns ordered events.
- `GET /v1/audit/{request_id}/events?after_sequence=-1&limit=50` traverses large
  chains with an exclusive, append-safe sequence cursor and a bounded page size.
- `GET /v1/audit/{request_id}/verify` validates sequence, links, and event HMACs.
- `GET /v1/audit/{request_id}/export` returns a signed evidence bundle containing the
  verified events, chain head, algorithm, and bundle signature.

An export fails with `409 audit_integrity_failed` if the stored chain is absent or invalid.
Auditors holding the separately controlled verification key can validate a bundle offline
with `AuditTrail.verify_bundle`.

## SDK administration

```python
from aegis_sdk import (
    AegisClient,
    Classification,
    ClassifiedValue,
    RecordInput,
)

records = [
    RecordInput(
        source="controlled-import",
        fields={
            "summary": ClassifiedValue(
                value="inspection complete",
                classification=Classification.INTERNAL,
            )
        },
    )
]

async with AegisClient("https://gateway.internal", token) as client:
    receipts = await client.create_records(records, concurrency=4)
    bundle = await client.export_audit(receipts[0].request_id)
```

Bulk SDK ingestion bounds concurrency between 1 and 32 and preserves input order. A
failed request raises `AegisClientError`; callers choose whether to retry the full batch or
the remaining records.

## Rate limits

Limits are keyed by trusted principal subject. A rejected request returns status `429`, a
stable `rate_limit_exceeded` error, and `Retry-After` in seconds. The in-process token
bucket is appropriate for the stateless reference service; deployments requiring a hard
global quota across replicas should provide a distributed `RateLimiter` adapter.

## Errors

Errors use one envelope:

```json
{
  "error": {
    "code": "authorization_denied",
    "message": "auditor role is required",
    "details": {}
  }
}
```

Stable codes include `authentication_failed`, `authorization_denied`, `policy_violation`,
`rate_limit_exceeded`, `audit_integrity_failed`, and `upstream_model_error`. Security
headers disable caching, MIME sniffing, framing, and referrer forwarding.

## Metrics

`GET /metrics` returns Prometheus text with request counts and cumulative duration buckets
using HTTP method, route template, and status only. Raw URLs, record IDs, subjects, query
text, field values, and model responses are deliberately excluded. Set
`AEGIS_METRICS_ENABLED=false` to return 404 from this endpoint.

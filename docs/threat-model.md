# Threat model

## Protected assets

- Field values above a caller's clearance or outside their compartments
- Values marked non-exportable, even for highly cleared callers
- Credentials, signing keys, bearer tokens, and audit integrity
- Model boundary instructions and policy configuration
- Availability of the API and integrity of its decisions

## Trust boundaries

The caller, record sources, model endpoint, and response consumer are independently
untrusted. The gateway process and its policy configuration are trusted. PostgreSQL is
trusted for availability but not solely trusted for audit integrity; HMAC verification is
designed to reveal database-level mutation.

## Threats and controls

| Threat | Control | Verification |
|---|---|---|
| Caller claims a higher clearance | Clearance comes only from validated token claims | Identity unit tests |
| Revoked credential is replayed | Revocation checked before any retrieval | End-to-end revoked-token test |
| One principal exhausts gateway capacity | Identity-keyed token bucket returns bounded retry guidance | Unit and HTTP integration tests |
| Restricted field reaches a model | Field-level mandatory policy builds a new safe context | Policy and query-path tests |
| Record contains prompt injection | High-confidence instructions are quarantined per field | Retrieved-injection test |
| Caller sends prompt injection | Ingress guard rejects before retrieval | Adversarial security gate |
| Model reconstructs or emits a protected value | Exact protected-value matching and credential patterns fail closed | Egress exfiltration tests |
| Error or telemetry leaks payloads | Stable errors and metadata-only structured logs | API contract and audit tests |
| Audit rows are changed or reordered | Database mutation trigger plus HMAC hash chain | Tampering test |
| Model endpoint is unavailable or malformed | Strict parsing and no unguarded fallback | Provider adapter tests |
| A compromised pod scans the cluster | Default-deny network policy and explicit destinations | Manifest review |
| Container privilege escalation | Non-root, read-only root, dropped capabilities, seccomp | Container and manifest review |
| Build artifact is replaced after testing | Wheel, SBOM, image ID, revision, and SHA-256 evidence manifest | Supply-chain CI job |

Signed identity claims are bounded after verification. A principal may carry at most 50
roles and 50 compartments, each no longer than 64 characters; oversized claims fail
authentication before policy evaluation.

## Abuse cases in CI

The red-team corpus includes instruction override, role reassignment, control-token
delimiters, Unicode normalization tricks, secret extraction, structured credentials, and
exact protected-value exfiltration. It also contains benign prompts to detect excessive
refusal. Any known leak or new false refusal fails CI.

## Security properties

Aegis is designed to demonstrate:

- no intentionally filtered value appears in the model input;
- no known protected value or credential pattern appears in a successful response;
- a completed request has a verifiable, ordered decision history;
- normal analytical questions remain usable under the same controls.

## Non-goals and residual risk

- Pattern matching is not a complete defense against novel encoded exfiltration. Add
  organization-specific classifiers and human review for the highest-impact workflows.
- Symmetric JWT signing is provided for a self-contained demo. Production deployments
  should validate short-lived tokens from a managed identity provider and rotate keys.
- The model could infer sensitive facts from authorized aggregates. Data owners must
  classify derived data and define purpose/aggregation policy appropriate to their domain.
- An attacker controlling both the database and the audit signing key can forge a chain.
  Keep those controls under separate administrative identities and export chain heads.
- This reference implementation is not itself a compliance certification.

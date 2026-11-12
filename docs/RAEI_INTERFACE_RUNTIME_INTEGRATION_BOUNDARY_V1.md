# RAEI–Interface Runtime Integration Boundary V1.0

**Status:** Architecture decision record — proposed boundary, not an implementation certification.

## 1. Current component responsibilities

| Component | Responsibility | Not equivalent to |
|---|---|---|
| `raei/project_record.py` and `raei/integrity.py` | Source-to-final project snapshot, revision history, gate links and chain validation | Durable event store or approval authority |
| `raei/store.py` | SQLite learning-practical records, optimistic versions, idempotency and hash-chained audit events | Authoritative production record |
| `raei/ledger.py` | Local JSON learning ledger with its own hash chain | Second writable replica of SQLite |
| `rhemascript/interfaces/contracts.py` | Common JSON request-envelope validation | Interface-specific business semantics |
| `rhemascript/interfaces/runtime.py` | Local envelope handling with disclosure and authority guards | Provider router, durable queue, or RAEI dispatcher |
| `rhemascript/interfaces/external.py` | Explicit provider transport and audit boundary | Default-on integration or implicit authority grant |

Similar use of the word “evidence” does not make these records interchangeable.

## 2. Integration decision

Do not directly merge project snapshots into the learning store, mirror the JSON ledger into SQLite, or infer that any IF-01..IF-18 identifier belongs to RAEI.

The shared interface runtime currently validates a common envelope and returns a local acknowledgement. It does not dispatch to business services. A future RAEI adapter must be a separately reviewed component with a named operation contract. The generic interface registry must not imply that mapping.

## 3. Proposed service boundary

A future adapter may expose these conceptual operations:

- `validate_project_snapshot`: validate a supplied snapshot with `validate_project_chain`; read-only.
- `compare_project_snapshots`: compare two snapshots with `compare_project_records`; read-only.
- `read_learning_unit`: retrieve a learning unit from an explicitly configured `EvidenceStore`; read-only.
- `record_learning_assessment`: record an assessment only when separately authorized, with explicit actor identity, expected version and idempotency key.

The first three operations are read-only. The fourth is a durable learning-record write and requires its own authorization, actor attribution, audit event and idempotency policy. None grants generation, spend, external-write, final-acceptance or publishing authority.

The service boundary should use typed domain arguments/results. It must not accept arbitrary Python objects, raw SQL, untrusted file paths or callback names.

## 4. Data ownership and consistency

- The project snapshot remains the source-to-final traceability record.
- SQLite remains the learning-practical record and transactional audit log.
- The JSON ledger remains a separate local format until a separately approved migration proves schema equivalence, event-history preservation, backup/restore safety and rollback.
- No dual-write is permitted. Any future cross-domain update requires an explicit outbox/reconciliation design; partial writes must be detectable and recoverable.
- References crossing domains must be opaque, non-empty identifiers. A learning assessment reference is not automatically a production approval reference.

## 5. Required safeguards

Before implementation can be accepted, tests must demonstrate:

1. Unknown operations and malformed envelopes fail closed.
2. Read operations cannot mutate either domain.
3. Learning writes require explicit authorization and actor attribution.
4. Expected-version checks and idempotency survive retries and concurrent requests.
5. Audit-chain verification runs before and after restore.
6. Project-chain validation never grants gate approval or production authority.
7. No call reaches YouTube, Google OAuth, generation, spend, publishing or another provider through this adapter.
8. Errors do not leak credentials, private paths or raw evidence payloads.
9. Contract tests cover the gateway-to-adapter boundary; domain tests cover each operation.
10. A rollback plan preserves the original project snapshot and learning store independently.

## 6. Explicit non-goals

This document does not assign an interface ID, implement a dispatcher, migrate data, create credentials, activate provider access, approve a project gate, or authorize production work. It is an integration contract proposal for review.

## 7. Acceptance sequence

1. Confirm the operation contract and ownership of the RAEI adapter.
2. Decide whether SQLite alone is the learning write model; keep the JSON ledger separate during any migration.
3. Implement the adapter in an isolated branch with contract tests.
4. Run full CI on the exact candidate head and inspect the report.
5. Review security, consistency and rollback evidence.
6. Obtain explicit human acceptance before merging or enabling consequential operations.

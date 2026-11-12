# RhemaScript Signed Approval Credential Contract V1

Status: verification foundation and synthetic tests only. Not connected to YouTube publishing or provider activation.

## Purpose

Replace caller-supplied booleans and generic authority dictionaries with signed, actor-attributed approvals narrowly bound to one consequential action, project, project version, and request. RhemaScript is a verifier, not an approval issuer.

## Credential schema

`RhemaScript.ApprovalCredential.v1` contains exactly:
- `approval_id`: unique immutable approval record ID
- `issuer`: configured trusted approval issuer
- `actor_id`: authenticated human actor identity asserted by the trusted issuer
- `action`: one exact consequential action, e.g. `PUBLISH` or `FINAL_ACCEPTANCE`
- `project_id` and `project_version`: exact project scope
- `request_id`: exact request scope; no cross-request reuse
- `issued_at` and `expires_at`: timezone-aware timestamps with a short bounded lifetime
- `nonce`: unique replay-prevention value
- `key_id`: identifies the issuer's active signing key
- `signature`: Ed25519 signature over canonical JSON excluding the signature field

The verifier enforces exact fields, issuer and key trust, Ed25519 public-key signature verification, action/project/version/request matching, issue-time skew, expiry, maximum lifetime, and replay/revocation state.

## Trusted issuer boundary\n\n`rhemascript/core/approval_issuer.py` defines a request-only `ApprovalCredentialSource` protocol. The caller supplies the exact action, project, project version and request ID, but does not supply an actor ID or claimed identity. The issuer must authenticate the operator independently, derive actor identity from its own authenticated session, enforce issuer-side policy, and return an Ed25519-signed credential. No issuer implementation or credential-minting key is included in RhemaScript.\n\n## Trust and storage boundary

1. The approval issuer must authenticate the human through an independently controlled identity provider or equivalent trusted local operator-authentication boundary.
2. The Ed25519 private signing key must be held by the issuer, not by the RhemaScript client, repository, browser, or caller. RhemaScript receives only the 32-byte Ed25519 public verification keys; the verifier cannot mint credentials.
3. The `consume_many_once` adapter must atomically reject revoked approvals and previously consumed `(approval_id, nonce)` pairs while recording every first use in a batch, or record none. `rhemascript/core/approval_store.py` now provides a dedicated SQLite implementation using immediate transactions, durable tables, owner-only POSIX file permissions, replay uniqueness and revocation records. It is separate from RAEI's EvidenceStore and JSON ledger. A process-local set or cache is not sufficient.
4. Production storage must provide durable transactions, access controls, backup, audit retention, key rotation, revocation and recovery procedures.
5. Separate `FINAL_ACCEPTANCE` and `PUBLISH` approvals must be issued as distinct records, with distinct approval IDs/nonces and authenticated actors. Both must bind to the same project, project version and request.
6. A failed or partial multi-approval consumption must not leave one approval silently reusable. Production implementation needs an atomic batch-consumption transaction across all required approvals.
7. Audit records must retain issuer, actor, action, project/version, request, approval ID, key ID, decision, and UTC timestamps, but never secrets or signing keys.

## Current implementation boundary

`rhemascript/core/approvals.py` is a verification-only Ed25519 primitive. It has no signing or minting method. Its injected atomic-consumption callback is mandatory. Unit tests use a test-only Ed25519 private key and a private temporary SQLite database to exercise cryptographic, persistence and policy checks. The private key exists only in tests.

The verifier supports `verify_many_and_consume` so distinct `FINAL_ACCEPTANCE` and `PUBLISH` credentials can be validated first and consumed as one atomic batch. The signed approval verifier is now wired into `YouTubeClient.upload_video` and `set_thumbnail`. When IF-18 is configured, `ExternalIntegrationGateway` independently verifies and atomically consumes the two signed credentials before the first provider write, caches the request-bound actor attribution for resumable chunks, and clears that authorization after the final chunk or thumbnail operation. Direct synthetic-transport tests verify and consume credentials in the client boundary. The gateway rejects boolean-only publishing authority and fabricated audit claims without its configured trusted verifier. Provider audit events include the two approval IDs, actor IDs and issuer. The approval issuer itself, authenticated operator session, production key custody/rotation, production database deployment, and independent security review remain outstanding. This code is a gated integration implementation, not a live production activation.

## Required next implementation stages

- Define a trusted issuer interface and operator authentication policy.
- Implement durable approval and revocation storage with atomic batch consumption.
- Integrate two separately signed approvals into YouTube upload and thumbnail write paths; reject boolean-only authority.
- Bind approval records to exact request IDs and immutable project versions, and include verified actor attribution in the audit trail.
- Add negative tests for missing, wrong-actor, wrong-action, wrong-project, stale-version, expired, revoked, replayed, and partial-batch approvals.
- Complete independent security review before any provider enablement or live connection.

No deployment, live OAuth, upload, thumbnail mutation, or publishing is authorized by this work.
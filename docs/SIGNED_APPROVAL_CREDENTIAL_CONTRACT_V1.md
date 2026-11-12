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
- `signature`: HMAC-SHA256 over canonical JSON excluding the signature field

The verifier enforces exact fields, issuer and key trust, constant-time signature comparison, action/project/version/request matching, issue-time skew, expiry, maximum lifetime, and replay/revocation state.

## Trust and storage boundary

1. The approval issuer must authenticate the human through an independently controlled identity provider or equivalent trusted local operator-authentication boundary.
2. The signing key must be held by the issuer, not by the RhemaScript client, repository, browser, or caller. RhemaScript receives verification keys only.
3. The `consume_once` adapter must atomically reject revoked approvals and previously consumed `(approval_id, nonce)` pairs while recording first use. A process-local set or cache is not sufficient.
4. Production storage must provide durable transactions, access controls, backup, audit retention, key rotation, revocation and recovery procedures.
5. Separate `FINAL_ACCEPTANCE` and `PUBLISH` approvals must be issued as distinct records, with distinct approval IDs/nonces and authenticated actors. Both must bind to the same project, project version and request.
6. A failed or partial multi-approval consumption must not leave one approval silently reusable. Production implementation needs an atomic batch-consumption transaction across all required approvals.
7. Audit records must retain issuer, actor, action, project/version, request, approval ID, key ID, decision, and UTC timestamps, but never secrets or signing keys.

## Current implementation boundary

`rhemascript/core/approvals.py` is a verification-only primitive. It has no signing or minting method. Its injected atomic-consumption callback is mandatory. Unit tests use a test-only signer and in-memory callback to exercise cryptographic and policy checks.

This foundation is **not yet wired into** `YouTubeClient.upload_video` or `set_thumbnail`. Existing boolean parameters and the current caller-supplied gateway authority dictionary remain a production blocker. Do not infer that this document or verifier tests make those paths production-safe.

## Required next implementation stages

- Define a trusted issuer interface and operator authentication policy.
- Implement durable approval and revocation storage with atomic batch consumption.
- Integrate two separately signed approvals into YouTube upload and thumbnail write paths; reject boolean-only authority.
- Bind approval records to exact request IDs and immutable project versions, and include verified actor attribution in the audit trail.
- Add negative tests for missing, wrong-actor, wrong-action, wrong-project, stale-version, expired, revoked, replayed, and partial-batch approvals.
- Complete independent security review before any provider enablement or live connection.

No deployment, live OAuth, upload, thumbnail mutation, or publishing is authorized by this work.
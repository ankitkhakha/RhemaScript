# Signed Approval Credential Contract V1.0 — Verification Foundation

## Current implementation status

This feature adds a local verification and replay-consumption library. It does **not** issue credentials, generate keys, connect to an external issuer, authorize Google OAuth scopes, or dispatch provider actions. It is not yet wired into YouTube upload, thumbnail or publishing paths.

The current YouTube integration still has boolean-only approval inputs documented as a production blocker. This library does not remove that blocker until a separate integration and authenticated local signer are reviewed and approved.

## Credential model

Credentials use Ed25519 signatures over canonical JSON and bind:
- approval ID and one-time nonce;
- trusted issuer and key ID;
- authenticated actor ID;
- exact action;
- exact RhemaScript project ID and project version;
- exact request ID;
- issued-at and expiry timestamps.

The verifier rejects malformed schemas, unknown issuers/keys, invalid signatures, wrong scopes, expired or future-issued credentials, excessive lifetime and replay. Multi-approval batches require distinct actors by default and are passed to the consumption store as one atomic batch.

## Verified-object boundary

A `VerifiedApproval` is not trusted merely because it has the right dataclass fields. The verifier issues a process-local proof token and registers the exact object identity. The public consumption method rejects caller-constructed and copied objects. This is an in-process capability boundary, not protection against arbitrary hostile code executing inside the same Python process.

## Consumption and revocation

The SQLite store:
- requires an owner-owned private parent directory and owner-only database file;
- rejects symlinked directory components;
- consumes an entire batch in one transaction or none;
- rejects expired, revoked, duplicate or previously consumed approvals;
- records actor attribution for consumption and revocation;
- creates owner-only backups;
- supports HMAC state checkpoints over consumed and revoked records.

Retain the HMAC checkpoint and its 32-byte-or-longer key outside the database. A database-local hash alone is not immutable storage. The key must not be committed to Git, logged or placed beside the database.

The SQLite path checks reduce other-user and accidental path-substitution risks. They do not eliminate same-user race conditions or protect against arbitrary code with the same OS account.

## Issuer and identity boundary

The issuer interface is a protocol only. No credential issuer or local signer is included in this feature. A future local signer must:
- keep the Ed25519 private key outside the repository in OS-protected storage;
- require an explicit interactive operator confirmation for every signature;
- bind the exact action, project, project version and request fingerprint;
- support key rotation and revocation;
- never allow RAEI to sign its own independent-review or publishing credentials.

The verifier trusts the configured issuer public keys. It does not independently authenticate the human behind an actor ID; that responsibility belongs to the trusted signer/identity process.

## Required next integration

Before any provider write or RAEI independent-review status can be enabled:
1. Implement and threat-model an explicit local human signer.
2. Bind signer identity and role to approved public keys.
3. Integrate the verifier/store into the current YouTube and external gateway without changing read-only OAuth scope.
4. Require two distinct actors for publish: one final acceptance and one publish authorization, both bound to the same exact request.
5. Add end-to-end replay, race, key-rotation, revocation, tamper and no-network tests.
6. Keep upload/publish disabled until the owner separately authorizes Google scope expansion and live channel verification.

No credential or key was created by this work.

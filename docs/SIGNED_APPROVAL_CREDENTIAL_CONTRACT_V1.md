# Signed Approval Credential Contract V2.0 — Exact Artifact Binding

## Purpose and authority boundary

This contract defines verification of externally signed Ed25519 approvals. RhemaScript does not issue credentials, create signing keys, authenticate human operators, authorize Google OAuth scopes, or enable provider writes by itself. The trusted issuer must authenticate each human independently and derive actor identity from its authenticated session.

## Credential versions

### V1 — legacy project/request scope

RhemaScript.ApprovalCredential.v1 binds approval ID, nonce, issuer, key ID, actor ID, action, project ID, project version, request ID, issued-at and expiry. V1 remains available for legacy workflows that do not require final-artifact authorization.

V1 credentials are rejected whenever an exact artifact binding is required. They cannot authorize governed finding/knowledge reviews, YouTube publication or thumbnail writes.

### V2 — exact final-artifact scope

RhemaScript.ApprovalCredential.v2 contains every V1 field plus:
- artifact_id: exact final-film artifact identifier;
- artifact_version: exact artifact revision;
- artifact_sha256: lowercase SHA-256 digest of the final-film bytes;
- artifact_size_bytes: exact byte length.

All fields are covered by the Ed25519 signature over canonical JSON. The verifier requires the signed artifact tuple to equal the independently byte-verified artifact tuple. Missing, malformed, stale or mismatched fields fail closed.

## Publication authorization

A YouTube video upload requires one atomic two-credential V3 batch:
1. FINAL_ACCEPTANCE — final acceptance by one independently authenticated human;
2. PUBLISH — publication authorization by a different independently authenticated human.

Both V3 credentials preserve the V2 exact-artifact fields and add signed subject, role, authentication context/time, identity session, identity-policy version and identity-provider claims. Both must bind the same project ID, project version, request ID, final-film artifact ID, artifact version, SHA-256 and byte length. The verifier enforces the trusted identity policy, distinct actor identities, unique approval IDs/nonces, expiry and atomic replay/revocation checks.

## Evidence verification and upload byte identity

Before approval consumption, RhemaScript:
- validates the complete Source-to-Final Evidence Pack;
- byte-verifies all approved/accepted/verified artifacts and capability-referenced artifacts against local_path and declared SHA-256;
- resolves the final EDITED_FILM artifact associated with the final-film evidence reference;
- constructs the exact artifact binding from the verified file bytes.

For upload, the selected video file is opened without following a symlink, copied into a private temporary spool, hashed while copying, and compared to the signed digest and byte length. The provider upload reads from that verified spool, not by reopening the caller's path. A changed, substituted or mismatched file is rejected before any provider request.

Thumbnail writes are currently disabled. Final-film approvals do not authorize thumbnail bytes. A separate signed thumbnail-artifact approval contract must bind the exact thumbnail bytes and pass independent security review before thumbnail writes can be enabled.

## Provider boundary

The IF-18 gateway independently checks that both approval objects:
- are exact in-process objects issued by ApprovalVerifier;
- have the required actions and distinct actors;
- share the same trusted issuer, project, version, request and exact artifact tuple;
- have not expired.

Caller-supplied booleans or reconstructed dataclass objects do not satisfy this boundary.

## Replay, revocation and history

The SQLite approval store atomically consumes a batch or none, rejects replay/revocation/expiry, and stores the signed credential schema, original Ed25519 signature, issuer/actor/action/request scope and exact artifact tuple. It stores no private signing keys and remains separate from the RAEI readiness/activity registry. A verifier can re-check a persisted signature against the configured trusted public key after process restart; expiry is reported separately from cryptographic signature validity.

The V3 HMAC checkpoint snapshot includes the persisted credential schema, signature and exact artifact tuple. A database-local hash or HMAC checkpoint is not immutable storage. Retain checkpoint keys and independently retained checkpoint records outside the database. This implementation does not claim protection against an attacker who can rewrite the database, the external checkpoint and its key.

## Remaining prerequisites

- A production trusted issuer must authenticate human identity and roles, derive actor identity from the authenticated session and protect private signing keys outside the repository.
- Public-key rotation, revocation, issuer outage and recovery procedures require operational testing.
- Signature re-verification is implemented for stored approval records, but independent checkpoint-anchor retention remains an operational responsibility and has not been automated.
- Exact-head CI, adversarial tests, full Source-to-Final invalidation and independent security review must pass.
- Live provider writes remain disabled until the owner separately authorizes the required Google permissions and live channel verification.
- No credential or signing key was created by this implementation.

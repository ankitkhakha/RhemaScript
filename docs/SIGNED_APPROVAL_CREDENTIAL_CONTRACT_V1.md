# RhemaScript Signed Approval Credential Contract V1

Status: implemented as a gated code path and validated with synthetic tests only. No live issuer, OAuth connection, provider activation or publishing is configured.

## Purpose

Replace caller-supplied booleans with signed, actor-attributed approvals narrowly bound to one consequential action, project, project version and request. RhemaScript verifies approvals; it does not issue or mint them.

## Credential schema

`RhemaScript.ApprovalCredential.v1` contains exactly:
- `approval_id`: unique immutable approval record ID
- `issuer`: configured trusted approval issuer
- `actor_id`: authenticated human identity asserted by the trusted issuer
- `action`: exact action, including `FINAL_ACCEPTANCE` or `PUBLISH`
- `project_id` and `project_version`: exact project scope
- `request_id`: exact request scope
- `issued_at` and `expires_at`: timezone-aware timestamps with a bounded lifetime
- `nonce`: unique replay-prevention value
- `key_id`: issuer signing-key identifier
- `signature`: Ed25519 signature over canonical JSON excluding the signature field

The verifier enforces exact fields, trusted issuer and key ID, Ed25519 signature validity, action/project/version/request matching, issue-time skew, expiry, maximum lifetime, distinct actor identities when required, and replay/revocation state.

## Trusted issuer boundary

`rhemascript/core/approval_issuer.py` defines a request-only `ApprovalCredentialSource` protocol and `request_publish_approval_credentials` helper for obtaining the two scoped credentials. The caller supplies action, project, project version and request ID, but no actor ID or claimed identity. The issuer must authenticate the human independently, derive actor identity from its authenticated session, enforce issuer-side policy, and return an Ed25519-signed credential. No issuer implementation or private signing key is included in RhemaScript.

## Key custody

1. The Ed25519 private signing key remains with the separately controlled issuer. RhemaScript receives only 32-byte Ed25519 public verification keys and cannot mint credentials.
2. The verifier accepts a key-ID-to-public-key mapping, allowing controlled overlap during key rotation. Production key provisioning, rotation and revocation policy must be operated by the issuer owner. Provision each replacement under a new immutable key ID, independently verify its fingerprint, overlap only for the maximum credential lifetime plus clock skew, then remove the old key. Never reuse a key ID for different key material. For compromise, disable the affected key immediately, stop issuance, revoke outstanding approvals where known, invalidate active authorization-cache sessions, preserve audit records and re-provision trust through a separately authenticated administrative process. Recovery must restore consumed and revoked state from an integrity-checked backup; never roll back replay protection.
3. Test private keys are synthetic and exist only in unit tests. No production private key is stored in the repository.

## Durable approval state and audit

`rhemascript/core/approval_store.py` provides a dedicated SQLite implementation using immediate transactions, durable uniqueness constraints, replay prevention, revocation records and owner-only POSIX file permissions. It is deliberately separate from RAEI's learning EvidenceStore and JSON ledger.

Atomic batch consumption records both approvals or neither. Durable consumed records include issuer, actor, action, project, project version, request ID, key ID, issue/expiry timestamps and consumption time. Provider audit events include the two approval IDs, actor IDs and issuer, but never signatures, private keys or credentials.

Production deployment still requires controlled database placement, backups, access controls, retention, restore testing and operational revocation procedures. The current local SQLite adapter is a tested implementation, not a deployed production service. Its pathname checks and owner-only parent directory reduce exposure, but SQLite opens the pathname itself; the adapter does not claim race-free descriptor-relative database opening. Production placement therefore requires OS-level directory ownership, service isolation and filesystem controls.

## YouTube/provider enforcement

`YouTubeClient.upload_video` and `set_thumbnail` require two separate signed credentials: `FINAL_ACCEPTANCE` and `PUBLISH`. Both must bind to the same project, immutable project version and request ID, and must identify distinct authenticated actors.

When IF-18 is configured, `ExternalIntegrationGateway` independently verifies and atomically consumes both credentials before the first provider write. Boolean-only publishing authority and fabricated audit claims are rejected. The request-bound authorization context is reused only across resumable upload chunks, then cleared after the final chunk, terminal client error, transport failure or audit failure. Abandoned cache entries expire after 15 minutes and the cache is bounded to 256 requests. Thumbnail authorization is cleared after its request. A request that begins with `UPLOAD_SESSION` may continue only with `UPLOAD_CHUNK`; the same approval request cannot start another upload or be repurposed for a thumbnail write. Reusing a completed request ID or consumed credential is rejected by durable replay protection.

For direct synthetic transport tests, the client verifies and consumes the credentials itself. The live provider path still requires an explicitly configured IF-18 gateway.

## Remaining production prerequisites

- Deploy a separately controlled approval issuer integrated with a real operator-authentication boundary.
- Provision public verification keys and document issuer key rotation, revocation and recovery.
- Deploy and operate the durable approval database with backup, access controls, monitoring and retention.
- Complete independent security review, threat modelling and operational acceptance.
- Perform a separately authorised, owner-operated read-only YouTube connection check before any consideration of provider activation.

No deployment, live OAuth, upload, thumbnail mutation or publishing is authorized by this work.
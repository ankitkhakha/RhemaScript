# Provider Authorization Lease and Fencing Design V1

## Status

**Design contract only — not implemented and not production-ready.** The current IF-18 path revalidates approvals immediately before transport, but that is a point-in-time read. A revocation can still commit after the read and before provider acceptance. A local SQLite transaction cannot atomically include a remote provider request.

## Security objective

Prevent an approval that is revoked, expired, superseded, or replayed from authorizing a provider mutation after the revocation/supersession has become authoritative. The enforcement point must be the component that serializes authorization state with dispatch acceptance—not merely the caller immediately before opening a socket.

## Required lease claims

A lease must be issued by an independently administered, authenticated authorization coordinator and bind all of the following:

- lease ID and unique nonce;
- issuer and authorization-coordinator identity;
- exact provider, interface, operation and HTTP method;
- exact canonical request fingerprint, including destination, request body digest and relevant immutable headers;
- project ID, project version, request ID and exact final-artifact ID/version/SHA-256/byte length;
- both consumed approval IDs, nonces, credential digests and distinct authenticated subjects;
- monotonic fencing generation for the authorization resource;
- issue time, short expiry, and single-use dispatch state.

The coordinator must verify current approval consumption/revocation, identity assurance, signing-key status, project/artifact binding and request scope as part of lease acquisition. It must not accept caller-supplied booleans or reconstructed approval objects as proof.

## Required state transitions

1. **Acquire:** atomically compare the current authorization generation and both approval states, then issue one lease and advance/record a monotonically increasing fence. Duplicate acquisition for the same dispatch nonce must return the same lease or reject; it must never create a second independently usable lease.
2. **Revoke/supersede:** commit revocation and advance the same authorization generation in the coordinator's linearizable state store. All older fence generations become unusable.
3. **Dispatch acceptance:** the provider or a trusted provider-side gateway validates the lease, exact request fingerprint, expiry, single-use nonce and current fence generation atomically with accepting the mutation. A client-side validation followed by an ordinary HTTP request is insufficient.
4. **Complete/indeterminate:** record the provider's definitive operation ID and outcome against the lease. If the connection is lost after dispatch may have begun, mark the outcome indeterminate and prohibit automatic replay. Reconciliation must use the provider operation ID/idempotency contract, not a fresh lease for an ambiguous duplicate.
5. **Expiry/recovery:** expired, consumed, revoked, mismatched, stale-generation or unavailable-coordinator leases fail closed. Recovery must not reset or reuse fence generations.

## Required concurrency and adversarial tests

- Revocation commits immediately before lease acquisition: acquisition rejects.
- Revocation races with acquisition: exactly one serialized order wins; no stale lease is accepted.
- Revocation commits after lease issuance but before dispatch acceptance: provider/gateway rejects the stale fence.
- Lease expires while queued or during delayed dispatch: acceptance rejects if expiry has passed at the enforcement point.
- Old fencing generation is replayed after a newer generation exists: reject.
- Duplicate lease nonce or duplicate dispatch: at most one provider mutation is accepted.
- Request body, destination, method, project version, artifact digest, or approval tuple changes after lease issuance: reject.
- Coordinator outage, stale replica, clock uncertainty, lost response, or audit failure: fail closed or report an explicit indeterminate outcome; never silently retry.
- Two concurrent lease acquisitions for overlapping approval IDs: coordinator serializes them and prevents double-use.

Tests using in-memory or SQLite fakes are synthetic contract tests only. They cannot prove linearizability, cross-region consistency, provider-side enforcement, or resistance to a privileged coordinator compromise.

## Deployment prerequisites

- Independently administered, linearizable lease coordinator and durable fencing counter.
- Authenticated service-to-service identity and mutually authenticated transport.
- HSM/KMS-backed signing key custody and independent key-operator controls.
- Provider-side lease/fence validation or a trusted gateway that is itself the provider's enforced ingress and can serialize dispatch with revocation.
- Durable single-use nonce/idempotency ledger, immutable audit sink and tested disaster recovery.
- Independent security review, fault-injection testing, revocation-latency measurements and documented incident procedures.

## Current RhemaScript boundary

The current implementation rechecks expiry, identity freshness, signing-key fingerprint/status and (when using the bound SQLite store) consumed/revoked state. The SQLite implementation now reads consumed and revoked flags from one consistent read snapshot. This improves consistency of the local state observation; it does **not** lock revocation through provider acceptance and does not close the read-to-dispatch race.

No lease coordinator, provider-side fencing contract, production identity provider, production key registry, HSM/KMS signer, or independent audit system is currently established by the repository evidence. Until those controls exist and are independently tested, CI-green synthetic PUBLISH tests must not be interpreted as permission or readiness for live provider writes.


## Synthetic reference model implementation — 13 November 2026

The repository now includes `rhemascript/core/authorization_lease_model.py` and adversarial tests in `tests/test_authorization_lease_model.py`. This is a local SQLite state-machine model for exercising the ordering and fencing invariants in this document. It is intentionally not connected to `ExternalIntegrationGateway` or any live provider transport.

The model serializes lease issuance, approval revocation, and dispatch-acceptance decisions with SQLite write transactions. It binds each lease to a resource, distinct approval IDs, dispatch nonce, request fingerprint, expiry and monotonic generation. It rejects stale generations, approval revocation, expired leases, changed request fingerprints and repeated dispatch acceptance. A newer lease supersedes an older generation for the same resource.

**Security boundary:** this model is a synthetic executable contract, not the independently administered coordinator required for production. It has no authenticated caller identity, dual-approval signature verification, HSM/KMS lease signing, independent durable audit, cross-region linearizability, provider-side fencing or remote dispatch integration. In particular, a local SQLite acceptance decision cannot atomically serialize a remote provider's acceptance with approval revocation. The model must not be used to enable production writes or described as closing the distributed read-to-dispatch race.

The tests exercise revocation after issuance, revocation before acquisition, stale-generation replay, changed fingerprints, expiry at acceptance, duplicate dispatch, overlapping approval sets and concurrent duplicate acceptance. Passing these tests validates only the local state-machine model.


## Acquisition expiry race hardening — 13 November 2026

The synthetic model rechecks lease expiry after acquiring SQLite's serialized write lock, not only before attempting the lock. This prevents a lease that expires while queued behind another writer from being issued using a stale pre-lock timestamp. The adversarial test holds the writer lock until the requested lease expires and verifies acquisition fails closed. This is a local model invariant only; production coordinators must apply the same rule using their authoritative time source and serialized transaction boundary.


## Coordinator identity, signing and audit contract

The production coordinator must have a trust domain separate from the RhemaScript worker and from the provider credential resolver. The following is a deployment contract, not an assertion that these services currently exist.

### Caller authentication

- Accept coordinator requests only over mutually authenticated service transport.
- Validate the caller workload identity against an explicit allowlist of service identities, environment, project and audience; reject user-session tokens and ambient credentials.
- Bind each request to a short-lived, unique request ID and reject replayed authentication assertions.
- Authorize distinct operations separately: acquire, revoke, inspect, complete and reconcile. A worker allowed to acquire a lease must not thereby gain revoke or key-administration privileges.
- Require independent operator identity and step-up authentication for key rotation, emergency invalidation, policy changes and recovery operations.

### Lease signing and verification

- Sign the exact canonical lease claims with an asymmetric key held by an HSM/KMS-backed service. The worker must never receive private signing material.
- Include a schema/version, signing key ID, coordinator issuer, audience, lease ID, nonce, resource, operation scope, request fingerprint, project/artifact binding, approval tuple, generation, issued-at and expiry.
- Use a fixed, reviewed canonical serialization and domain-separated signature input. Reject unknown critical claims, duplicate JSON keys, invalid encodings, unsupported algorithms, missing fields and algorithm/key-type mismatches.
- Verifiers pin the permitted issuer and audience, resolve keys only through the authenticated key registry, enforce key validity/revocation and retain historical public-key material for audit.
- Key rotation must support overlap without accepting revoked or expired signing keys. Emergency invalidation must advance the authorization generation and invalidate all outstanding leases.

### Audit and recovery

- Emit append-only, independently stored events for lease requested, granted, denied, revoked, accepted, completed, indeterminate, expired and reconciled.
- Each event binds the prior event digest or a monotonic audit sequence, coordinator identity, lease ID, generation, request fingerprint, approval IDs and outcome. Never log credentials, bearer tokens, raw approval secrets, media bytes or sensitive query/header values.
- Require durable audit acknowledgement before granting a lease and before reporting a dispatch outcome as definitive. If audit durability is unavailable, fail closed or return an explicit indeterminate state.
- Persist idempotency mapping from dispatch nonce to one lease and one provider operation ID. A lost response must be reconciled against this mapping; it must not silently mint a replacement lease or repeat a potentially accepted mutation.
- Recovery must restore the fencing counter, revocations, outstanding/consumed nonces and audit chain from independently protected checkpoints. A restored generation must be strictly greater than every generation that may have been issued before the failure.

### Canonical request binding

The fingerprint contract must define a versioned, unambiguous encoding over provider origin, HTTP method, normalized path, exact query representation, operation, content digest, project and artifact version/digest, and an explicit allowlist of semantic headers. Use length-prefixed fields or a reviewed canonical format; do not concatenate delimiter-separated strings. Exclude volatile transport headers only when they cannot change provider semantics. The provider-side enforcement point must recompute or independently validate the same binding at acceptance.

### Required fault-injection scenarios

- Coordinator identity is valid but has the wrong audience, environment, project or operation privilege.
- A caller replays a previously used acquisition request ID or dispatch nonce.
- Signing key is revoked between lease issuance and dispatch acceptance.
- Key registry is stale, unavailable, equivocal or returns a key with a mismatched issuer/algorithm.
- Audit sink acknowledges late, loses an event, returns an ambiguous response or becomes unavailable during revocation.
- Coordinator crashes after committing a lease but before returning it; retry must recover the same idempotent outcome or reject safely.
- Coordinator crashes after revocation commit but before responding; all older generations must remain fenced.
- Recovery restores a stale checkpoint or attempts to lower/reuse a fencing generation.
- Provider acceptance succeeds but the response is lost; reconciliation must not issue a duplicate mutation.

These controls require independent implementation and review. A passing local SQLite test cannot establish caller identity, signing-key custody, audit immutability, provider enforcement or distributed consistency.


## One-time approval binding in the synthetic model — 13 November 2026

The local model now enforces a unique lease association for each approval ID. A credential already bound to one lease cannot be reused for another lease, including a lease targeting a different resource. This models the one-time nature of consumed approval credentials and closes a gap in the earlier reference tests, which allowed an overlapping approval ID to be attached to a second lease. The model still does not replace the production approval ledger or prove atomicity across independent services.


## Dispatch expiry and indeterminate-outcome recovery model — 13 November 2026

The SQLite reference model now samples the acceptance clock after it acquires the serialized dispatch-state lock. This mirrors the acquisition-side expiry recheck and prevents a lease that expires while waiting behind another writer from being accepted on the basis of an earlier timestamp. An adversarial lock-contention test covers this path.

The model also represents the post-acceptance uncertainty boundary:

- An accepted dispatch may be marked `INDETERMINATE` with a bounded reason code when the client cannot establish whether the remote provider completed the operation.
- An indeterminate dispatch cannot be accepted or replayed again.
- Reconciliation requires a provider operation ID and an authoritative terminal result (`SUCCEEDED` or `REJECTED`).
- Repeating the exact same reconciliation is idempotent; conflicting results are rejected.
- A provider operation ID can be associated with only one lease.
- A lease that was never accepted cannot be marked indeterminate or reconciled.

These are synthetic local state-machine behaviors only. The model does not contact a provider, prove that a provider operation ID is authentic, or create an independent audit trail. Production reconciliation must verify provider evidence through an authenticated provider interface, persist evidence and audit acknowledgement independently, and prohibit automatic replay whenever acceptance is ambiguous.

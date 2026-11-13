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

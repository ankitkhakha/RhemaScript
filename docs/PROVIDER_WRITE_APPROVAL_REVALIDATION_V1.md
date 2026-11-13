# Provider-Write Approval Revalidation V1

## Purpose

Close the time gap between atomic approval consumption and the first external provider write. A credential can be valid when consumed but expire, lose identity-authentication freshness, or have its signing key revoked before the gateway sends the provider request.

## Code path

- `ApprovalVerifier` attaches an opaque reference to the exact verifier instance that created each `VerifiedApproval`.
- `revalidate_consumed_verified_approval` accepts only the exact in-process approval object already marked as consumed by the verifier.
- `ApprovalVerifier.revalidate_consumed_approval` rechecks:
  - when the atomic-consumption callback is a bound durable store method exposing `is_consumed` and `is_revoked`, the exact approval remains present in the consumption ledger and has not subsequently been revoked; ledger read failures fail closed;
  - that the credential remains unexpired;
  - that the signing key still resolves from the verifier's configured trust source;
  - that the current key fingerprint matches the key used during signature verification;
  - that a registry-backed key remains active and inside its validity interval;
  - that human-authentication freshness remains inside the signed identity policy's permitted age and clock-skew window.
- `ExternalIntegrationGateway.request` performs this revalidation after credential resolution and immediately before calling the provider transport for PUBLISH operations. Failure is fail-closed and occurs before transport.

## Production key-registry requirement

When the verifier uses a live `VerificationKeyRegistry`, the provider-boundary recheck resolves the key again. Registry outage, stale/future-dated registry response, revocation, key replacement, or validity-window failure prevents the provider request.

A verifier configured with a static in-process public-key map can recheck expiry, identity freshness and that its configured key has not changed in that verifier instance. A static map cannot provide emergency revocation or authoritative key-lifecycle freshness. Production high-risk writes must therefore use an authenticated live registry with independently controlled revocation and key custody; static-key mode is suitable only for constrained offline/synthetic scenarios.

## Residual distributed race

The final key-registry read occurs immediately before transport, but the registry and provider transport do not share a distributed transaction. A revocation may occur after the final successful read and before the provider accepts the request. Eliminating that residual race requires a provider-boundary authorization lease or a registry/provider protocol with atomic fencing semantics. This code narrows the window; it does not claim to eliminate it.

## Validation

Synthetic tests cover:
- a key revoked after approval consumption and rejected by write-boundary revalidation;
- a gateway write rejected when revalidation fails;
- an approval revoked after durable consumption and rejected by write-boundary revalidation;
- no provider transport call on revalidation failure.

CI success validates the local code contracts and synthetic test doubles only. It does not prove production registry deployment, revocation propagation latency, external identity assurance, HSM/KMS custody, or provider-side fencing.

## Release gates

Before enabling production provider writes:
1. Deploy an authenticated, independently administered live key registry.
2. Define and measure revocation propagation and registry freshness guarantees.
3. Establish independent key custody, rotation, compromise response and audit retention.
4. Decide whether the residual read-to-transport race is acceptable or requires an authorization-lease/fencing protocol.
5. Complete independent human security review and production write-boundary testing.

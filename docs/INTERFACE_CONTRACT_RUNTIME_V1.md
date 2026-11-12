# Shared Interface Contract Runtime V1.0

**Status:** Implemented on a review branch; local execution tests are authored but have not yet been run in a repository checkout.

## Scope

This increment introduces one provider-neutral shared request-envelope validator and wires the existing local InterfaceGateway through it. It applies equally to the existing IF-01..IF-18 registry without inventing per-interface business semantics.

The validator checks:
- registered interface identity;
- required request envelope fields;
- non-empty identifier fields;
- object-shaped payload;
- non-empty classification when supplied; and
- deterministic JSON canonicalisation with non-finite numbers rejected.

The gateway continues to apply existing disclosure and authority checks. The adapter remains local-only and returns ACCEPTED_FOR_LOCAL_PROCESSING; it does not call providers or perform external writes.

## Explicit limitations

- IF-01..IF-18 semantic ownership and payload schemas remain unresolved; this increment does not claim those mappings are complete.
- The returned SHA-256 fingerprint is a deterministic request fingerprint, not a durable idempotency guarantee.
- The replay cache remains process-local and in-memory. Cross-process persistence, concurrency safety, expiry policy and durable replay protection remain pending.
- Provider-specific authentication, network transport, timeout/retry policy and sandbox E2E remain outside this increment.
- No generation, spend, publishing, external write, deployment or authority change is enabled.

## Validation

A focused unittest module covers valid envelopes, key-order-independent fingerprints, unknown interfaces, missing/blank fields, malformed payloads, non-JSON values, NaN rejection, gateway integration, in-process replay, and normalization/explicit-true authorization checks for all four registered consequential operations (GENERATE, PUBLISH, SPEND, EXTERNAL_WRITE). Run the repository CI with python ci/run_ci.py after checking out this branch. No test pass is claimed until that command has actually run.

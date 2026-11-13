# External Gateway Mutating-Method Authorization V1

## Rule

Authorization classification must consider both the declared operation and the actual HTTP method. A configured operation label is not sufficient to establish that an operation is read-only.

- YouTube `UPLOAD_SESSION`, `UPLOAD_CHUNK`, and the disabled `THUMBNAIL_WRITE` map to `PUBLISH` and require the signed dual-approval path.
- `GET`, `HEAD`, and `OPTIONS` are treated as safe methods unless the operation name itself is one of the configured consequential actions.
- Every other HTTP method is treated as a mutating request. If its operation name is one of `GENERATE`, `PUBLISH`, `SPEND`, or `EXTERNAL_WRITE`, that explicit action is required. Otherwise it is classified as `EXTERNAL_WRITE`.
- Generic `EXTERNAL_WRITE`, `GENERATE`, and `SPEND` mutations are now rejected even when the caller supplies the corresponding `*_authorisation: true` boolean. Those booleans are caller-controlled data, not proof of authenticated human approval. The gateway remains fail-closed until signed, identity-bound, independently verifiable authority contracts are implemented for those actions.
- `OAUTH_TOKEN` is a narrow YouTube token-exchange exception: POST only, exact host `oauth2.googleapis.com`, exact path `/token`, and no query or fragment. It cannot authorize other provider endpoints or resource mutations.

## Fail-closed behavior

The authorization check runs before credential resolution and before provider transport. Missing or invalid explicit authority rejects the request without a transport call. Adding a new custom mutating operation therefore cannot silently inherit read-only treatment.

The gateway still enforces the provider operation's exact method, host and path-prefix allowlist. The OAuth exception adds an exact endpoint check beyond the normal path-prefix rule.

## Validation

Synthetic tests cover:
- an unclassified custom POST rejected without explicit external-write authority and with no transport call;
- a custom POST and named `GENERATE` / `SPEND` / `EXTERNAL_WRITE` operations rejected even when forged caller-supplied booleans are true;
- YouTube upload operations remaining on the PUBLISH dual-approval path;
- OAuth-token aliases, path suffixes, query strings and fragments rejected before transport.

CI validates local code behavior and synthetic fixtures only. It does not establish production identity, authorization, or provider-write readiness.


## Legacy generic POST entry point

The legacy `ExternalIntegrationGateway.invoke` API always emits POST and has no signed, operation-specific approval contract. It is therefore disabled unconditionally, including when callers supply `external_action_authorisation: true`. The method performs only basic interface/enabled/binding/audit-sink checks before rejecting; it never resolves provider credentials, consults the response cache, or calls transport. Generic mutations must not be routed through this API. The method-aware request path also keeps GENERATE, SPEND and EXTERNAL_WRITE disabled until signed, identity-bound operation authority is implemented.

Adversarial tests confirm that forged boolean authority and concurrent/duplicate attempts cannot reach transport through the legacy API.

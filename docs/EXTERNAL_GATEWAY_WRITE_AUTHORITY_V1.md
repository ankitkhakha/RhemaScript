# External Gateway Mutating-Method Authorization V1

## Rule

Authorization classification must consider both the declared operation and the actual HTTP method. A configured operation label is not sufficient to establish that an operation is read-only.

- YouTube `UPLOAD_SESSION`, `UPLOAD_CHUNK`, and the disabled `THUMBNAIL_WRITE` map to `PUBLISH` and require the signed dual-approval path.
- `GET`, `HEAD`, and `OPTIONS` are treated as safe methods unless the operation name itself is one of the configured consequential actions.
- Every other HTTP method is treated as a mutating request. If its operation name is one of `GENERATE`, `PUBLISH`, `SPEND`, or `EXTERNAL_WRITE`, that explicit action is required. Otherwise it is classified as `EXTERNAL_WRITE` and requires `external_action_authorisation`.
- `OAUTH_TOKEN` is the narrowly scoped token-exchange exception. Its exact provider contract must continue to constrain it to the OAuth token endpoint; it is not permission to perform resource mutations.

## Fail-closed behavior

The authorization check runs before credential resolution and before provider transport. Missing or invalid explicit authority rejects the request without a transport call. Adding a new custom mutating operation therefore cannot silently inherit read-only treatment.

The gateway still enforces the provider operation's exact method, host and path-prefix allowlist. This rule supplements rather than replaces those controls.

## Validation

Synthetic tests cover:
- an unclassified custom POST rejected without explicit external-write authority and with no transport call;
- the same custom POST accepted only when the explicit external-write authority flag is supplied;
- existing YouTube upload operations remaining on the PUBLISH dual-approval path;
- the OAuth token-exchange flow retaining its narrowly scoped contract.

CI validates local code behavior and synthetic fixtures only. It does not establish production identity, authorization, or provider-write readiness.

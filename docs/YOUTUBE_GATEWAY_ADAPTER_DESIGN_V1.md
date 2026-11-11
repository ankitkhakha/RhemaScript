# YouTube provider gateway adapter — architecture decision record

**Status:** IF-18 client routing implemented; automated gateway verification in progress; owner-controlled OAuth and live channel validation not performed.
**Scope:** RhemaScript YouTube Data API v3 and YouTube Analytics API.
**Cost boundary:** Python standard library only. No paid service, dependency, hosted proxy, or credential relay.

## Existing authority and interface facts

- The canonical registry defines the interface identifiers IF-01 through IF-18, but does not assign provider meanings to those identifiers.
- The local `InterfaceGateway` is a synthetic runtime adapter and must remain local-only.
- `ExternalIntegrationGateway` is the provider-neutral external boundary. It is disabled by default, requires an explicit provider binding, HTTPS host allowlisting, disclosure checks, consequential-operation authority, credential injection, an audit sink, and idempotency.
- The original `invoke` contract remains JSON POST only. A separate method-aware `request` path now represents OAuth form POST, authenticated GET requests, resumable session POST, binary PUT chunks, response headers, and HTTP 308 acknowledgements.
- `YouTubeClient` routes live requests through an explicitly supplied IF-18 gateway. The client rejects live traffic when neither a gateway nor an injected test transport is provided; injected test transports remain offline test seams.

## Decision

**YouTube is assigned to `IF-18` as its dedicated external provider interface.** The owner delegated the interface selection to engineering on 2026-11-12, and engineering selected IF-18 to isolate the YouTube provider boundary from the other generic interfaces. This is a provider mapping for `ExternalIntegrationGateway` only; it does not change the local `InterfaceGateway`, its synthetic adapters, or the canonical registry's interface tuple.

Do not route a dummy JSON request through the gateway and call that integration. Do not change local runtime interface adapters or their synthetic contract. The YouTube transport adapter must reject missing, unknown, unbound, or disabled IF-18 configuration before making any network request. No other IF identifier is to be treated as YouTube.

## Required adapter contract

The adapter is implemented as an extension of the existing external gateway boundary; it must not create a second gateway or bypass the existing controls.

1. **Method and operation allowlist:** Every operation declares its HTTP method, permitted host, and permitted path family. The client maps fixed API path families to named operations; arbitrary URLs and caller-selected methods are rejected by the gateway contract. Content-type constraints are validated by the client protocol layer, not yet represented as fields in the provider binding.
2. **Google endpoint allowlist:** OAuth token endpoint, YouTube Data API, YouTube Analytics API, and Google-issued resumable session endpoints must be individually constrained to HTTPS and exact approved hosts. Reject userinfo, nonstandard ports, fragments, and redirects. Do not forward credentials across redirects.
3. **Secret handling:** OAuth client secret, refresh token, access token, resumable session URL, and video bytes must never enter audit records, exception text, source control, CI output, or idempotency canonical JSON. Credentials are resolved locally at request time. The OAuth refresh-token form body must be treated as secret-bearing opaque bytes.
4. **Audit:** Emit REQUESTED, COMPLETED, and FAILED records for each network step, with interface ID, provider, project/request correlation, operation name, method, host, status, byte counts, and a non-reversible request fingerprint. Do not log query values, authorization headers, session URL, payload, or body bytes.
5. **Binary/resumable transport:** Support bounded request/response sizes and explicit response headers. HTTP 308 is a resumable-upload acknowledgement, not a redirect. Validate acknowledged byte ranges and reject regressions, impossible offsets, or no-progress loops.
6. **Authority:** Read-only channel/analytics calls require approved scope and disclosure. Upload, thumbnail changes, and publication require the existing validated Evidence Pack, all six ordered approved gates, matching final-film evidence, human final acceptance, and separate publishing authorization. The client carries the validated project ID/version and publishing authorization into the gateway call; the gateway independently checks PUBLISH authority for upload-session, upload-chunk, and thumbnail-write operations. Scheduled/public release remains a distinct publishing decision.
7. **Idempotency:** Read operations may use deterministic request fingerprints. Upload-session creation and binary chunks require protocol-aware idempotency and acknowledgement handling; do not replay a chunk or create a new session blindly after an ambiguous network failure.
8. **Fail-closed defaults:** No provider binding, no audit sink, no approved interface mapping, no explicit enablement, no valid credentials, or no authority means no network request.

## Required tests before activation

- Any interface other than the explicitly mapped `IF-18`, and missing IF-18 binding, fail before transport.
- Gateway disabled and missing audit sink fail before transport.
- Every supported HTTP method and operation is allowlisted.
- Host, port, path, userinfo, fragment, and redirect attacks are rejected.
- Audit records contain no credentials, query values, session URL, payload, or media bytes.
- OAuth refresh, GET, resumable session creation, PUT chunks, 308 acknowledgements, final status verification, and Analytics GET all pass through the same configured gateway boundary.
- The current automated suite has passed the base IF-18 client-routing test. Explicit upload-chunk authority/308 tests have been added and await CI confirmation; full end-to-end gateway-backed resumable upload and thumbnail tests remain outstanding.
- Failed and ambiguous chunk requests do not silently restart or skip bytes.
- Existing generic gateway and local runtime contract tests remain unchanged and pass.

## Approval and activation boundary

This record assigns only the YouTube external provider mapping to IF-18 under the owner's delegated engineering decision. It does not amend authority masters, enable external integration, authorize OAuth, connect a channel, upload media, or publish content. The YouTube integration remains dormant by default: the owner must explicitly configure and enable the gateway, complete local OAuth setup, and authorize each publishing action. A passing CI run is not a live account connection or upload test.

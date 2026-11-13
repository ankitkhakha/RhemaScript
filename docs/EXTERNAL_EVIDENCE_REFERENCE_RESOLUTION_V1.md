# External Evidence Reference Resolution V1.0 — Design and Threat Model

**Status:** Design only; not implemented or activated  
**Applies to:** Project Evidence Pack V1.0 and RAEI evidence integrity  
**Authority:** Evidence identification and verification only. No approval, execution, generation, publishing, or final-acceptance authority.

## 1. Current-state boundary

In Evidence Pack V1.0, `evidence_refs` are caller-supplied strings. They are useful traceability labels, but the local artifact verifier does not dereference them, establish that a remote source exists, authenticate its publisher, or prove that the cited content supports a capability claim.

A local artifact's SHA-256 proves the bytes read at the configured local path. It does not prove the origin, authorship, publication date, truth, completeness, licensing, or relevance of those bytes.

Accordingly:
- Existing V1 references remain opaque identifiers.
- `UNRESOLVED_BY_LOCAL_ARTIFACT_VERIFIER` is an explicit non-verification state, not a failure or a verified state.
- No arbitrary URL, domain name, citation string, file name, HTTP response, or status label is accepted as proof.
- This document defines a future interface and controls only. It does not add network access or change current runtime behaviour.

## 2. Resolution outcomes

A future resolver must return one of these explicit outcomes for each reference:

| Outcome | Meaning | May support a capability assessment? |
|---|---|---|
| UNRESOLVED | No resolver or supported adapter was supplied | No verified-source claim |
| REJECTED | Malformed, disallowed, unsafe, or policy-ineligible reference | No |
| FETCH_FAILED | Approved adapter could not safely retrieve the source | No |
| CONTENT_VERIFIED | Retrieved bytes match a captured digest and retrieval receipt | Establishes content identity only |
| SOURCE_AUTHENTICATED | Source identity is validated under a documented source-specific trust policy | Establishes bounded source authenticity only |
| HUMAN_REVIEWED | A named authorised reviewer records a scoped review decision against the exact digest | Only the stated review scope; not blanket approval |

No state may be inferred from another. In particular, CONTENT_VERIFIED is not SOURCE_AUTHENTICATED, and neither state implies HUMAN_REVIEWED or approval.

## 3. Resolver architecture contract

The future resolver must be an injected, source-specific adapter. Core evidence validation must remain offline and deterministic when no adapter is supplied.

A resolver request must include:
- reference identifier exactly as recorded in the evidence pack;
- reference kind and declared source system;
- project ID and project version;
- evidence record ID and capability ID;
- requested verification policy version.

A successful resolution receipt must include:
- original reference and canonical locator;
- adapter identifier and adapter version;
- retrieval timestamp in UTC;
- final source locator after redirects, if redirects are supported;
- media type and byte length;
- cryptographic digest of the exact retrieved bytes;
- source identity/authentication method and its result, or an explicit NOT_CHECKED value;
- policy version and resolver outcome;
- any limitations, including truncation, dynamic content, paywall, access restriction, or unsupported format.

Receipts must be immutable values once recorded. Re-resolution creates a new receipt/version; it must never silently rewrite an earlier result. A digest is always bound to the exact evidence record, capability, project version, and reference.

## 4. Threat model and mandatory controls

### T1 — Arbitrary URL / SSRF
**Threat:** A manifest points the resolver at loopback, private, link-local, metadata, or internal network services.

**Required controls:** No generic URL fetcher in the core package. Adapter-owned destination allowlists; reject IP literals and private/reserved destinations unless explicitly approved for a controlled local adapter; validate DNS results at connection time; revalidate every redirect; block scheme downgrade and unsupported ports; enforce connection/read/total timeouts and response-size limits.

### T2 — Redirect and DNS rebinding
**Threat:** An initially permitted hostname redirects or resolves to a prohibited destination.

**Required controls:** Pin and validate each connection destination; disable redirects by default; if enabled, cap hops and re-run the full allowlist and address policy at every hop. Never trust a preflight DNS lookup alone.

### T3 — Content substitution and mutable sources
**Threat:** A page or file changes between review and production, or the same URL serves different bytes.

**Required controls:** Hash the exact retrieved bytes; persist the receipt; bind every review and assessment to the digest and project version; re-resolution produces a new evidence version and invalidates any review tied to a previous digest.

### T4 — Source impersonation
**Threat:** A lookalike domain, spoofed document, or untrusted mirror claims to be authoritative.

**Required controls:** Source-specific trust policy; allowlisted publisher identity; TLS validation; where available, independently verifiable signatures or official API identity. HTTPS alone is transport protection, not proof that a source is authoritative or accurate.

### T5 — Malicious or oversized content
**Threat:** Decompression bombs, parser exploits, hostile markup, scripts, malformed PDFs, or excessive payloads.

**Required controls:** Fetch bytes only; never execute source content. Strict byte, time, decompression, page, and parser limits; isolated parsers; content-type sniffing; safe text extraction; reject unsupported or encrypted formats rather than guessing.

### T6 — Prompt injection in retrieved sources
**Threat:** Source text contains instructions that attempt to alter the agent, policies, or tools.

**Required controls:** Treat retrieved content as untrusted data, never instructions. No retrieved content may modify resolver policy, tool permissions, workflow, or authority. Keep extraction separate from execution.

### T7 — Citation-to-claim mismatch
**Threat:** A genuine source is cited for a claim it does not support, or a citation points to the wrong passage/version.

**Required controls:** Preserve exact passage/page/section locators and extracted text digest. Require a scoped human review or separately validated domain-specific rule before labelling a source claim supported. Source authenticity alone does not establish interpretive correctness.

### T8 — Licence, privacy, and retention
**Threat:** Retrieval or storage violates copyright, privacy, terms, or retention requirements.

**Required controls:** Record access basis and permitted use; minimise retained content; prefer references plus digests and bounded excerpts; apply source-specific retention and deletion policy; do not bypass access controls or paywalls.

### T9 — Receipt and registry tampering
**Threat:** A local attacker edits receipts, registry rows, or checkpoints.

**Required controls:** Canonical receipt serialization; digest and replay checks; independently retained HMAC or digital-signature checkpoints; restricted file permissions and backups. HMAC is a shared-secret anchor, not immutable storage or non-repudiation.

## 5. Human and governance boundaries

- Resolver output is evidence metadata, not a capability decision.
- Capability assessment remains bounded and returns only human-review readiness.
- Human review must name the reviewer, scope, decision, timestamp, and exact evidence digest.
- Project gates, separate generation authorisation, final acceptance, and publishing authorisation remain independent.
- A changed digest, source identity, reference locator, or policy version requires a new receipt and review.
- No automatic approval or execution may follow from successful retrieval or authentication.

## 6. Implementation gates before activation

1. Approve a versioned reference taxonomy and source-specific trust policies.
2. Select the first narrowly scoped source adapter; do not build an unrestricted web fetcher.
3. Define and test SSRF, redirect, DNS rebinding, payload-limit, parser, and prompt-injection controls.
4. Define receipt schema, canonicalization, persistence, checkpoint custody, and retention.
5. Add adversarial tests and an offline deterministic test harness.
6. Review legal/licensing and privacy requirements for the selected source.
7. Require explicit Human Director approval before enabling any network-capable adapter.

## 7. Non-goals

This design does not implement a browser, crawler, general-purpose URL fetcher, Bible API, YouTube API, OAuth flow, source ranking engine, automated theological judgement, copyright clearance, or approval automation. It does not grant new network permissions.

**Current status:** Design recorded. External references remain unresolved until a separately approved, source-specific resolver is implemented and tested.

# Local Source Adapter V1.0 — Offline Verification Policy

**Status:** Implemented as an offline adapter on the PR branch; not activated in production.  
**Scope:** Exact references mapped to local files by an explicitly supplied catalog.  
**Authority:** Byte identity only. No publisher authentication, theological judgement, claim validation, approval, or execution authority.

## Policy

1. The adapter accepts only an exact reference already present in the caller-supplied catalog. It performs no URL parsing, DNS lookup, HTTP request, redirects, browser access, or network operation.
2. Every catalog entry must specify a stable source ID, root-relative path, version, expected SHA-256, media type, and catalog revision.
3. The underlying artifact verifier rejects traversal, symlinks, missing files, and non-regular files. The adapter independently compares the actual digest with the catalogued digest.
4. A successful receipt is labelled `CONTENT_VERIFIED`. It always records `source_authentication=NOT_CHECKED` and `claim_relevance=NOT_CHECKED`.
5. A catalog is configuration, not a cryptographic trust anchor. The adapter does not claim that a source is official, authoritative, licensed, or approved merely because it appears in the catalog.
6. Catalog changes require a new catalog revision and a new receipt. Receipts are immutable values; callers should persist them through the separately governed registry/checkpoint mechanism.
7. No Bible translation, HINOVBSI text, publisher, or source URL is preconfigured. A source corpus and its lawful-use basis must be supplied and approved separately.

## Fail-closed outcomes

- Unknown reference, malformed catalog, unsafe path, missing file, or digest mismatch: raise `LocalSourceResolutionError`; no success receipt is returned.
- Matching bytes: return `CONTENT_VERIFIED` only.
- Source identity and passage-to-claim relevance remain unverified and require separate source-specific policy and human review.

## Explicit non-goals

No network-capable adapter, Bible API, remote URL fetch, automatic source ranking, translation substitution, copyright clearance, doctrinal assessment, workflow approval, generation authorization, or publishing action.

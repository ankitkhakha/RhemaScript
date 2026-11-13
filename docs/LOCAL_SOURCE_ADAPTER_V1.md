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

## Security review addendum — catalog, receipt and project binding

The resolver freezes a defensive copy of the supplied catalog and computes a deterministic SHA-256 catalog fingerprint over every entry, including source ID, relative path, source version, expected digest, media type, catalog revision and project scope. Mutating the caller's original mapping cannot change the resolver snapshot. The resolver exposes the catalog as a read-only mapping.

Every receipt records the catalog fingerprint and, when configured, the exact project ID and project version. Evidence-pack integration requires catalog project scope to match the manifest project/version and requires the resolved source ID, source version and digest to match the artifact record. A catalog entry scoped to another project or project version is rejected.

`verify_receipt` re-resolves the exact reference against the current catalog snapshot and current file bytes. It rejects a receipt from a different catalog fingerprint, a replaced catalog revision, changed source bytes, or a project-scope mismatch. Evidence-pack execution always resolves afresh; it does not accept a caller-supplied receipt as proof.

The catalog fingerprint is an identity digest, not a signature or external trust anchor. A malicious operator who can replace both the catalog and all independently retained evidence can create a new internally consistent snapshot. Independent retention of approved catalog fingerprints and readiness checkpoints remains necessary for tamper detection. SQLite and in-process receipt objects are not immutable against a privileged local attacker.

## Readiness traceability

`run_project_assessment` accepts the same explicit local resolver. The report records each receipt's source ID, version, digest, catalog revision/fingerprint and project scope, and the artifact trace maps that receipt to the exact artifact. The durable readiness registry stores the complete receipt alongside byte-verified artifact versions. Reusing a readiness run ID with a changed receipt/catalog identity is rejected as a replay conflict.

These checks establish content identity and provenance linkage only. They do not establish publisher identity, copyright permission, theological correctness, approval, generation authorization or publishing authorization.

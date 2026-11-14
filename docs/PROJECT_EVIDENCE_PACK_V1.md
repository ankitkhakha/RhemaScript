# RhemaScript Project Evidence Pack & Run Manifest V1.0

**Status:** Initial validated implementation  
**Module:** `rhemascript.evidence`  
**Authority:** Evidence organisation only. Existing capability contracts, six project gates and separate approval, execution, final-acceptance and publishing authorities remain unchanged.

## Purpose

A project evidence pack is a version-bound index of source material, approved creative artefacts, capability evidence, provenance links and existing gate records. It supplies structured evidence to the existing Creative Production Orchestrator. It is not a new approval system, media store or execution command.

## Manifest contents

- `manifest_id` and `schema_version`.
- Validated `project_record`; project ID and version are binding keys.
- `artifacts`: stable artifact ID, type, project/version binding, artifact version, status and optional evidence references.
- `evidence_records`: stable evidence ID, existing CAP ID, payload, evidence references and artifact references.
- `source_to_final_links`: source artifact ID, target artifact ID and relationship.
- Optional existing `gate_records`, passed to the current six-gate validator unchanged.

Evidence payloads for the same CAP are merged only when repeated keys have identical values. Conflicts fail closed. The pack compiles capability evidence for the orchestrator.

## Integrity controls

- Unique artifact and evidence IDs.
- Exact project ID/version binding for every artifact.
- All artifact references resolve.
- Provenance links resolve, cannot self-reference and form a directed acyclic graph.
- Script and narration artefacts labelled as approved require an explicit APPROVED, VERIFIED or ACCEPTED status; approval is never inferred from the type name.
- If any EDITED_FILM exists, every final film must be reachable through one continuous, ordered path containing each stage: biblical source → approved script → approved narration → storyboard → audio-visual plan → prompt → asset → that edited film. Separate pairwise-connected branches cannot be spliced together to claim a complete chain, and an additional orphan final film is rejected.
- Partial packs are valid before an edited film exists; the orchestrator reports capability evidence gaps.

## Run behaviour

`validate_evidence_pack` validates and normalises the pack. `run_evidence_pack` validates first, then sends compiled evidence and existing gate records to `CreativeProductionOrchestrator`. The pack does not bypass capability, dependency or gate checks. Generation, external actions and publishing remain unperformed.

## Limits

References are caller-supplied opaque identifiers; remote files and source identities are not fetched or verified. Readiness traceability explicitly labels these references unresolved by the local artifact verifier. The threat model and future source-specific resolver contract are documented in `docs/EXTERNAL_EVIDENCE_REFERENCE_RESOLUTION_V1.md`; that design is not implemented or activated. No binary media storage, signature service, retention engine or immutable audit store is added. Human approval authenticity still depends on the existing gate-record process and review. No frame or waveform inspection is implemented.


## Canonical schema and starter template

- JSON Schema: `schemas/project-evidence-pack-v1.schema.json` (Draft 2020-12).
- Starter manifest: `templates/project-evidence-pack-v1.template.json`.
- The starter is a valid empty DRAFT project manifest and passes the runtime evidence-pack validator.
- Replace sample project identifiers and add version-bound artefacts/evidence as the project progresses.
- The JSON Schema describes the manifest structure; the Python runtime validator remains authoritative for cross-record checks such as project/version binding, reference resolution, provenance acyclicity and complete source-to-final linkage.
- Do not place generation authorisation in the manifest. Existing gate records are supplied as records; the separate execution-authorisation input remains outside the evidence pack.

## Optional offline local-source resolution

`run_evidence_pack` accepts an explicitly constructed `local_source_resolver` in addition to the existing optional `evidence_root`. An artifact may carry `local_source_reference` and its declared `sha256`. The resolver must contain that exact reference in its caller-supplied catalog. The resolved source ID, artifact version and digest must exactly match the evidence-pack artifact before the run is assessed.

Successful resolution adds the immutable receipt to `ValidatedEvidencePack.source_resolution_receipts` and the verified byte version to `byte_verified_artifacts`. The receipt remains `CONTENT_VERIFIED` with source authentication and claim relevance both `NOT_CHECKED`. Resolver failure or any identity/version/digest disagreement rejects the pack before orchestration. No source reference is auto-discovered and no network lookup is performed.

This is evidence resolution only. It does not change the six existing project gates, create approvals, infer human acceptance, grant generation authority, or enable external/publishing actions. Existing `gate_records` and the separate `generation_authorisation` input retain their current handling.


## Continuous source-to-final lineage hardening — 13 November 2026

The runtime graph validator now checks the ordered chain per final-film artifact, rather than accepting independent pairwise reachability across unrelated branches. Every EDITED_FILM must be the terminal node of a single directed path that visits every required artifact type in order. Adversarial tests reject (1) an orphan second final film when another film has a valid chain and (2) a chain assembled from disconnected source/script/narration segments. These checks establish structural path continuity only; they do not authenticate source publishers or prove that a claimed derivation is semantically genuine.

Exact implementation/test head `4886efd07d13ef71d57d048979de1075d094fbe5` passed full contract and synthetic integration CI run #1692: https://github.com/ankitkhakha/RhemaScript/actions/runs/43417414768. The first run exposed a stale test assertion expecting the prior generic “disconnected” error; the assertion was aligned with the stricter per-film error and the exact-head run passed.


## YouTube Analytics evidence artifacts — 13 November 2026

The V1 artifact catalog now accepts `YOUTUBE_ANALYTICS_SNAPSHOT` and `YOUTUBE_ANALYTICS_COMPARISON` records.

- A snapshot artifact must carry its internal `snapshot_sha256`.
- A comparison artifact must carry its `comparison_sha256`, the distinct artifact IDs of its current and previous snapshot sources, and both source snapshots' exact `snapshot_sha256` values.
- Both source IDs must resolve to artifacts of type `YOUTUBE_ANALYTICS_SNAPSHOT` in the same project and project version, and the recorded source digests must match those artifact records.
- The Analytics artifact store requires both exact source snapshot objects and recomputes the comparison from them before persistence; an internally rehashed comparison envelope alone is not sufficient to establish derivation.
- When a comparison is approved or referenced by capability evidence, `verify_pack_artifacts` also byte-reads both source snapshot envelopes and recomputes the comparison from those exact payloads; a byte-valid but forged comparison is rejected.
- The provenance graph must contain explicit `DERIVED_FROM` edges from both exact snapshot artifacts to the comparison artifact.
- The normal evidence-pack provenance graph can link each source snapshot to its derived comparison.
- When an analytics artifact is marked VERIFIED/APPROVED/ACCEPTED or is referenced by capability evidence, the existing byte-verification path additionally requires its `local_path` and file-byte `sha256`; the internal snapshot/comparison digest and the file-byte digest are separate identities.

These catalog additions do not write files, fetch provider data, establish source authenticity, or mark artifacts verified. Snapshot creation remains offline and synthetic until the owner performs an authorized read-only provider retrieval. The JSON Schema and runtime validator both enforce the Analytics artifact metadata shape; runtime checks also resolve comparison source IDs to actual snapshot artifacts.


## Validated-pack trust boundary — 14 November 2026

`validate_evidence_pack` now validates a detached deep copy of the caller's manifest, so later mutations to the original input do not alter the returned `ValidatedEvidencePack`. The dataclass is frozen only at the outer level; its nested dictionaries remain mutable and the type is publicly constructible. Accordingly, `verify_pack_artifacts` rebuilds and structurally revalidates a detached manifest snapshot before byte verification. It does not trust the dataclass type or assume that validation performed earlier still applies to the current nested contents. A regression verifies both input detachment and rejection of a mutated validated pack. This is integrity validation only; it does not grant generation or publishing authority.
